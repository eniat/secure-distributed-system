"""
End to end tests for the secure voting system.

Each test drives the real HTTP API against a live server process, exercising the
full pipeline: voter registration, authentication, ballot encryption and signing,
vote submission, election closure, threshold key reconstruction and tallying.

The server is started in an isolated temporary directory so that generated keys,
credentials and ballots never touch the working tree.
"""
import contextlib
import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

BASE_URL = "http://127.0.0.1:5000"
PASSWORD = "correct-horse-battery-staple"
SRC_DIR = Path(__file__).resolve().parent.parent / "src"


# ---------------------------------------------------------------- fixtures

def _port_open(host="127.0.0.1", port=5000):
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex((host, port)) == 0


@pytest.fixture(scope="session")
def server(tmp_path_factory):
    """Run the server in an isolated copy of the source tree for the session."""
    workdir = tmp_path_factory.mktemp("election")
    shutil.copytree(SRC_DIR, workdir / "src")

    log = open(workdir / "server-stderr.log", "w+")
    proc = subprocess.Popen(
        [sys.executable, "-m", "src.server"],
        cwd=workdir,
        stdout=log,
        stderr=subprocess.STDOUT,
    )

    def _server_output() -> str:
        log.flush()
        log.seek(0)
        return log.read().strip() or "(no output)"

    deadline = time.time() + 15
    while time.time() < deadline:
        if _port_open():
            break
        if proc.poll() is not None:
            pytest.fail(
                f"the server exited before becoming ready:\n{_server_output()}"
            )
        time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail(f"the server did not start within 15s:\n{_server_output()}")

    yield workdir

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()


@pytest.fixture
def election(server):
    """A freshly opened election with four registered voters. Returns a helper."""
    return Election(server)


# ---------------------------------------------------------------- helper

@contextlib.contextmanager
def _inside(workdir: Path):
    """Run a block with `workdir` as both the cwd and an import root."""
    previous = os.getcwd()
    os.chdir(workdir)
    sys.path.insert(0, str(workdir))
    try:
        yield
    finally:
        sys.path.remove(str(workdir))
        os.chdir(previous)


class Election:
    """Drives the voting system over its HTTP API, as the real clients do."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.voters: list[str] = []
        self.key_id: str | None = None
        self._admin_token: str | None = None
        self._tallier_token: str | None = None

    # -- setup ---------------------------------------------------------

    def register_voters(self, count: int) -> list[str]:
        with _inside(self.workdir):
            from src import registrar, auth
            new = []
            for i in range(count):
                voter_id = f"voter{len(self.voters) + i}-{int(time.time()*1000)%100000}"
                registrar.generate_keys(voter_id)
                auth.add_user("voter", voter_id, PASSWORD)
                new.append(voter_id)
        self.voters.extend(new)
        return new

    def create_staff(self):
        with _inside(self.workdir):
            from src import auth
            auth.add_user("admin", "admin", PASSWORD)
            auth.add_user("tallier", "tallier", PASSWORD)

    # -- auth ----------------------------------------------------------

    @staticmethod
    def login(role: str, user_id: str, password: str = PASSWORD):
        return requests.post(
            f"{BASE_URL}/auth/login",
            json={"role": role, "id": user_id, "password": password},
            timeout=5,
        )

    @staticmethod
    def _auth(token: str) -> dict:
        return {"Authorisation": f"Bearer {token}", "Content-Type": "application/json"}

    @property
    def admin_token(self) -> str:
        if not self._admin_token:
            self._admin_token = self.login("admin", "admin").json()["token"]
        return self._admin_token

    @property
    def tallier_token(self) -> str:
        if not self._tallier_token:
            self._tallier_token = self.login("tallier", "tallier").json()["token"]
        return self._tallier_token

    # -- lifecycle -----------------------------------------------------

    def open(self, n_shares: int = 3, threshold: int = 2):
        with _inside(self.workdir):
            from src import admin
            keys = admin.generate_keys(n_shares, threshold)
        self.key_id = str(keys["key_id"])
        requests.post(
            f"{BASE_URL}/pubkey",
            json={"key_id": keys["key_id"], "pem": keys["public_pem"]},
            headers=self._auth(self.admin_token),
            timeout=5,
        ).raise_for_status()
        return requests.post(f"{BASE_URL}/open", json={},
                             headers=self._auth(self.admin_token), timeout=5)

    def close(self):
        return requests.post(f"{BASE_URL}/close", json={},
                             headers=self._auth(self.admin_token), timeout=5)

    # -- voting --------------------------------------------------------

    def _pubkey(self):
        obj = requests.get(f"{BASE_URL}/pubkey", timeout=5).json()
        return serialization.load_pem_public_key(obj["pem"].encode())

    def build_ballot(self, voter_id: str, candidate: str) -> dict:
        """Encrypt the choice under the election key and sign it as the voter."""
        cipher = self._pubkey().encrypt(
            candidate.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        ).hex()
        pem = (self.workdir / "signature_keys" / f"{voter_id}_private.pem").read_bytes()
        private_key = serialization.load_pem_private_key(pem, password=None)
        signature = private_key.sign(
            f"{voter_id}:{cipher}".encode(), ec.ECDSA(hashes.SHA256())
        ).hex()
        return {"voter_id": voter_id, "ciphertext": cipher, "signature": signature}

    def cast(self, voter_id: str, candidate: str, token: str | None = None):
        if token is None:
            token = self.login("voter", voter_id).json()["token"]
        return requests.post(f"{BASE_URL}/vote",
                             json=self.build_ballot(voter_id, candidate),
                             headers=self._auth(token), timeout=5)

    # -- tallying ------------------------------------------------------

    def tally(self, share_ids: list[int] | None = None) -> dict:
        """Reconstruct the private key from shares and decrypt every ballot."""
        with _inside(self.workdir):
            from src.shamir import reconstruct
            from src import tallier as tallier_mod

            files = sorted(glob.glob(f"election_keys/share_{self.key_id}_*.json"))
            loaded = [json.loads(Path(f).read_text()) for f in files]
            n, e, P, T = loaded[0]["n"], loaded[0]["e"], loaded[0]["P"], loaded[0]["T"]
            if share_ids is None:
                share_ids = [rec["i"] for rec in loaded][:T]
            shares = [(r["i"], r["y"]) for r in loaded if r["i"] in share_ids]
            if len(shares) < T:
                raise ValueError(f"need {T} shares, got {len(shares)}")

            secret = json.loads(
                Path(f"election_keys/secret_{self.key_id}.json").read_text())
            d = reconstruct(shares, P)
            priv = tallier_mod.build_private_key(
                n, e, d, int(secret["p"]), int(secret["q"]))

        ballots = requests.get(f"{BASE_URL}/ballots",
                               headers=self._auth(self.tallier_token),
                               timeout=5).json()["ballots"]
        candidates = set(requests.get(f"{BASE_URL}/candidates",
                                      timeout=5).json()["candidates"])

        results: dict[str, int] = {}
        for ballot in ballots:
            if str(ballot["key_id"]) != str(self.key_id):
                continue
            choice = priv.decrypt(
                bytes.fromhex(ballot["ciphertext"]),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None),
            ).decode()
            if choice in candidates:
                results[choice] = results.get(choice, 0) + 1

        requests.post(f"{BASE_URL}/tally",
                      json={"key_id": self.key_id, "results": results},
                      headers=self._auth(self.tallier_token), timeout=5).raise_for_status()
        return results


# ---------------------------------------------------------------- tests

class TestElectionLifecycle:
    def test_full_election_produces_correct_tally(self, election):
        """The headline property: votes cast are the votes counted."""
        election.create_staff()
        a, b, c, d = election.register_voters(4)
        election.open()

        assert election.cast(a, "Alice").status_code == 200
        assert election.cast(b, "Alice").status_code == 200
        assert election.cast(c, "Bob").status_code == 200
        assert election.cast(d, "Charlie").status_code == 200

        election.close()
        assert election.tally() == {"Alice": 2, "Bob": 1, "Charlie": 1}

    def test_results_published_to_voters_match_tally(self, election):
        election.create_staff()
        a, b = election.register_voters(2)
        election.open()
        election.cast(a, "Bob")
        election.cast(b, "Bob")
        election.close()
        expected = election.tally()

        published = requests.get(f"{BASE_URL}/results", timeout=5)
        assert published.status_code == 200
        assert published.json() == expected == {"Bob": 2}

    def test_status_transitions(self, election):
        election.create_staff()
        election.register_voters(1)
        election.open()
        assert requests.get(f"{BASE_URL}/status", timeout=5).json()["status"] == "open"
        election.close()
        assert requests.get(f"{BASE_URL}/status", timeout=5).json()["status"] == "closed"


class TestBallotIntegrity:
    def test_voter_cannot_vote_twice(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()

        assert election.cast(voter, "Alice").status_code == 200
        second = election.cast(voter, "Bob")
        assert second.status_code == 409, "a second ballot must be rejected"

    def test_only_first_vote_is_counted(self, election):
        """Ballot stuffing must not change the result."""
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        election.cast(voter, "Alice")
        election.cast(voter, "Bob")
        election.cast(voter, "Charlie")
        election.close()
        assert election.tally() == {"Alice": 1}

    def test_vote_after_close_is_rejected(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]
        ballot = election.build_ballot(voter, "Alice")
        election.close()

        late = requests.post(f"{BASE_URL}/vote", json=ballot,
                             headers=election._auth(token), timeout=5)
        assert late.status_code == 403

    def test_tampered_signature_is_rejected(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]

        ballot = election.build_ballot(voter, "Alice")
        flipped = "0" if ballot["signature"][0] != "0" else "1"
        ballot["signature"] = flipped + ballot["signature"][1:]

        res = requests.post(f"{BASE_URL}/vote", json=ballot,
                            headers=election._auth(token), timeout=5)
        assert res.status_code == 401, "an invalid signature must not be counted"

    def test_ballot_for_unregistered_voter_is_rejected(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]

        ballot = election.build_ballot(voter, "Alice")
        ballot["voter_id"] = "ghost-voter"
        res = requests.post(f"{BASE_URL}/vote", json=ballot,
                            headers=election._auth(token), timeout=5)
        assert res.status_code == 401

    def test_incomplete_ballot_is_rejected(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]

        ballot = election.build_ballot(voter, "Alice")
        del ballot["signature"]
        res = requests.post(f"{BASE_URL}/vote", json=ballot,
                            headers=election._auth(token), timeout=5)
        assert res.status_code == 400


class TestAccessControl:
    def test_wrong_password_is_refused(self, election):
        election.create_staff()
        assert election.login("admin", "admin", "wrong").status_code == 401

    def test_unknown_user_is_refused(self, election):
        assert election.login("admin", "nobody", PASSWORD).status_code == 401

    def test_voting_requires_a_token(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        ballot = election.build_ballot(voter, "Alice")
        res = requests.post(f"{BASE_URL}/vote", json=ballot,
                            headers={"Content-Type": "application/json"}, timeout=5)
        assert res.status_code == 401

    def test_voter_cannot_open_or_close_election(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]
        for path in ("/open", "/close"):
            res = requests.post(f"{BASE_URL}{path}", json={},
                                headers=election._auth(token), timeout=5)
            assert res.status_code == 403, f"voter must not reach {path}"

    def test_voter_cannot_read_ballots(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]
        res = requests.get(f"{BASE_URL}/ballots",
                           headers=election._auth(token), timeout=5)
        assert res.status_code == 403

    def test_voter_cannot_post_a_tally(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        token = election.login("voter", voter).json()["token"]
        election.close()
        res = requests.post(f"{BASE_URL}/tally",
                            json={"key_id": election.key_id, "results": {"Alice": 999}},
                            headers=election._auth(token), timeout=5)
        assert res.status_code == 403

    def test_voter_cannot_vote_as_another_voter(self, election):
        election.create_staff()
        attacker, victim = election.register_voters(2)
        election.open()

        token = election.login("voter", attacker).json()["token"]
        ballot = election.build_ballot(victim, "Alice")
        res = requests.post(f"{BASE_URL}/vote", json=ballot,
                            headers=election._auth(token), timeout=5)
        assert res.status_code == 403, "a voter must not submit a ballot for someone else"


class TestBallotSecrecy:
    def test_ballots_are_pseudonymised_for_the_tallier(self, election):
        """The tallier must not learn who cast which ballot."""
        election.create_staff()
        voters = election.register_voters(3)
        election.open()
        for voter in voters:
            election.cast(voter, "Alice")
        election.close()

        ballots = requests.get(f"{BASE_URL}/ballots",
                               headers=election._auth(election.tallier_token),
                               timeout=5).json()["ballots"]
        exposed = {b["voter_id"] for b in ballots}
        assert exposed.isdisjoint(set(voters)), "real voter ids leaked to the tallier"
        assert len(exposed) == len(voters), "pseudonyms must stay distinct per voter"

    def test_ballots_are_not_readable_while_voting_is_open(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        election.cast(voter, "Alice")
        res = requests.get(f"{BASE_URL}/ballots",
                           headers=election._auth(election.tallier_token), timeout=5)
        assert res.status_code == 403


class TestThresholdRecovery:
    def test_threshold_shares_recover_the_key_and_decrypt_ballots(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open(n_shares=5, threshold=3)
        election.cast(voter, "Charlie")
        election.close()
        assert election.tally(share_ids=[2, 3, 4]) == {"Charlie": 1}

    def test_below_threshold_shares_cannot_tally(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open(n_shares=5, threshold=3)
        election.cast(voter, "Alice")
        election.close()
        with pytest.raises(ValueError):
            election.tally(share_ids=[1, 2])


class TestResultDisclosure:
    def test_results_unavailable_before_tallying(self, election):
        election.create_staff()
        (voter,) = election.register_voters(1)
        election.open()
        election.cast(voter, "Alice")
        election.close()
        res = requests.get(f"{BASE_URL}/results", timeout=5)
        assert res.status_code == 404, "no results should exist before the tally"

    def test_results_unavailable_while_voting_is_open(self, election):
        election.create_staff()
        election.register_voters(1)
        election.open()
        res = requests.get(f"{BASE_URL}/results", timeout=5)
        assert res.status_code == 403