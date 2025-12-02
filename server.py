import json
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from threading import Lock
from kerberos import load_user, verify_password, create_token, role_from_header

candidates = ["Alice", "Bob", "Charlie"]
votes = {name: 0 for name in candidates}
ballots = []
lock = Lock()
election = {"status": "closed"}
active_key = {"key_id": None, "pem" :None}
final_results = None
auth_roles = ("admin", "tallier", "voter")
seen_votes: set[tuple[str, str]] = set()

# For logging
LOG_FILE = Path("server.log")
logging.basicConfig(
    level= logging.INFO,
    format= "%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding= "utf-8")
])

def log_action(action, *, role= None, user_id=None, **extra):
    # Payload for logging
    payload = {
        "role": role or "-",
        "user_id": user_id or "-"
    }
    # Update the log and add extra if it exists
    payload.update(extra)
    logging.info("%s | %s", action,json.dumps(payload, separators=(",", ":")))

def add_results(key_id: str, results: dict):
    # set results file path
    results_file = Path("signature_keys/election_results.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    # Create an entry and check file exists and write to it
    entry = {"key_id": key_id, "timestamp": int(time.time()), "results": results}
    try:
        data = json.loads(results_file.read_text())
        if not isinstance(data, list):
            data = []
    except Exception:
        data = []
    data.append(entry)
    results_file.write_text(json.dumps(data, indent= 2))

def response(handler, code, obj):
    # Defines what is sent back in response
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(obj).encode())

def load_public_key( voter_id):
    # Check that the public_keys.json exists
    db_path = Path("signature_keys/public_keys.json")
    if not db_path.exists():
        raise ValueError("no public_keys to load")

    # Read public keys for the voter ID and raise error if doesn't exist
    db = json.loads(db_path.read_text())
    pem = db.get(voter_id)
    if not pem:
        raise ValueError("Voters not registered")
    return serialization.load_pem_public_key(pem.encode())

def verify_signature(voter_id, vote, signature):
    # Load the voters public_key
    public_key = load_public_key(voter_id)

    # Generate message from the voter_id and the vote
    message = f"{voter_id}:{vote}".encode()

    # Dehex the signature then verify using public_key using ECDSA and SHA256
    sig = bytes.fromhex(signature)
    public_key.verify(sig, message, ec.ECDSA(hashes.SHA256()))

class VoteHandler(BaseHTTPRequestHandler):

    def require(self, roles: set[str]):
        # retreive headers
        header = self.headers.get("Authorisation") or ""
        # try return role from header if not raise correct errors depending
        try:
            claim = role_from_header(header, roles)
            # Log sucessful
            log_action(
                "auth_ok",
                role=claim.get("role"),
                user_id= claim.get("id"),
                path= self.path,
                method=self.command
            )
            return claim
        except PermissionError as e:
            # Error with auth header
            log_action(
                "auth_failed",
                role=None,
                user_id=None,
                path=self.path,
                method=self.command,
                reason = str(e)
            )
            code = 401 if "missing" in str(e) else 403
            response(self, code, {"error": str(e)})
        except Exception as e:
            log_action(
                "auth_error",
                role=None,
                user_id=None,
                path=self.path,
                method=self.command,
                reason=str(e)
            )
            response(self, 401, {"error":f"auth failed: {e}"})
        return None
    # require user to be admin
    def require_admin(self): return self.require({"admin"})
    # require user to be admin
    def require_tallier(self):return self.require({"tallier"})
    # require user to be admin
    def require_voter(self): return self.require({"voter"})

    def do_POST(self):
        global final_results
        # Adds a login endpoint and verifies user logging in
        if self.path == "/auth/login":
            if "application/json" not in (self.headers.get("Content-Type") or""):
                return response(self, 400, {"error": "Must be json"})
            # Load json and get role, user_id and password
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode())
            role = str(data.get("role", "")).strip()
            user_id = str(data.get("id", "")).strip()
            password = str(data.get("password", ""))
            # Check that the role is valid and all required data passed
            if role not in auth_roles or not user_id or not password:
                log_action(
                    "login_failed",
                    role= role or None,
                    user_id=user_id or None,
                    path=self.path,
                    method=self.command,
                    reason= "bad role, id or password fields"
                )
                return response(self, 400, {"error": "issue with role, password or user_id"})
            # Retrieve the user and verify the given password
            rec = load_user(role, user_id)
            if not rec or not verify_password(password, rec["salt"], rec["hash"]):
                log_action(
                    "login_failed",
                    role=role or None,
                    user_id=user_id or None,
                    path=self.path,
                    method=self.command,
                    reason="Invalid credentials"
                )
                return response(self, 401, {"error": "Incorrect username or password"})
            # If succesful create token for user
            token = create_token(role, user_id, lifetime= 600)
            log_action(
                "Login_success",
                role=role,
                user_id=user_id,
                path=self.path,
                method=self.command
            )
            return response(self, 200, {"token": token})

        # Checks if posted is open, if so sets local status via lock
        if self.path == "/open":
            # Check that user is an admin
            claim = self.require_admin()
            if not claim:
                return
            with lock:
                # If no public key, don't allow open
                if not active_key["pem"]:
                    return response(self, 400, {"error": "no pubkey set"})
                election["status"] ="open"
                # Clear ballot and seen votes everytime voting is restarted
                for k in votes: votes[k] = 0
                ballots.clear()
                seen_votes.clear()
                final_results = None
            log_action(
                "election_open",
                role=claim.get("role"),
                user_id= claim.get("id"),
                path=self.path,
                method=self.command
            )
            return response(self, 200, {"status":"open"})

        # Checks if posted is close, if so sets local status via lock
        if self.path == "/close":
            # Check that user is an admin
            claim= self.require_admin()
            if not claim:
                return
            with lock:
                election["status"] = "closed"
                active_key["key_id"] = None
                active_key["pem"] = None
            log_action(
                "election_closed",
                role=claim.get("role"),
                user_id=claim.get("id"),
                path=self.path,
                method=self.command
            )
            return response(self, 200, {"status": "closed"})

        if self.path == "/pubkey":
            # Check that user is an admin
            claim = self.require_admin()
            if not claim:
                return
            # admin.py posts public RSA key
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode())
            active_key["key_id"] = data.get("key_id")
            active_key["pem"] = data.get("pem")
            log_action(
                "pubkey_set",
                role=claim.get("role"),
                user_id=claim.get("id"),
                path=self.path,
                method=self.command,
                key_id = str(active_key["key_id"])
            )
            return response(self, 200, {"status": "pubkey set"})

        # stores tally from tallier
        if self.path == "/tally":
            # Check that user is a tallier
            claim = self.require_tallier()
            if not claim:
                return
            # Check election is closed
            if election["status"] != "closed":
                return response(self, 403, {"error": "election still open"})
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode())
            key_id = data.get("key_id")
            results = data.get("results")
            with lock:
                add_results(key_id, results)
                final_results = results
            log_action(
                "tally_posted",
                role=claim.get("role"),
                user_id=claim.get("id"),
                path=self.path,
                method=self.command,
                key_id= str(key_id),
                results_summary= {k: int(v) for k,v in (results or {}).items()}
            )
            return response(self, 200, {"status": "tally scored"})

        # If not /vote then gives error
        if self.path != "/vote":
            return response(self, 404, {"error": "Not found"})

        # If not open give closed error message
        if election["status"] != "open":
            return response(self, 403, {"error": "Voting is closed"})

        # Check that user is a voter
        claim = self.require_voter()
        if not claim:
            return

        if "application/json" not in (self.headers.get("Content-Type")or ""):
            return response(self, 400, {"error": "Wrong content-type, has to be json"})

        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n).decode())

        # Extract data from json
        cipher = data.get("ciphertext")
        voter_id = data.get("voter_id")
        signature = data.get("signature")

        # Check that all required information was sent and that the vote is valid
        if not voter_id or not signature or not cipher:
            log_action(
                "vote_rejected_bad_payload",
                role=claim.get("role"),
                user_id=claim.get("id"),
                path=self.path,
                method=self.command
            )
            return response(self, 400, {"error": "Missing voter_id, ciphertext or signature"})

        # Verify signature before counting vote
        try:
            verify_signature(voter_id, cipher, signature)
        except Exception as e:
            log_action(
                "vote_rejected_bad_signature",
                role=claim.get("role"),
                user_id=claim.get("id"),
                path=self.path,
                method=self.command,
                reason= str(e)
            )
            return response(self, 401, {"error": f"Invalid signature - {e}"})

        # Check voter_id and key_id haven't already occured
        with lock:
            # Get key_id if not one then raise error
            key_id = str(active_key.get("key_id") or "")
            if not key_id:
                return response(self, 400, {"error": "No key_id"})
            # If already voted then raise error
            key = (key_id, voter_id)
            if key in seen_votes:
                log_action(
                    "vote_rejected_duplicate",
                    role=claim.get("role"),
                    user_id=claim.get("id"),
                    path=self.path,
                    method=self.command,
                    key_id = key_id
                )
                return response(self, 409, {"error": "Already voted, denied"})
            # Add key to seen_votes
            seen_votes.add(key)
            # record in ballot
            ballots.append({"voter_id": voter_id, "ciphertext": cipher, "key_id": active_key["key_id"]})

        log_action(
            "vote_accepted",
            role=claim.get("role"),
            user_id=claim.get("id"),
            path=self.path,
            method=self.command,
            key_id= key_id
        )
        return response(self, 200, {"message": f"Vote successfully submitted"})

    def do_GET(self):
        # Fetches elegible voters
        if self.path == "/voters":
            db_path = Path("signature_keys/public_keys.json")
            if not db_path.exists():
                return response(self, 200, {"voters":[]})
            try:
                db = json.loads(db_path.read_text())
                voters = list(db.keys())
                log_action(
                    "voters_list",
                    path= self.path,
                    method= self.command,
                    voters_count = len(voters)
                )
                return response(self, 200, {"voters": voters })
            except Exception as e:
                return response(self, 500, {"error" : f"failed to load voters: {e}"})
        # Gets ballots for tallying
        if self.path == "/ballots":
            # Check that user is a tallier
            claim = self.require_tallier()
            if not claim:
                return
            if election["status"] != "closed":
                log_action(
                    "ballots_view_denied",
                    role= claim.get("role"),
                    user_id=claim.get("id"),
                    path = self.path,
                    method = self.command,
                    reason="voting is open"
                )
                return response(self, 403, {"error": "voting is open"})
            log_action(
                "ballots_view",
                role=claim.get("role"),
                user_id=claim.get("id"),
                path=self.path,
                method=self.command,
                ballots_count = len(ballots)
            )
            return response(self, 200, {"ballots":ballots})
        # Fetches RSA pubkey
        if self.path == "/pubkey":
            if not active_key["pem"]:
                return response(self, 404, {"error": "no pubkey"})
            log_action(
                "pubkey_get",
                path=self.path,
                method=self.command,
                key_id= str(active_key.get("key_id"))
            )
            return response(self, 200, active_key)
        # Return voting status
        if self.path == "/status":
            log_action(
                "status_view",
                path=self.path,
                method=self.command,
                status= election["status"]
            )
            return response(self, 200, {"status": election["status"]})
        # Return results when election is closed
        if self.path == "/results":
            if election["status"] != "closed":
                return response(self, 403, {"error": "Voting is open"})
            if final_results is None:
                return response(self, 404, {"error": "No tally yet"})
            log_action(
                "results_view",
                path=self.path,
                method=self.command
            )
            return response(self, 200, final_results)
        # Return candidates
        if self.path == "/candidates":
            log_action(
                "candidates_view",
                path=self.path,
                method=self.command,
                candidates_count = len(candidates)
            )
            return response(self, 200, {"candidates": candidates})
        # If incorrect path return error
        log_action(
            "incorrect_get",
            path=self.path,
            method=self.command
        )
        return response(self, 404, {"error": "Not found"})

def run():

    HTTPServer(("127.0.0.1", 5000), VoteHandler).serve_forever() #type: ignore

if __name__ == "__main__":
    run()