import json
import glob
import requests
from typing import List
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers, RSAPrivateNumbers
from shamir import reconstruct

base_url = "http://127.0.0.1:5000"
current_tallier = {"id": None, "token": None}

def auth_login(tallier_id: str, password: str) -> str | None:
    # Build the login url
    url = f"{base_url}/auth/login"
    # Try login if not successful then error message
    try:
        res = requests.post(url, json= {"role": "tallier", "id": tallier_id, "password": password}, timeout=5)
        res.raise_for_status()
        return res.json().get("token")
    except Exception as e:
        print(f"Auth failed: {e}")
        return None

def fetch_candidates():
    # Create the url and send get request
    url = f"{base_url}/candidates"
    res = requests.get(url, timeout= 5)
    res.raise_for_status()
    # return the candidates
    return res.json()["candidates"]

def fetch_ballots():
    # Create the url and send get request
    url = f"{base_url}/ballots"
    # Create headers
    headers = {"Authorisation": f"Bearer {current_tallier['token']}"}
    res = requests.get(url, headers= headers, timeout= 5)
    res.raise_for_status()
    # return the ballots
    return res.json()["ballots"]

def post_tally(key_id: str, results :dict):
    # Create the url and send post request
    url = f"{base_url}/tally"
    # Create headers
    headers = {"Authorisation": f"Bearer {current_tallier['token']}"}
    res = requests.post(url, json={"key_id": key_id, "results": results}, headers= headers, timeout= 5)
    res.raise_for_status()
    # return the json
    return res.json()

#   Prompt the user to input share ids separated by commas (e.g., 1,2).
#   Users must input a number of share ids that is equal to or greater than the threshold.
#   Return the shares to be used for reconstruction.
def prompt_share_ids(available_ids: List[int], threshold: int) -> List[int]:
    raw = input(f"Enter at least {threshold} share id's seperated by commas (e.g., 1,2)").strip()

    try:
        chosen = [int(x) for x in raw.split(",") if x.strip() != ""]
    except ValueError:
        raise ValueError("Share id's must be integers")

    if len(chosen) < threshold:
        raise ValueError(f"Need at least {threshold} shares")

    if any(x not in available_ids for x in chosen):
        raise ValueError("Share is not in available ids")

    # dedup logic
    seen = set()
    unique = []
    for x in chosen:
        if x not in seen:
            unique.append(x)
            seen.add(x)

    return unique

def load_shares(key_id: str):
    # get all shares for election
    files = sorted(glob.glob(f"election_keys/share_{key_id}_*.json"))
    if not files:
        raise ValueError(f"No shares found for {key_id}")

    # load all and extract params
    loaded = [json.loads(Path(p).read_text()) for p in files]
    n = loaded[0]["n"]
    e = loaded[0]["e"]
    P = loaded[0]["P"]
    T = loaded[0]["T"]

    # prompt for share id's with avaibable ids
    available_ids = [rec["i"] for rec in loaded]
    chosen_ids = prompt_share_ids(available_ids, T)

    # take chosen and check they are equal or over the threshold
    chosen = [rec for rec in loaded if rec["i"] in chosen_ids]
    shares = [(rec["i"], rec["y"]) for rec in chosen]
    if len(shares) < T:
        raise ValueError(f"need {T} shares")

    return n, e, P, T, shares

def load_secret(key_id: str):
    # Load and return secret p & q
    path = Path(f"election_keys/secret_{key_id}.json")
    obj = json.loads(path.read_text())
    return int(obj["p"]), int(obj["q"])

def build_private_key(n :int, e: int, d :int, p:int, q:int):
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    public_numbers = RSAPublicNumbers(e=e, n=n)
    private_numbers = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=public_numbers
    )
    priv_rebuilt = private_numbers.private_key()
    return priv_rebuilt

def dedup_ballot(ballots, key_id: str):
    # Only allow first vote of every user
    seen = set()
    unique = []
    for ball in ballots:
        # If it doesn't belong to this vote skip
        if str(ball.get("key_id")) != str(key_id):
            continue
        voter_id = ball.get("voter_id")
        if not voter_id or voter_id in seen:
            continue
        seen.add(voter_id)
        unique.append(ball)
    return unique

def run_tally_for_key_id(key_id: str):
    # Load shares, Threshold, n , e, P, p, q, reconstruct d and build key
    n, e, P, T, shares = load_shares(key_id)
    p, q = load_secret(key_id)
    d = reconstruct(shares, P)
    priv = build_private_key(n, e, d, p, q)

    # fetch and dedupe the ballots and fetch candidates
    ballots = dedup_ballot(fetch_ballots(), key_id)
    if not ballots:
        print("No ballots for that key_id")
        return
    candidates = set(fetch_candidates())
    tally: dict[str, int] = {}
    failed = 0

    # Decrupt and count the ballots, keepong track of how many fail
    for ball in ballots:
        try:
            point = priv.decrypt(bytes.fromhex(ball["ciphertext"]),
                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                              label=None)).decode()
            if point in candidates:
                tally[point] = tally.get(point, 0) + 1
        except Exception as e:
            print(f"error: {e}")
            failed += 1

    # post tally to server and let user know of any fails
    post_tally(key_id, tally)
    print("Tally complete: ", tally)
    if failed:
        print("Amount of failed ballots: ", failed)

def cli():
    print("Tallier system")
    # Prompt tallier for username and password to get token
    while True:
        tallier_id = input("Enter tallier ID: ").strip()
        password = input("Enter tallier password: ").strip()
        token = auth_login(tallier_id, password)
        if token:
            current_tallier["id"] = tallier_id #type:ignore
            current_tallier["token"] = token #type:ignore
            break
        print("Invalid username or password")

    # Pick Election
    key_id = input("Enter election key_id: ").strip()

    if not key_id:
        print("Key_id is required")
        return

    try:
        run_tally_for_key_id(key_id)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    cli()