import requests
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

base_url = "http://127.0.0.1:5000"

current_voter = {"id": None, "key": None, "token": None}

def auth_login(voter_id: str, password: str) -> str | None:
    # Build the login url
    url = f"{base_url}/auth/login"
    # Try login if not successful then error message
    try:
        res = requests.post(url, json= {"role": "voter", "id": voter_id, "password": password}, timeout=5)
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

def fetch_pubkey():
    # Create the url and send get request
    url = f"{base_url}/pubkey"
    res = requests.get(url, timeout= 5)
    res.raise_for_status()
    data = res.json()
    pub = load_rsa_pubkey_pem(data["pem"].encode())
    # return the pubkey
    return pub, data.get("key_id")

def load_private_key(voter_id):
    # Read and check for voter id to see if it exists
    db_path = Path("signature_keys/public_keys.json")
    db = json.loads(db_path.read_text())
    if voter_id not in db:
        raise ValueError("Voter is not registered")

    # Check that the private key pem exisits
    pem_path = Path(f"signature_keys/{voter_id}_private.pem")
    if not pem_path.exists():
        raise ValueError("Private key not found")

    # Load and return the private pem key
    key = serialization.load_pem_private_key(pem_path.read_bytes(), password= None)
    return key

def sign_vote(private_key, voter_id, candidate):
    # Create message which contains voter id and the candidate
    message = f"{voter_id}:{candidate}".encode()

    # Generating signature with ECDSA and SHA256 then returning as hex
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

def fetch_status():
    # Create the status url
    url = f"{base_url}/status"

    try:
        # Get request to retrieve status
        response = requests.get(url, timeout= 5)
        response.raise_for_status()

        data = response.json()
        status = data.get("status")

        # Check that valid reponse given
        if status not in  ("open", "closed"):
            raise ValueError(f"Unexpected response: {data}")

        return status
    except Exception as e:
        print(f"Error retrieving status: {e}")
        return None

def load_rsa_pubkey_pem(pem_bytes: bytes):
    # Load public pem key
    return serialization.load_pem_public_key(pem_bytes)

def encrypt_vote(pubkey, vote: str)-> str:
    # Encrypt the vote
    ciphertext = pubkey.encrypt(vote.encode(), padding.OAEP(mgf= padding.MGF1(algorithm= hashes.SHA256()), algorithm= hashes.SHA256(), label=None))
    # return as hex
    return ciphertext.hex()

def send_vote(vote):

    # If voting is not open then returns error message
    status = fetch_status()
    if status != "open":
        print("Sorry voting is closed")
        return

    # Check voter is authenticated
    if not current_voter["key"]:
        print("Not authenticated")
        return
    # retreive the public key
    try:
        pub, key_id = fetch_pubkey()
    except Exception as e:
        print(f"error fetching public key: {e}")
        return
    # Check the voter has a current token
    if not current_voter["token"]:
        print("Token is missing")
        return
    # Create headers
    headers = {"Authorisation" : f"Bearer {current_voter['token']}", "Content-Type": "application/json"}
    # Gets the users voter_id and creates their signature
    voter_id = current_voter["id"]
    cipher = encrypt_vote(pub, vote)
    signature = sign_vote(current_voter["key"], voter_id, cipher) #type:ignore

    # Append the signature and id to the data along with vote
    url = f"{base_url}/vote"
    data = {"voter_id": voter_id, "ciphertext":cipher, "signature": signature, "key_id": key_id}
    #print ("Payload: ", data)

    # Send vote or give relevent error on failure
    try:
        resp = requests.post(url, headers=headers, json=data)
        resp.raise_for_status()
        print(f"Server response: {resp.json()['message']}")
    except requests.exceptions.RequestException as e:
        print(f"Failed with code: {e}")

def fetch_results():

    # If voting is not closed then returns error message
    status = fetch_status()
    if status != "closed":
        print("Sorry voting is still open")
        return

    url = f"{base_url}/results"
    # Send a get request and display the current results
    try:
        respo = requests.get(url)
        results = respo.json()
        print("Current votes:")
        for cand, count in results.items():
            print(f"{cand}:{count}")
    except requests.exceptions.HTTPError as e:
        try:
            err = e.response.json()
            print(err.get("error", f"Error: {e.response.status_code}"))
        except Exception as error:
            print(f"Error: {e.response.status_code}: {e.response.text}: {error}")
    except requests.exceptions.RequestException as e:
        print(f"Failed with code: {e}")

def helper(candidates):
    print("List of valid candidates:", candidates)
    print("To vote type: vote <name of who the vote is for>")
    print("To check current results type: results")
    print("To check the status of the voting type: status")
    print("To quit type: quit")

def cli():

    print("Voting System")
    # Check that the voter id exists and then assign to voter
    while True:
        voter_id = input("Enter voter ID: ").strip()
        password = input("Enter voter password: ").strip()
        try:
            key = load_private_key(voter_id)
            token = auth_login(voter_id, password)
            # If login fails then give error
            if not token:
                print("invalid username or password")
                continue
            current_voter["id"] = voter_id #type:ignore
            current_voter["key"] = key #type:ignore
            current_voter["token"] = token #type:ignore
            break
        except ValueError as error:
            print(f"Error: {error}")

    candidates = fetch_candidates()
    cands = {cand.lower(): cand for cand in candidates}
    helper(candidates)

    while True:
        raw = input("> ").strip()
        cmd = raw.lower()

        if cmd == "quit":
            print("Exiting Voting System")
            break

        elif cmd.startswith("vote "):
            # If vote then split the vote from the candidate
            vote_raw = raw.split(maxsplit=1)[1].strip()
            # Lower to catch all votes
            cand = cands.get(vote_raw.lower())
            # If not in the candidates list then tell user and skip
            if not cand:
                print(f"Invalid candidate: {vote_raw}. Allowed: {candidates}")
                continue
            send_vote(cand)

        elif cmd == "results":
            fetch_results()

        elif cmd == "status":
            status = fetch_status()
            print(status)

        else:
            print("That is not a valid option!")

if __name__ == "__main__":
    cli()
