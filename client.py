import requests
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

baseUrl = "127.0.0.1:5000"

current_voter = {"id": None, "key": None}

def load_private_key(voter_id):
    # Read and check for voter id to see if it exists
    db_path = Path("public_keys.json")
    db = json.loads(db_path.read_text())
    if voter_id not in db:
        raise ValueError("Voter is not registered")

    # Check that the private key pem exisits
    pem_path = Path(f"{voter_id}_private.pem")
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

def send_vote(vote):
    # Check voter is authenticated
    if not current_voter["key"]:
        print("Not authenticated")
        return

    # Gets the users voter_id and creates their signature
    voter_id = current_voter["id"]
    signature = sign_vote(current_voter["key"], voter_id, vote)

    # Append the signature and id to the data along with vote
    url = f"http://{baseUrl}/vote"
    data = {"voter_id": voter_id, "vote":vote, "signature": signature}
    print ("Payload: ", data)

    # Send vote or give relevent error on failure
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        print(f"Server response: {response.json()['message']}")
    except requests.exceptions.RequestException as e:
        print(f"Failed with code: {e}")

def fetch_results():
    url = f"http://{baseUrl}/results"
    # Send a get request and display the current results
    try:
        response = requests.get(url)
        response.raise_for_status()
        results = response.json()
        print("Current votes:")
        for cand, count in results.items():
            print(f"{cand}:{count}")
    except requests.exceptions.RequestException as e:
        print(f"Failed with code: {e}")

def cli():

    print("Voting System")
    # Check that the voter id exists and then assign to voter
    while True:
        voter_id = input("Enter voter ID: ")
        try:
            key = load_private_key(voter_id)
            current_voter["id"] = voter_id
            current_voter["key"] = key
            break
        except ValueError as error:
            print(f"Error: {error}")

    print("To vote type: vote <name of who the vote is for>")
    print("To check current results type: results")
    print("to quit type: quit")

    while True:
        cmd = input("> ").strip().lower()

        if cmd == "quit":
            print("Bye")
            break

        elif cmd.startswith("vote "):
            _, vote = cmd.split(maxsplit= 1)
            send_vote(vote.capitalize())

        elif cmd == "results":
            fetch_results()

        else:
            print("That is not a valid option!")

if __name__ == "__main__":
    cli()
