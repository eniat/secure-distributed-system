import json
import uuid
import requests
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

base_url = "http://127.0.0.1:5000"

def generate_keys(voter_id):
    # Make a directory for the signature keys
    directory = Path("signature_keys")
    directory.mkdir(parents=True, exist_ok=True)

    # Generate the private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate the PEM from private key
    private_pem = private_key.private_bytes(encoding= serialization.Encoding.PEM, format= serialization.PrivateFormat.PKCS8, encryption_algorithm= serialization.NoEncryption())

    # Write the private key pems to seperate files
    (directory / f"{voter_id}_private.pem").write_bytes(private_pem)

    # Generate the public pem to be returned
    public_pem = private_key.public_key().public_bytes(encoding= serialization.Encoding.PEM, format= serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    # Write the public keys to a json
    db_path = directory / "public_keys.json"
    if db_path.exists():
        db = json.loads(db_path.read_text())
    else:
        db = {}
    db[voter_id] = public_pem
    db_path.write_text(json.dumps(db, indent=2))

    return public_pem

def add_voters():
    # Ask the user how many voters to register
    try:
        n = int(input("Enter amount of voters: "))
        if n <= 0:
            print("Must be a positive number")
            return
    except ValueError:
        print("please enter a number")
        return


    # Generate key pairs for each voter
    for i in range(1, n + 1):
        voter_id = uuid.uuid4().hex[:8]
        generate_keys(voter_id)

    # Load existing public keys
    directory = Path("signature_keys")
    db_path = (directory / "public_keys.json")
    total = len(json.loads(db_path.read_text())) if db_path.exists() else 0
    print(f"{n} voters added. Now {total} registered voters")

def list_voters():
    # retrieve and print eligible voters from server
    res = requests.get(f"{base_url}/voters", timeout= 5)
    res.raise_for_status()
    data = res.json()
    voters = data.get("voters", [])
    for vote in voters:
        print(f"vote id: {vote}")

def cli():
    print("Registrar system")
    print("To list eligible voters type: voters")
    print("To add voters type: add")
    print("To quit type: quit")
    while True:
        cmd = input("> ").strip().lower()

        if cmd =="quit":
            print("bye")
            break

        elif cmd == "voters":
            list_voters()

        elif cmd == "add":
            add_voters()

        else:
            print("That's not an option!")

if __name__ == "__main__":
    cli()
