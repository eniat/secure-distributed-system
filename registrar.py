import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_keys(voter_id):
    # Generate the private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate the PEM from private key
    private_pem = private_key.private_bytes(encoding= serialization.Encoding.PEM, format= serialization.PrivateFormat.PKCS8, encryption_algorithm= serialization.NoEncryption())

    # Make a directory for the private keys
    directory = Path("private_keys")
    directory.mkdir(parents=True, exist_ok= True)

    # Write the private key pems to seperate files
    file_path = directory / f"{voter_id}_private.pem"
    with open(file_path, "wb") as f:
        f.write(private_pem)

    # Generate the public pem to be returned
    public_pem = private_key.public_key().public_bytes(encoding= serialization.Encoding.PEM, format= serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    return public_pem

def main():
    # Ask the user how many voters to register
    n = int(input("Enter amount of voters: "))

    # Load existing public key database if it exists, or start a new one
    db_path = Path("public_keys.json")

    if db_path.exists():
        db = json.loads(db_path.read_text())

    else:
        db = {}

    # Generate key pairs for each voter and update the public key database
    for i in range(1, n+1):

        voter_id = f"voter{i}"
        public_pem = generate_keys(voter_id)
        db[voter_id] = public_pem

    # Save the updated public key database to disk
    db_path.write_text(json.dumps(db, indent= 2))

if __name__ == "__main__":
    main()
