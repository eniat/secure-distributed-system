import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

candidates = ["Alice", "Bob", "Charlie"]
votes = {name: 0 for name in candidates}

def response(handler, code, obj):
    # Defines what is sent back in response
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(obj).encode())


def load_public_key( voter_id):
    # Check that the public_keys.json exists
    db_path = Path("public_keys.json")
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

    def do_POST(self):

        if "application/json" not in (self.headers.get("Content-Type")or ""):
            return response(self, 400, {"error": "Wrong content-type, has to be json"})

        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n).decode())

        # Extract data from json
        cand = data.get("vote")
        voter_id = data.get("voter_id")
        signature = data.get("signature")

        # Check that all required information was sent and that the vote is valid
        if not voter_id or not signature or not cand:
            return response(self, 400, {"error": "Missing voter_id, vote or signature"})
        if cand not in candidates:
            return response(self, 400, {"error": f"Invalid candidate '{cand}' Please vote for one of the allowed: {candidates}"})

        # Verify signature before counting vote
        try:
            db = json.loads(Path("public_keys.json").read_text())

            # If noter_id doesn't exist return error
            if voter_id not in db:
                return response(self, 400, {"error": "Voter not registered"})
            # load public key
            pub_pem = db[voter_id]
            pub_key = serialization.load_pem_public_key(pub_pem.encode())

            # Verify signature using ECDSA and SHA256
            message = f"{voter_id}:{cand}".encode()
            pub_key.verify(bytes.fromhex(signature), message, ec.ECDSA(hashes.SHA256()))

        except Exception as e:
            return response(self, 401, {"error": f"Invalid signature - {e}"})

        votes[cand] += 1
        return response(self, 200, {"message": f"Vote successfully submitted"})

    def do_GET(self):

        if self.path != "/results":
            return response(self, 404, {"error": "Not found"})

        return response(self, 200, votes)

def run():

    HTTPServer(("127.0.0.1", 5000), VoteHandler).serve_forever() #type: ignore

if __name__ == "__main__":
    run()
