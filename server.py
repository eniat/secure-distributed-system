import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from threading import Lock

candidates = ["Alice", "Bob", "Charlie"]
votes = {name: 0 for name in candidates}
ballots = []
lock = Lock()
election = {"status": "closed"}
active_key = {"key_id": None, "pem" :None}
final_results = None

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

    def do_POST(self):
        global final_results
        # Checks if posted is open, if so sets local status via lock
        if self.path == "/open":
            with lock:
                # If no public key, don't allow open
                if not active_key["pem"]:
                    return response(self, 400, {"error": "no pubkey set"})
                election["status"] ="open"
                # Clear ballot everytime voting is restarted
                for k in votes: votes[k] = 0
                ballots.clear()
                final_results = None
            return response(self, 200, {"status":"open"})

        # Checks if posted is close, if so sets local status via lock
        if self.path == "/close":
            with lock:
                election["status"] = "closed"
                active_key["key_id"] = None
                active_key["pem"] = None
            return response(self, 200, {"status": "closed"})

        if self.path == "/pubkey":
            # admin.py posts public RSA key
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode())
            active_key["key_id"] = data.get("key_id")
            active_key["pem"] = data.get("pem")
            return response(self, 200, {"status": "pubkey set"})

        # stores tally from tallier
        if self.path == "/tally":
            # Check election is closed
            if election["status"] != "closed":
                return response(self, 403, {"error": "election still open"})
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode())
            results = data.get("results")
            final_results = results
            return response(self, 200, {"status": "tally scored"})

        # If not /vote then gives error
        if self.path != "/vote":
            return response(self, 404, {"error": "Not found"})

        # If not open give closed error message
        if election["status"] != "open":
            return response(self, 403, {"error": "Voting is closed"})

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
            return response(self, 400, {"error": "Missing voter_id, ciphertext or signature"})

        # Verify signature before counting vote
        try:
            verify_signature(voter_id, cipher, signature)
        except Exception as e:
            return response(self, 401, {"error": f"Invalid signature - {e}"})

        # With lock count votes and record in ballot
        with lock:
            ballots.append({"voter_id": voter_id, "ciphertext": cipher, "key_id": active_key["key_id"]})
        return response(self, 200, {"message": f"Vote successfully submitted"})

    def do_GET(self):
        # Fetches elegible voters
        if self.path == "/voters":
            db_path = Path("signature_keys/public_keys.json")
            if not db_path.exists():
                return response(self, 200, {"voters":[]})
            try:
                db = json.loads(db_path.read_text())
                return response(self, 200, {"voters": list(db.keys())})
            except Exception as e:
                return response(self, 500, {"error" : f"failed to load voters: {e}"})
        # Gets ballots for tallying
        if self.path == "/ballots":
            if election["status"] != "closed":
                return response(self, 403, {"error": "voting is open"})
            return response(self, 200, {"ballots":ballots})
        # Fetches RSA pubkey
        if self.path == "/pubkey":
            if not active_key["pem"]:
                return response(self, 404, {"error": "no pubkey"})
            return response(self, 200, active_key)
        # Return voting status
        if self.path == "/status":
            return response(self, 200, {"status": election["status"]})
        # Return results when election is closed
        if self.path == "/results":
            if election["status"] != "closed":
                return response(self, 403, {"error": "Voting is open"})
            if final_results is None:
                return response(self, 404, {"error": "No tally yet"})
            return response(self, 200, final_results)
        # Return candidates
        if self.path == "/candidates":
            return response(self, 200, {"candidates": candidates})
        # If incorrect path return error
        return response(self, 404, {"error": "Not found"})

def run():

    HTTPServer(("127.0.0.1", 5000), VoteHandler).serve_forever() #type: ignore

if __name__ == "__main__":
    run()