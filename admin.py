import json
import random
import requests
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from shamir import generate_shares, next_probable_prime_at_least

base_url = "http://127.0.0.1:5000"
RSA_KEY_SIZE = 2048
current_admin = {"id": None, "token": None}

def auth_login(admin_id: str, password: str) -> str | None:
    # Build the login url
    url = f"{base_url}/auth/login"
    # Try login if not successful then error message
    try:
        res = requests.post(url, json= {"role": "admin", "id": admin_id, "password": password}, timeout=5)
        res.raise_for_status()
        return res.json().get("token")
    except Exception as e:
        print(f"Auth failed: {e}")
        return None

def generate_keys(N, T):

    if not (1 <= T <= N):
        raise ValueError("Threshold must satisy 1 <= T <= N")
    # Generate RSA key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)

    # Extract private numbers from the private key
    priv_nums = private_key.private_numbers()
    p = priv_nums.p
    q = priv_nums.q
    d = priv_nums.d
    e = priv_nums.public_numbers.e
    n = priv_nums.public_numbers.n

    # Get next possible prime and generate shares
    P = next_probable_prime_at_least(d + 1)
    shares = generate_shares(d, N, T, P)

    pub_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = random.randint(1, 100)

    # Make a directory for the election keys
    directory = Path("election_keys")
    directory.mkdir(parents=True, exist_ok=True)

    for (i, y) in shares:
        share_payload = {"key_id": key_id, "i": i, "y": y, "n": n, "e": e, "P": P, "T": T}
        (directory / f"share_{key_id}_{i}.json").write_text(json.dumps(share_payload, indent=2))

    # Store p & q for the tallier
    secret_payload = {"key_id": key_id, "p": p, "q": q}
    (directory / f"secret_{key_id}.json").write_text(json.dumps(secret_payload, indent=2))

    return {
        "key_id": key_id,
        "public_pem": pub_pem.decode()
    }

def post_pubkey(key_id, public_pem):
    # Create url and header
    url = f"{base_url}/pubkey"
    headers = {"Authorisation": f"Bearer {current_admin['token']}"}
    resp = requests.post(url, json={"key_id": key_id, "pem": public_pem},headers=headers, timeout=5)
    resp.raise_for_status()
    print(resp.json())

def send_post(path):
    # Create the full url from the base_url and the given path ( protected from leading slash)
    server_url = f"{base_url}/{path.lstrip('/')}"
    headers = {"Authorisation": f"Bearer {current_admin['token']}", "Content-Type": "application/json"}

    try:
        # Generate a post request
        response = requests.post(server_url, json= {}, headers= headers, timeout= 5)
        response.raise_for_status()
        # Parse the resonse and print
        print(response.json())
    except requests.HTTPError as e:
        # if http error parse and print Json body if available
        resp = e.response
        try:
            print(resp.json())
        except Exception as e:
            print(f"HTTP {resp.status_code}: {resp.text} : Error {e}")
    except Exception as e:
        # Any other error give failure message
        print(f"Error : {e}")

def server_status():
    # Generate the status endpoint url
    server_url = f"{base_url}/status"

    try:
        # Generate a get request
        response = requests.get(server_url, timeout= 5)
        response.raise_for_status()
        # Parse the resonse and print
        print(response.json())
    except requests.HTTPError as e:
        # if http error parse and print Json body if available
        resp = e.response
        try:
            print(resp.json())
        except Exception as e:
            print(f"HTTP {resp.status_code}: {resp.text} : Error {e}")
    except Exception as e:
        # Any other error give failure message
        print(f"Error : {e}")

def helper():
    # Tells users how to run the script
    print("To open voting type: open")
    print("To close the voting type: close")
    print("To check the status of voting type: status")
    print("To quit type: quit")

def main():
    print("Admin System")
    # Prompt admin for username and password to get token
    while True:
        admin_id = input("Enter admin ID: ").strip()
        password = input("Enter admin password: ").strip()
        token = auth_login(admin_id, password)
        if token:
            current_admin["id"] = admin_id #type:ignore
            current_admin["token"] = token #type:ignore
            break
        print("Invalid username or password")

    helper()
    while True:
        raw = input("> ").strip()
        cmd = raw.lower()

        if cmd == "quit":
            print("Exiting Admin System")
            break

        elif cmd == "open":
            N = int(input("Number of talliers: "))
            T = int(input("Threshold: "))

            keys = generate_keys(N, T)

            post_pubkey(keys["key_id"], keys["public_pem"])
            send_post("open")

        elif cmd == "close":
            send_post("close")

        elif cmd == "status":
            server_status()

        else:
            print("That is not a valid option!")
            helper()

if __name__ == "__main__":
    main()