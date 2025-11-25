import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

AUTH_ROOT = Path("auth")
SECRET_PATH = AUTH_ROOT/ "server_secret.key"

def role_dir(role: str) -> Path:
    # Designated roles
    mapping = {"voter": "voters", "tallier": "talliers", "admin": "admins"}
    # If not designated role raise error
    if role not in mapping:
        raise ValueError("Invalid role given")
    # Returns directory related to role
    direc = AUTH_ROOT / mapping[role]
    direc.mkdir(parents=True, exist_ok=True)
    return direc

def get_secret() -> bytes:
    # Make the path for the secret and set secret
    AUTH_ROOT.mkdir( parents= True, exist_ok= True)
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(os.urandom(32))
    # Return secret bytes
    return SECRET_PATH.read_bytes()

def hash_password(password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
    # If no salt given create random one
    if salt is None:
        salt = os.urandom(16)
    # Hash password with sha256 with length 32 and return the hex
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return {"salt": salt.hex(), "hash": hashed.hex()}

def verify_password(password :str, salt_hex:str, hash_hex: str) -> bool:
    # Get the salt and the excepted hash value
    salt = bytes.fromhex(salt_hex)
    expec = bytes.fromhex(hash_hex)
    # Recalculate and compare
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return hmac.compare_digest(test, expec)

def load_user(role: str, user_id:str) -> Optional[Dict[str, str]]:
    # get the path from role_dir for the specified role
    path = role_dir(role) / f"{user_id}.json"
    # If doesnt exist then return None
    if not path.exists():
        return None
    # Try read the json if you can't return error message and nome
    try:
        return json.loads(path.read_text())
    except Exception as e:
        print(f"error: {e}")
        return None

def create_token(role: str, user_id:str, lifetime: int ) -> str:
    # get current time and append it with the token expiry time
    now = int(time.time())
    payload = {"role": role, "id": user_id, "iat": now, "exp": now + lifetime}
    # Create a hmac of the data also passes the payload as json
    body = json.dumps(payload, separators=(",",":"), sort_keys= True).encode( "utf-8")
    mac_hex = hmac.new(get_secret(), body, hashlib.sha256).hexdigest()
    body_hex = body.hex()
    # returns hex of body and mac
    return f"{body_hex}.{mac_hex}"

def verify_token(token: str) -> Dict[str, Any]:
    # Tries to split tokens to mac and body if fails raises error
    try:
        body_hex, mac_hex = token.split(".", 1)
    except ValueError:
        raise ValueError("Error splitting")
    # Try to read the body from hex
    try:
        body = bytes.fromhex(body_hex)
    except ValueError:
        raise ValueError("Error with body")
    # Check the signature to make sure they match
    test_mac_hex = hmac.new(get_secret(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac_hex, test_mac_hex):
        raise ValueError("Signatures don't max")
    # Get the "claims"
    try:
        claims = json.loads(body.decode("utf-8"))
    except Exception:
        raise ValueError("Error with claims")
    # Check that the "claims" isn't expired
    now = int(time.time())
    if now >= int(claims.get("exp",0)):
        raise ValueError("Token has expired ")
    return claims

def role_from_header(auth_header: str, allowed_roles) -> Dict[str, Any]:
    # checks that there is a valid bearer part
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise PermissionError("missing bearer token")
    # Get token and verify it
    token = auth_header.split(" ", 1)[1].strip()
    claims= verify_token(token)
    # Get the role and check they're permitted
    role = claims.get("role")
    if role not in allowed_roles:
        raise PermissionError("Access not allowed")
    return claims