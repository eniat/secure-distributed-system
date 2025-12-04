import json
from pathlib import Path
from kerberos import role_dir, hash_password

def add_user(role: str, user_id:str,password:str ) -> Path:
    # ensure directory exists
    dir = role_dir(role)
    # get salt and hash
    creds = hash_password(password)
    # Write to json
    path = dir /f"{user_id}.json"
    path.write_text(json.dumps(creds, indent=2))
    return path

if __name__ == "__main__":
    role = input("Role (admin/tallier/voter: " ).strip()
    user_id = input("User id: ").strip()
    password = input("Password: ").strip()
    path = add_user(role, user_id, password)
    print(f"{user_id} credentials created")