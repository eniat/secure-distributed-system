import subprocess, sys, time, json
from pathlib import Path

import requests

from auth import add_user

PY = sys.executable or "python3"
BASE_URL = "http://127.0.0.1:5000"

ADMIN_ID = "admin"
TALLIER_ID = "tallier"
PASSWORD = "password"

def start_proc(script_name):
    # Starts a cli as a subprocess
    return subprocess.Popen([PY, script_name],stdin= subprocess.PIPE, text= True, bufsize=1)

def send_cmd(proc, line):
    # Send inpout to subprocess
    proc.stdin.write(line + "\n")
    proc.stdin.flush()

def start_server():
    print("[1] Starting server.py")
    server = subprocess.Popen([PY, "server.py"])
    # Slight wait for server
    time.sleep(1)
    return server

def registrar_add_and_list(num_voters:int):
    print("\n######################################")
    print("\n[2] Registrar add voters and list them")
    proc = start_proc("registrar.py")
    time.sleep(0.2)
    send_cmd(proc, "add")
    send_cmd(proc, str(num_voters))
    send_cmd(proc, "voters")
    send_cmd(proc, "quit")
    proc.wait()
    # Load the voters ID's
    db_path = Path("signature_keys") / "public_keys.json"
    data = json.loads(db_path.read_text())
    voter_ids = list(data.keys())
    # Only get the recent voter_id's for auth
    selected = voter_ids[-num_voters:]
    print("     Using voter IDs:", selected)
    return selected

def setup_auth(voter_ids):
    # Although Auth does have a cli, due to passwords being set off band in my assumption this is done manually here
    print("\n######################################")
    print("\n[3] Credentials set up for users")
    add_user("admin", ADMIN_ID, PASSWORD)
    add_user("tallier", TALLIER_ID, PASSWORD)
    print(f"    Admin set up: {ADMIN_ID}, {PASSWORD}")
    print(f"    Tallier set up: {TALLIER_ID}, {PASSWORD}")
    # Voters set up from given voter ids
    for voter_id in voter_ids:
        add_user("voter", voter_id, PASSWORD)
        print(f"    Voter set up: {voter_id}, {PASSWORD}")

def get_key_id_from_pubkey() -> str:
    # Reads active keyID from server, as this would be sent where needed off band
    res = requests.get(f"{BASE_URL}/pubkey", timeout= 5)
    obj = res.json()
    key_id = obj.get("key_id")
    print(f"    key_id from /pubkey {key_id}")
    return str(key_id)

def admin_open_election():
    print("\n######################################")
    print("\n[4] Admin logs in opens election, generates and posts pub key")
    proc = start_proc("admin.py")
    time.sleep(0.2)
    #login
    send_cmd(proc, ADMIN_ID)
    send_cmd(proc, PASSWORD)
    time.sleep(0.5)
    # Check status
    send_cmd(proc, "status")
    time.sleep(0.5)
    # Open election
    send_cmd(proc, "open")
    send_cmd(proc, "3")
    send_cmd(proc, "2")
    time.sleep(1.0)
    send_cmd(proc, "quit")
    proc.wait()
    # Now set retrieve key_id and return
    key_id = get_key_id_from_pubkey()
    return key_id

def client_vote(voter_id:str, candidate: str, check_status: bool = False):
    print("\n######################################")
    print(f"\n[5] Client voter {voter_id} voting for {candidate}. (one after election closed)")
    proc = start_proc("client.py")
    time.sleep(0.2)
    #login
    send_cmd(proc, voter_id)
    send_cmd(proc, PASSWORD)
    time.sleep(0.5)
    # Check status if true
    if check_status:
        send_cmd(proc, "status")
        time.sleep(0.5)
    # Vote
    send_cmd(proc, f"vote {candidate}")
    time.sleep(0.5)
    send_cmd(proc, "quit")
    proc.wait()

def admin_close_election():
    print("\n######################################")
    print(f"\n[6] Admin logs in and closes election with wrong password first before redoing")
    proc = start_proc("admin.py")
    time.sleep(0.2)
    # wrong login to show it works
    send_cmd(proc, ADMIN_ID)
    send_cmd(proc, "Not password")
    # Now with right
    time.sleep(0.2)
    send_cmd(proc, ADMIN_ID)
    send_cmd(proc, PASSWORD)
    time.sleep(0.5)
    send_cmd(proc, "close")
    time.sleep(0.5)
    send_cmd(proc, "quit")
    proc.wait()

def tallier_tally(key_id: str):
    print("\n######################################")
    print(f"\n[7] Tallier logs in enters the key_id and wrong share ids first then correct to tally votes")
    # Wrong share Ids first
    proc1 = start_proc("tallier.py")
    time.sleep(0.2)
    send_cmd(proc1, TALLIER_ID)
    send_cmd(proc1, PASSWORD)
    time.sleep(0.5)
    send_cmd(proc1, key_id)
    time.sleep(0.2)
    send_cmd(proc1, "5,8")
    time.sleep(1)
    # Now right share IDs
    proc = start_proc("tallier.py")
    time.sleep(0.2)
    send_cmd(proc, TALLIER_ID)
    send_cmd(proc, PASSWORD)
    time.sleep(0.5)
    send_cmd(proc, key_id)
    time.sleep(0.2)
    send_cmd(proc, "1,2")
    time.sleep(1)
    proc.wait()

def client_show_result(voter_id: str):
    print("\n######################################")
    print("\n[8] Client logs in and fetches results (also done one before results tallied to show error)")
    proc = start_proc("client.py")
    time.sleep(0.2)
    # Login
    send_cmd(proc, voter_id)
    send_cmd(proc, PASSWORD)
    time.sleep(0.5)
    send_cmd(proc, "results")
    time.sleep(0.5)
    send_cmd(proc, "quit")
    proc.wait()

def main():
    # start server
    server = start_server()

    try:
        # [1] Registrar add 4 voters and then list
        voter_ids = registrar_add_and_list(4)
        # [2] Auth credentials set up for all users which would be off band
        setup_auth(voter_ids)
        # [3] Admin checks status and then opens elections and gets key_id
        key_id = admin_open_election()
        #[4] Clients vote one client votes for charlie twice then bob, whilst the other two vote for alice
        v1, v2, v3, v4 = voter_ids
        # voter 1 checks status and votes for alice
        client_vote(v1, "Alice", check_status=True)
        # voter 2 goes wild first should be counted other two get errors
        client_vote(v2, "Charlie")
        client_vote(v2, "Charlie")
        client_vote(v2, "Bob")
        # voter 3 for Alice
        client_vote(v3, "Alice")

        # [5] Admin closes election
        admin_close_election()
        # sneaky vote placed after election closed by v4
        client_vote(v4, "Bob")
        # Client tries to check before results
        client_show_result(v1)
        #[6] Tallier runs with first giving incorrect share_ids then correcttly and posts
        tallier_tally(key_id)
        # [7] Client shows results successfully
        client_show_result(v2)
        print("\n [FINAL] TEST HAS FINISHED")
    finally:
        print("Stopping server.py")
        server.terminate()

if __name__ == "__main__":
    main()