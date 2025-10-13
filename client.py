import requests

baseUrl = "127.0.0.1:5000"

def send_vote(vote):
    url = f"http://{baseUrl}/vote"
    data = {"vote":vote}

    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        print(f"Server response: {response.json()['message']}")
    except requests.exceptions.RequestException as e:
        print(f"Failed with code: {e}")

def fetch_results():
    url = f"http://{baseUrl}/results"

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
