import requests

base_url = "http://127.0.0.1:5000"


def send_post(path):
    # Create the full url from the base_url and the given path ( protected from leading slash)
    server_url = f"{base_url}/{path.lstrip('/')}"
    headers = {"Content-Type": "application/json"}

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

    helper()
    while True:
        raw = input("> ").strip()
        cmd = raw.lower()

        if cmd == "quit":
            print("Exiting Admin System")
            break

        elif cmd == "open":
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