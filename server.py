import json
from http.server import HTTPServer, BaseHTTPRequestHandler

candidates = ["Alice", "Bob", "Charlie"]
votes = {name: 0 for name in candidates}

def response(handler, code, obj):
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.end_headers()
    handler.wfile.write(json.dumps(obj).encode())

class VoteHandler(BaseHTTPRequestHandler):

    def do_POST(self):

        if "application/json" not in (self.headers.get("Content-Type")or ""):
            return response(self, 400, {"error": "Wrong content-type, has to be json"})

        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n).decode())
        cand = data.get("vote")

        if cand not in candidates:
            return response(self, 400, {"error": f"Invalid candidate '{cand}' Please vote for one of the allowed: {candidates}"})

        votes[cand] += 1
        return response(self, 200, {"message": f"Vote successfully submitted"})

    def do_GET(self):

        if self.path != "/results":
            return response(self, 404, {"error": "Not found"})

        return response(self, 200, votes)

def run():

    HTTPServer(("127.0.0.1", 5000), VoteHandler).serve_forever()

if __name__ == "__main__":
    run()
