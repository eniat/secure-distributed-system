# Step 1: Import the requests library to send HTTP requests to the server

# Step 2: Define the base URL of the server
# This should match the host and port used in server.py

# Step 3: Write a function to send a vote
#   Prepare the headers and JSON payload
#   Send a POST request to the /vote endpoint and raise an error if the server responds with a failure code (e.g. 400 or 500)
#   Print the server's response (should be a confirmation message)

# Step 4: Write a function to fetch current vote results
#   Send a GET request to the /results endpoint
#   Print the vote tally in a readable format

# Step 5: Create a simple command-line interface
#   This lets users type commands to vote or view results
#   If the user types a vote command, extract the candidate name and send the vote
#   If the user types 'results', fetch and display the current tally
