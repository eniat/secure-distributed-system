# Step 1: Import helper functions for handling web requests and JSON responses

# Step 2: Use a dictionary to store vote counts for each candidate. It should be held in memory and updated as votes are received.
# Your voting server should accept votes for three candidates: Alice, Bob and Charlie.

# Step 3: Define a custom request handler class to manage incoming HTTP requests.
# It should handle POST requests.
# Write a function do_POST(self) that:
#   Checks that the incoming request contains JSON data. 
#   Extract the candidate name and validate that the candidate is in the allowed list defined in step 3. 
#   Return an error response if the canddiate is not in the allowed list.
#   If the candidate is in the allowed list, increment the vote count for that candidate and return a success message.
# Write a function do_GET(self) that:
#   Handles GET requests used to retrieve the current vote results. 
#   It should check that the request is targeting the /results endpoint and respond with the current vote tally in JSON format.

# Step 4: Write a function that sets up and runs the HTTP server.
# It should bind to localhost on port 5000.
# It should run until manually stopped. 
