# Secure Distributed Voting System
![tests](https://github.com/eniat/secure-distributed-system/actions/workflows/tests.yml/badge.svg)

Python prototype of a secure electronic voting workflow using role-based authentication, encrypted ballots, digital signatures and threshold key recovery.

The system models voter registration, election opening, ballot submission, election closing, threshold-based tallying and result publication. It is a security-focused distributed systems project, not a production voting platform.

## Features

- Registrar generates voter IDs and ECDSA key pairs.
- Admin opens/closes elections and creates election key material.
- Voters authenticate, encrypt ballots and sign submissions.
- Talliers reconstruct the election key and count closed-election ballots.
- PBKDF2 password hashing with salts.
- HMAC-signed bearer tokens with expiry times.
- RSA-OAEP encryption for ballot confidentiality.
- ECDSA signatures for ballot authenticity.
- Shamir's Secret Sharing for threshold key reconstruction.
- Duplicate vote prevention per voter and election key.
- Pseudonymised ballot retrieval for talliers.
- Server-side audit logging.
- Automated end-to-end test suite covering tallying, access control and ballot secrecy.

## Tech Stack

- Python 3
- `http.server`
- `requests`
- `cryptography`
- JSON file storage
- Custom Shamir Secret Sharing implementation

## Repository Structure

```text
.
├── src/
│   ├── admin.py          # Election control and key generation
│   ├── auth.py           # Credential setup helper
│   ├── client.py         # Voter CLI
│   ├── demo_e2e.py       # Scripted walkthrough of a full election
│   ├── kerberos.py       # Password hashing and HMAC token helpers
│   ├── registrar.py      # Voter registration and signing keys
│   ├── server.py         # HTTP API, election state and audit logging
│   ├── shamir.py         # Shamir Secret Sharing
│   └── tallier.py        # Key reconstruction and vote tallying
├── tests/
│   └── test_election_e2e.py   # Automated end-to-end test suite
├── cryptographic-voting-system-security-analysis.pdf
├── requirements.txt
└── README.md
```

Runtime folders are generated automatically:

```text
auth/              # Password hashes by role
election_keys/     # Shamir shares and election key material
signature_keys/    # Voter signing keys and public key registry
server.log         # Server-side audit log
```


## Report

`cryptographic-voting-system-security-analysis.pdf` contains the written security analysis for the system. The README gives the practical setup and usage notes, while the report explains the design decisions, assumptions and threat model behind the implementation.

The report covers:

- Assumptions around off-band key delivery, voter registration and credential storage.
- A data-flow diagram showing how the admin, registrar, voter client, server and tallier interact.
- Architecture notes for each component, including `admin.py`, `client.py`, `registrar.py`, `server.py`, `tallier.py`, `kerberos.py` and `shamir.py`.
- Security design trade-offs for RSA-OAEP, ECDSA, Shamir Secret Sharing, HMAC tokens, pseudonymisation and logging.
- STRIDE threat modelling across spoofing, tampering, repudiation, information disclosure, denial of service and elevation of privilege.
- Assessment of replay, man-in-the-middle, denial-of-service, eavesdropping, ransomware and data manipulation attacks.
- Evaluation of least privilege, separation of privilege and a case study on Kad/Kademlia DHT poisoning.

## Security Design

The registrar creates voter IDs and ECDSA signing keys. The admin generates the RSA election key, splits the private exponent into Shamir shares, posts the public key and controls the election state.

Voters encrypt ballots with the active RSA public key and sign the encrypted ballot before submission. The server validates authentication, verifies signatures and blocks repeat votes for the same election key.

Talliers retrieve pseudonymised ballots after the election closes, reconstruct the private key from enough shares, decrypt the ballots and post the final tally.

## Installation

Install the dependencies:

```bash
pip install -r requirements.txt
```

Python 3.10+ is recommended.

## Tests

The suite drives the real HTTP API end to end: it registers voters with ECDSA keys, generates an RSA election key split into Shamir shares, encrypts and signs ballots, submits them, closes the election, reconstructs the key from threshold shares and verifies the tally.

```bash
pip install -r requirements.txt pytest
pytest -q
```

The server runs in a temporary directory, so no keys, credentials or ballots are written to the working tree. A full run takes roughly two minutes, dominated by RSA key generation.

Covered properties:

- Votes cast are the votes counted, and published results match the tally.
- A voter cannot vote twice, and ballot stuffing does not change the outcome.
- Votes after the election closes are rejected.
- Tampered signatures and unregistered voter IDs are rejected.
- Voters cannot open or close elections, read ballots, or post a tally.
- Ballots reach the tallier pseudonymised, with real voter IDs never exposed.
- Threshold shares reconstruct the key; below-threshold shares fail.
- Results are unavailable before tallying and while voting is open.

For a narrated walkthrough of the same lifecycle, `src/demo_e2e.py` runs the CLIs as subprocesses and prints each step.

## Manual Run

Run the components in separate terminals where needed:

```bash
python -m src.server      # Start API server
python -m src.registrar   # Add voters and list generated voter IDs
python -m src.auth        # Create admin, tallier and voter credentials
python -m src.admin       # Open or close the election
python -m src.client      # Submit votes and view results
python -m src.tallier     # Reconstruct key and tally closed-election ballots
```

Suggested manual flow:

1. Start `server.py`.
2. Use `registrar.py` and run `add`, then `voters`.
3. Use `auth.py` to create credentials for the admin, tallier and generated voter IDs.
4. Use `admin.py` to authenticate, check `status`, then run `open` with tallier count and threshold.
5. Use `client.py` to authenticate as a voter and run `vote Alice`, `vote Bob` or `vote Charlie`.
6. Use `admin.py` to run `close`.
7. Use `tallier.py` with the election key ID and comma-separated share IDs.
8. Use `client.py` and run `results` after tallying.

## API Overview

- `POST /auth/login` - authenticate and receive a bearer token.
- `POST /pubkey`, `/open`, `/close` - admin election management.
- `POST /vote` - voter submits an encrypted signed ballot.
- `POST /tally` - tallier posts final results.
- `GET /status`, `/candidates`, `/voters`, `/pubkey`, `/ballots`, `/results`.

## Limitations

This is a local prototype. It does not use TLS, uses JSON files for persistence, and stores generated key material on disk for demonstration. Credential setup is handled out-of-band through `auth.py`, and the system is not designed for real election use.

## Usage Notice

This repository is provided for portfolio and review purposes only.

All rights are reserved. No permission is granted to copy, redistribute, submit, or reuse this work, in whole or in part, for academic coursework, assessment, or commercial purposes.
