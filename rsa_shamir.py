import random
from typing import List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.primitives import hashes
from shamir import generate_shares, reconstruct


# You may use the following parameters.
RSA_KEY_SIZE = 1024
N_SHARES = 3
THRESHOLD = 2

# The following function finds a prime that is greater than or equal to some target value.
def is_probable_prime(n: int, rounds: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# This function will test odd numbers to find a prime.
# You can use it to pick a prime for Shamir secrey sharing that is greater than the secret key.
def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate

# The following functions can be used to convert integers to bytes and bytes to integers respectively.
def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, byteorder="big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

# -------------------------------------------------------------------------------------------
# Here you will write interactive prompt functions that take input from the user.

# Step 2: Write a function 'prompt_message' that asks a user to input a message to encrypt.
#   Your function should return the message as bytes.
def prompt_message() -> bytes:
    message = input("Enter Message to encrypt: ").encode()
    return message

# Step 3: Write a function 'prompt_share_ids' that prompts the user to enter the share ids that will be used
# for reconstruction of the secret key.
#   Your function should take as input a list of available ids and the threshold that is required
#   to reconstruct the secret key.
#   Your function should prompt the user to input share ids separated by commas (e.g., 1,2).
#   Users must input a number of share ids that is equal to or greater than the threshold.
#   If users do not provide valid share ids, or do not provide enough shares, your function should
#   return an error.
#   Return the shares to be used for reconstruction.
# -------------------------------------------------------------------------------------------
def prompt_share_ids(available_ids: List[int], threshold: int) -> List[int]:
    raw = input(f"Enter at least {threshold} share id's seperated by commas (e.g., 1,2)").strip()

    try:
        chosen = [int(x) for x in raw.split(",") if x.strip() != ""]
    except ValueError:
        raise ValueError("Share id's must be integers")

    if len(chosen) < threshold:
        raise ValueError(f"Need at least {threshold} shares")

    if any(x not in available_ids for x in chosen):
        raise ValueError("Share is not in available ids")

    # dedup logic
    seen = set()
    unique = []
    for x in chosen:
        if x not in seen:
            unique.append(x)
            seen.add(x)

    return unique



# Step 4: Write a function main as follows:
def main():
#   1. Generate an RSA key pair using cryptography.io.
#       You should use public exponent 65537 and RSA_KEY_SIZE (defined at beginning of file) for the key size.
#       You should store the public key in a variable public_key and the private key in a vaiable private_key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size= RSA_KEY_SIZE)
    public_key = private_key.public_key()
#   2. The following code will extract private numbers from the private key.
    priv_nums = private_key.private_numbers()
    p = priv_nums.p
    q = priv_nums.q
    d = priv_nums.d
    e = priv_nums.public_numbers.e
    n = priv_nums.public_numbers.n
#   We will be sharing private key d only.
#   Print the bit length of the modulus n and private key d.
    print(f"bit length modulus n {n.bit_length()}")
    print(f"bit length private key d {d.bit_length()}")

#   3. Choose a Shamir prime P that is greater than d.
#       You should use next_probable_prime_at_least(d + 1)
    P = next_probable_prime_at_least(d + 1)
#       Print the bit length of P.
    print(f"bit length of P {P.bit_length()}")
#   4. Generate N_SHARES (defined at top of file) shares of private key d.
#       You should use generate_shares function from task 1.
#       Use threshold THRESHOLD (defined at top of file) and the Shamir prime P as additional inputs.
    shares = generate_shares(d, N_SHARES, THRESHOLD, P)
    avaiable_ids = [share_id for share_id, _ in shares]
#       Print the share ids and shares
    for share_id, share_value in shares:
        print(f"shareID: {share_id}, share Value: {share_value}")
#   5. Prompt user for message to encrypt.
    message = prompt_message()
#   6. Encrypt message using the RSA algorithm from the cryptography.io library.
#       Use OAEP for padding and the SHA256 hash function.
    ciphertext = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm= hashes.SHA256()), algorithm= hashes.SHA256(), label= None))
#       Print the ciphertext in hex format.
    print(f"ciphertext: {ciphertext.hex()}")
#   7. Prompt the user to input shares that should be used to reconstruct the private key.
#       Build a list of chosen shares that preserves the (id, value) tuples
    chosen_ids = prompt_share_ids(avaiable_ids, THRESHOLD)
#       Print the shares to be used for reconstruction.
    chosen_shares = [(share_id, share_value) for (share_id, share_value) in shares if share_id in chosen_ids]
    for share in chosen_shares:
        print(f"chosen share: {share}")
#   8. Reconstruct private key d.
#       You should use reconstruct function from task 1.
#       Name the reconstructed key d_rec.
    d_rec = reconstruct(chosen_shares, P)

#   9. The following will rebuild the private key using original p and q plus reconstructed d
    dmp1 = d_rec % (p - 1)
    dmq1 = d_rec % (q - 1)
    iqmp = pow(q, -1, p)

    public_numbers = RSAPublicNumbers(e=e, n=n)
    private_numbers = RSAPrivateNumbers(
        p=p,
        q=q,
        d=d_rec,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=public_numbers
    )
    priv_rebuilt = private_numbers.private_key()


#   10. Decrypt the ciphertext using priv_rebuilt and compare with original message.
#       Output an error if the decrypted message does not match the original message.
#       Else output a message indicating a successful decryption and print the decrypted message.
    try:
        message_dec = priv_rebuilt.decrypt(ciphertext, padding=padding.OAEP(mgf=padding.MGF1(algorithm= hashes.SHA256()), algorithm= hashes.SHA256(), label=None))
    except Exception as e:
        print(f"error: {e}")
        return

    if message_dec != message:
        print("Decryption not matched")
    else:
        print(f"Matches, message: {message_dec.decode()}")

if __name__ == "__main__":
    main()