import random
import secrets
from typing import List, Tuple

Share = Tuple[int, int]

def eval_polynomial(coeffs : List[int], x: int, p: int) -> int:
    result = 0
    power = 1

    for c in coeffs:
        result = (result + c * power) %p
        power = (power * x) %p
    return result


def generate_shares(secret:int, n: int, t: int, p:int) -> List[Share]:
    if not (1 <= t <= n):
        raise ValueError("1 <= t <= n")

    secret %=p
    coeffs = [secret] + [secrets.randbelow(p) for _ in range (t-1)]

    shares = []
    for i in range(1, n+1):
        y = eval_polynomial(coeffs, i, p)
        shares.append((i, y))
    return shares


def lagrange_interpolate_at_zero(x_s: List[int], y_s: List[int], prime: int) -> int:
    assert len(x_s) == len(y_s)
    k = len(x_s)
    total = 0
    for j in range(k):
        xj, yj = x_s[j], y_s[j]
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            xm = x_s[m]
            num = (num * (-xm)) % prime
            den = (den * (xj - xm)) % prime
        inv_den = pow(den, -1, prime)
        lj = (num * inv_den) % prime
        total = (total + yj * lj) % prime
    return total

def reconstruct(shares: List[Share], p: int) -> int:
    x_s = [x for x, _ in shares]
    y_s = [y for _, y in shares]
    if len(set(x_s)) != len(x_s):
        raise ValueError("Duplicate x's in shares")
    return lagrange_interpolate_at_zero(x_s, y_s, p)

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
def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate


def demo():
    prime = 2**127 - 1
    secret = 42
    n = 6
    t = 3

    #   Generate shares and print the shares.
    shares = generate_shares(secret, n, t, prime)
    for s in shares:
        print (f"Share: x={s[0]}, y={s[1]}")

    #   Reconstruct the secret from first t shares and print the result.
    round1 = reconstruct(shares[:t], prime)
    print(f"reconstructed from {t} shares: {round1}")

    #   Reconstruct the secret from an arbitrary subset of t shares. Print the result.
    arbitrary = [shares[i] for i in (1,4,5)]
    round2 = reconstruct(arbitrary, prime)
    print(f"reconstructed from arbitrary subset {arbitrary} : {round2}")

    #   Attempt to reconstruct the secret with fewer than t shares.
    #   This should produce a wrong value.
    fewer = shares[:t-1]
    round3 = reconstruct(fewer, prime)
    print(f"reconstructed than fewer than {t} shares : {round3}")

    #   Tamper a share and show that it returns a wrong value.
    tamper = arbitrary.copy()
    tamper[0] = (0,0)
    round4 = reconstruct(tamper, prime)
    print(f"reconstructed with share tampered : {round4}")

if __name__ == "__main__":
    demo()
