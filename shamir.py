import secrets
from typing import List, Tuple

Share = Tuple[int, int]

# Define a function 'eval_polynomial' that evaluates a polynomial f(x) = s + f1*x^1 + f2*x^2 + ... + ft-1*x^{t-1} at a point x (modulo a prime).
#   The function will be called in function generate_shares.
#   Your function should take as input:
#       1. a list of coefficients 'coeffs'. The coefficients list coeffs is ordered so coeffs[0] is the constant term (i.e., secret s), coeffs[1] is f1, coeffs[2] is f2 and so on.
#       2. an integer 'x' (the point at which the polynomial will be evaluated)
#       3. a prime number 'p'
#   Initialise two variables:
#       1. 'result' will accumulate the value of the polynomial at point x. It should start at 0.
#       2. 'power' will hold successive powers of x, beginning at x**0 = 1.
#   Evaluate the polynomial by looping through each coefficient c in coeffs:
#       1. Multiply c by the current power and add to 'result'.
#       2. Update the power by multiplying it by x.
#       3. After the loop, return the result.
#       4. Remember to perform all computations modulo prime p.
def eval_polynomial(coeffs : List[int], x: int, p: int) -> int:
    result = 0
    power = 1

    for c in coeffs:
        result = (result + c * power) %p
        power = (power * x) %p
    return result

# Define a function 'generate_shares' that will generate n shares.
#   Your function should take as input:
#       1. the secret to be shared 'secret'
#       2. the number of shares to be created 'n'
#       3. the threshold 't'
#       4. prime number 'p'
#   Construct a ranadom polynomial of degree t-1.
#       Your polynomial will be defined by its list of coefficients 'coeffs'
#       Define coeffs[0] = secret
#       For 1,...,t-1, the coefficient should be a random value chosen from the range 0,...,prime-1.
#   Produce shares by evaluating the polynomial at x = 1,...,n.
#       That is, for each i = 1,...,n, compute y = f(i) using eval_polynomial.
#       Store each share as a tuple (i, y) in a list.
#   Return the list of shares.
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


# The following function reconstructs the polynomial for a list of shares.
# It uses a method callled Lagrange interpolation to compute f(0) given a list of shares.
# It takes as input:
#   1. a list of elements 'i' incidcating which shares are being combined.
#   2. a list of elements 'y', which are the shares corresponding to the 'i' indices.
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

# Step 5: Define a function 'reconstruct' that will return the secret from a list of provided shares.
#   Your function should take as input:
#       1. a list of shares 'List'
#       2. prime 'p'
#   Separate the input list of tuples returned by generate_shares into two lists:
#       1. x_s that will hold the first element of each tuple, the participants 'i' value
#       2. y_s which will hold the corresponding share value
#   Call function lagrange_interpolate_at_zero
#   Return the secret
def reconstruct(shares: List[Share], p: int) -> int:
    x_s = [x for x, _ in shares]
    y_s = [y for _, y in shares]
    if len(set(x_s)) != len(x_s):
        raise ValueError("Duplicate x's in shares")
    return lagrange_interpolate_at_zero(x_s, y_s, p)


# Step 6: Define a dunction demo() that will run and perform basic tests on your code.
def demo():
    # You can use the values below to test your code.
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