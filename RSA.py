import random
import gmpy2


# Square and multiply algorithm
def sq_mu(base, exp, mod):
    exp_binary = bin(exp)
    value = base

    for i in range(3, len(exp_binary)):  # leftest 3 bit will be skin
        value = gmpy2.powmod(value, 2, mod)  # do base^2
        if (i != len(exp_binary)) & (exp_binary[i:i + 1] == '1'):  # if is 1 do mul
            value = gmpy2.f_mod(gmpy2.mul(value, base), mod)
    return value


# Euclidean Algorithm
def euclidean_alg(r0, r1):
    r = gmpy2.f_mod(r0, r1)
    while r != 0:
        r0 = r1
        r1 = r
        r = gmpy2.f_mod(r0, r1)
    return r1


# Extended Euclidean Algorithm
def gcdExtended(r0, r1):
    s0 = 1
    s1 = 0
    t0 = 0
    t1 = 1
    while r1 != 1:
        q = gmpy2.f_div(r0, r1)
        r = gmpy2.f_mod(r0, r1)
        s = s0 - gmpy2.mul(s1, q)
        t = t0 - gmpy2.mul(t1, q)
        r0 = r1
        r1 = r
        s0 = s1
        s1 = s
        t0 = t1
        t1 = t
    # s is no need here, if s is needed just return s,t
    return t


# Miller-Rabin Primality Test
def MR_primality_test(p, s):
    # print(f"p={p}")
    if gmpy2.f_mod(p, 2) == 0:  # if p is even number, just return false
        return False
    p_candidate = p - 1  # the ~p
    u = 0  # init for u and r
    r = 1
    while gmpy2.f_mod(p_candidate, 2) == 0:  # make ~p=2^u*r
        u += 1
        r = gmpy2.div(p_candidate, 2)
        p_candidate = gmpy2.div(p_candidate, 2)  # ~p/= 2
    # print(f"u={u} and r={r}")
    for i in range(0, s):  # witness loop, run for s times
        a = random.randint(2, p - 2)  # random pick a
        z = gmpy2.powmod(a, r, p)

        if z != 1 or z != p - 1:  # if z not equal 1 or ~p
            for j in range(1, u - 1):
                z = gmpy2.powmod(z, 2, p)  # do z^2 mod p, u-1 times
                if z == p - 1:
                    continue  # go to next witness round
            if z != p - 1:
                return False

    return True


# function to pick up two prime p and q
def pick_up_two_primes(bit_length):
    while True:
        p = gmpy2.mpz(random.getrandbits(bit_length))  # randomly generate ask bit length number
        p = gmpy2.next_prime(p)  # target to next prime close to p
        q = gmpy2.mpz(random.getrandbits(bit_length))
        q = gmpy2.next_prime(q)
        while p == q:  # make sure p and q not same number
            q = gmpy2.mpz(random.getrandbits(bit_length))
            q = gmpy2.next_prime(q)
        if MR_primality_test(p, 5) and MR_primality_test(q, 5):  # run  Miller-Rabin Primality Test, 5 rounds
            return p, q


# RSA key generation function
def RSA_key_generation(key_length: int):
    # 1.pick p and q
    p, q = pick_up_two_primes(key_length)
    # print(f"p={p} and q={q}")
    # 2. compute n and phi(n)
    n = gmpy2.mul(p, q)  # p*q
    phi_n = gmpy2.mul(p - 1, q - 1)  # (p-1)*(q-1)
    # 3. randomly choose a e which gcd(e,phi(n))=1, e is {1......phi(n)-1}
    e = random.randint(1, phi_n - 1)
    while euclidean_alg(phi_n, e) != 1:
        e = random.randint(1, phi_n - 1)

    # 4.find d using d = e^-1 mod phi(n)
    d = gcdExtended(phi_n, e)
    # print out result of key generation
    print(f"p={p}\nq={q}\nn={n}\nphi(n)={phi_n}\ne={e}\nd={d}")
    print(f"gcd(phi_n,e) => {euclidean_alg(phi_n, e)}")
    print(f"d*e mod phi_n => {gmpy2.f_mod(gmpy2.mul(d, e), phi_n)}")  # d*e%phi_n
    # return public key and private key
    return (e, n), d


def RSA_encryption(msg, e, n):
    # for small words message:
    # msg_in_decimal = [ord(i) for i in msg]
    # print(msg_in_decimal)
    # meg_encrypted = [sq_mu(base=c,exp=e,mod=n) for c in msg_in_decimal]
    # print(meg_encrypted)

    # for numbers only
    meg_encrypted = sq_mu(base=msg, exp=e, mod=n)
    return meg_encrypted


def RSA_decryption(ciphertext, d, n):
    # for small words message:
    # plaintext_in_decimal = [sq_mu(base=x,exp=d,mod=n) for x in ciphertext]
    # print(plaintext_in_decimal)
    # plaintext = [chr(i) for i in plaintext_in_decimal]

    # for numbers only
    plaintext = sq_mu(base=ciphertext, exp=d, mod=n)
    print(f"plain text :{plaintext}")


# example with small p and q:
# RSA_key_generation()
# p=7547 and q=6263
# n=47266861 and phi(n)=47253052
# e=5834025 and d=7609029
# ciphertxt = RSA_encryption("avxc", e=5834025, n=47266861)
# RSA_decryption(ciphertxt,d=7609029,n=47266861)

# example with 512bit length of p,q
public_key, private_key = RSA_key_generation(512)
print("input number is 39")
ciphertxt = RSA_encryption(39, e=public_key[0], n=public_key[1])
RSA_decryption(ciphertxt, d=private_key, n=public_key[1])
