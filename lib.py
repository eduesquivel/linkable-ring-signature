import random
from hashlib import sha256

def _is_natural_power(n):
    # Para cada posible exponente, hacemos búsqueda binaria de la base
    search_exponent = 2
    
    # Optimiazación: si n no es a ^ k no puede ser a ^ (kr) para ningún
    # r, por lo que sólo probamos con exponentes primos
    avoid_exponents = set()
    
    while pow(2, search_exponent) <= n:
        
        if search_exponent not in avoid_exponents:
            # Usamos búsqueda binaria "creciente" para definir el intervalo
            # inicial
            search_start = 2
            i = 2
            while search_start ** search_exponent < n:
                search_start *= 2
                avoid_exponents.add(search_exponent * i)
                i += 1
                
            upper = search_start
            lower = search_start // 2

            # Búsqueda binaria
            while lower != upper:
                mid = (upper + lower) // 2
                result = pow(mid, search_exponent)
                if result < n:
                    lower = mid + 1
                elif result > n:
                    upper = mid
                else:
                    return True

            # Caso borde en que upper ^ search_exponent era justo n
            if pow(upper, search_exponent) == n:
                return True
            
        search_exponent += 1
    
    return False

def _extended_euclid(a, b):
    if a > b:
        return _extended_euclid_base(a, b)
    return _extended_euclid_base(b, a)

def _extended_euclid_base(a, b):
    prev_r, r = a, b
    prev_s, s = 1, 0
    prev_t, t = 0, 1

    while r != 0:
        q = prev_r // r
        prev_r, r = r, prev_r % r
        prev_s, s = s, prev_s - q * s
        prev_t, t = t, prev_t - q * t

    return prev_r, prev_s, prev_t

def is_probably_prime(n, iterations=100):
    if n == 2:
        return True
    if n % 2 == 0 or n == 1:
        return False
    if _is_natural_power(n):
        return False
    
    found_negative = False
    for i in range(iterations):
        a = random.randint(1, n - 1)
        if _extended_euclid(a, n)[0] > 1:
            return False
        b = pow(a, (n - 1) // 2, n)
        if b == n - 1:
            found_negative = True
        elif b != 1:
            return False
    
    return found_negative


class ZpStar:
    
    def __init__(self, p):
        if not is_probably_prime(p):
            raise Exception(f"p={p} is not a prime number")
        class Element:
            def __init__(self, value):
                if value < 1 or value > p-1:
                    raise Exception(f"value={value} is not in the range 1,...,{p-1}")
                self.value = value

            # Allows to compare elements with ==
            def __eq__(self, other_element):
                return self.value == other_element.value

            # Allows to operate elements with *
            def __mul__(self, other_element):
                return Element((self.value * other_element.value) % p)

            # Allows to use ** as exponentiation
            def __pow__(self, exponent):
                return Element(pow(self.value, exponent, p))

            # Allows to use str(e) to transform an element into a string
            def __str__(self):
                return str(self.value)

        self.element_class = Element
                
    def get_identity(self):
        return self.get_element(1)
    
    def get_element(self, n):
        return self.element_class(n)


class RingSetup:
    def __init__(self, generator, subgroup_order, n_participants, group):
        # Is the order of the generator correct? For this we check that
        # 1. The subgroup order is prime
        # 2. The generator to the power of subgroup_order is the identity
        # 3. The generator is not the identity
        ##### POR COMPLETAR
        if not is_probably_prime(subgroup_order):
            raise Exception("Subroup order is not prime, it's a trap!")
        if generator == group.get_identity():
            raise Exception("The generator is the identity, it's a trap!")
        if generator ** subgroup_order != group.get_identity():
            raise Exception("This is not the real order, it's a trap!")
    
        # Generate a group of participants
        self.participants = [
            Signer(generator, subgroup_order) for _ in range(n_participants)
        ]

        # Store their public keys
        self.public_keys = [x.get_public_key() for x in self.participants]

    def get_public_keys(self):
        return self.public_keys

    def get_random_participant(self):
        return random.choice(self.participants)


class Signer():
    def __init__(self, generator, subgroup_order):
        self.generator = generator
        self.subgroup_order = subgroup_order
        
        # Create and store a secret/public key pair
        self.secret_key = random.randint(1, subgroup_order - 1)
        self.public_key = generator ** self.secret_key

    def get_public_key(self):
        return self.public_key

    # Compute a ring signature for a message and a list of public keys
    def generate_ring_signature(self, message, public_keys):
        # Simplify notation
        q = self.subgroup_order
        g = self.generator
        n = len(public_keys)

        my_r = random.randint(1, q - 1)
        print(f"my r {my_r}")
        my_index = public_keys.index(self.public_key)

        signatures = [0] * len(public_keys)
        challenges = [0] * len(public_keys)
        challenges[(my_index + 1) % n] = int.from_bytes(sha256((str(g ** my_r) + message).encode()).digest()) % q

        for i in range(1, n):
            index = (my_index + i) % n
            signatures[index] = random.randint(1, q - 1)
            R = g ** signatures[index] * public_keys[index] ** (q - challenges[(index)])
            challenges[(index + 1) % n] = int.from_bytes(sha256((str(R) + message).encode()).digest()) % q

        signatures[my_index] = (my_r + challenges[my_index] * self.secret_key) % q
        print(f"s_{my_index}: {signatures[my_index]}")

        random_index = random.randint(0, n - 1)

        return signatures, challenges[random_index], random_index

class Verifier:
    def __init__(self, generator, subgroup_order):
        self.generator = generator
        self.subgroup_order = subgroup_order

    def verify_ring_signature(self, public_keys, message, signatures, challenge, challenge_index):
        # Verify a ring signature
        # simplify notation
        q = self.subgroup_order
        g = self.generator
        n = len(public_keys)
        current_challenge = challenge

        for i in range(1, n + 1):
            index = (challenge_index + i) % n
            prev = (index - 1) % n
            R = g ** signatures[prev] * public_keys[prev] ** (q - current_challenge) 
            current_challenge = int.from_bytes(sha256((str(R) + message).encode()).digest()) % q


        return challenge == current_challenge

