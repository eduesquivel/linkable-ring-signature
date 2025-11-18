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
    # MODIFIED: Added h_generator
    def __init__(self, generator, h_generator, subgroup_order, n_participants, group):
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
            
        # MODIFIED: Check the new generator h
        if h_generator == group.get_identity():
            raise Exception("The h_generator is the identity, it's a trap!")
        if h_generator ** subgroup_order != group.get_identity():
            raise Exception("This is not the real order for h, it's a trap!")
        if h_generator == generator:
            raise Exception("g and h cannot be the same generator!")
            
        self.generator = generator
        self.h_generator = h_generator
        self.subgroup_order = subgroup_order

        # Generate a group of participants
        self.participants = [
            # MODIFIED: Pass h_generator to the Signer
            Signer(generator, h_generator, subgroup_order) for _ in range(n_participants)
        ]

        # Store their public keys
        self.public_keys = [x.get_public_key() for x in self.participants]

    def get_public_keys(self):
        return self.public_keys

    def get_random_participant(self):
        return random.choice(self.participants)
        
    # MODIFIED: Helper function to get the other participant
    def get_other_participant(self, signer):
        for p in self.participants:
            if p != signer:
                return p
        return signer

class Signer():
    # MODIFIED: Added h_generator
    def __init__(self, generator, h_generator, subgroup_order):
        self.generator = generator
        self.h_generator = h_generator # MODIFIED: Store h
        self.subgroup_order = subgroup_order
        
        # Create and store a secret/public key pair
        self.secret_key = random.randint(1, subgroup_order - 1)
        self.public_key = generator ** self.secret_key
        
        # MODIFIED: Create the Key Image (Tag)
        self.key_image = self.h_generator ** self.secret_key

    def get_public_key(self):
        return self.public_key
        
    # MODIFIED: Add a getter for the key image
    def get_key_image(self):
        return self.key_image

    # MODIFIED: This function is heavily changed
    # Compute a ring signature for a message and a list of public keys
    def generate_ring_signature(self, message, public_keys):
        # Simplify notation
        q = self.subgroup_order
        g = self.generator
        h = self.h_generator # MODIFIED: Get h
        I = self.key_image  # MODIFIED: Get Key Image
        n = len(public_keys)
        x_i = self.secret_key
        my_index = public_keys.index(self.public_key)

        # MODIFIED: Hash the message with the public key ring
        # This prevents an attacker from swapping public keys
        m_prime = "".join([str(pk) for pk in public_keys]) + message

        # Store s and c values
        signatures = [0] * n
        challenges = [0] * n

        # === Signer's "secret" step ===
        # 1. Generate a random nonce
        my_r = random.randint(1, q - 1)

        # 2. Compute the "commitment" values for the signer's position
        R_i = g ** my_r
        R_prime_i = h ** my_r
        
        # 3. Compute the *next* challenge in the ring, c_{i+1}
        c_next = int.from_bytes(
            sha256((str(R_i) + str(R_prime_i) + m_prime).encode()).digest()
        ) % q
        challenges[(my_index + 1) % n] = c_next

        # === Faking the rest of the ring ===
        # 4. Iterate for all other participants
        for i in range(1, n):
            index = (my_index + i) % n
            
            # 5. Pick a random s_j (the "fake" signature part)
            s_j = random.randint(1, q - 1)
            signatures[index] = s_j
            c_j = challenges[index]
            y_j = public_keys[index]

            # 6. Compute R_j and R'_j using the ring equations
            # R = g^s * y^(-c)  ==> g^s * y^(q-c)
            # R' = h^s * I^(-c) ==> h^s * I^(q-c)
            R_j = (g ** s_j) * (y_j ** (q - c_j))
            R_prime_j = (h ** s_j) * (I ** (q - c_j))
            
            # 7. Compute the *next* challenge c_{j+1}
            c_next = int.from_bytes(
                sha256((str(R_j) + str(R_prime_j) + m_prime).encode()).digest()
            ) % q
            challenges[(index + 1) % n] = c_next

        # === Closing the loop ===
        # 8. Get the signer's challenge, c_i
        c_i = challenges[my_index]
        
        # 9. Solve for the signer's signature part, s_i
        # s_i = r + c_i * x_i  (mod q)
        signatures[my_index] = (my_r + c_i * x_i) % q

        # MODIFIED: The signature is (KeyImage, c1, [s1, s2, ..., sn])
        # We return c[0] (which is c_1 in 1-based indexing)
        return I, challenges[0], signatures

class Verifier:
    # MODIFIED: Added h_generator
    def __init__(self, generator, h_generator, subgroup_order):
        self.generator = generator
        self.h_generator = h_generator # MODIFIED: Store h
        self.subgroup_order = subgroup_order

    # MODIFIED: This function is heavily changed
    def verify_ring_signature(self, public_keys, message, key_image, c1, signatures):
        # Verify a ring signature
        # simplify notation
        q = self.subgroup_order
        g = self.generator
        h = self.h_generator # MODIFIED: Get h
        I = key_image       # MODIFIED: Get I
        n = len(public_keys)
        
        # MODIFIED: Hash the message with the public key ring
        m_prime = "".join([str(pk) for pk in public_keys]) + message
        
        # MODIFIED: We will re-compute the entire ring of challenges
        current_challenge = c1
        
        for i in range(n):
            s_i = signatures[i]
            y_i = public_keys[i]
            c_i = current_challenge
            
            # 1. Re-compute R_i and R'_i for this participant
            # R = g^s * y^(-c)  ==> g^s * y^(q-c)
            # R' = h^s * I^(-c) ==> h^s * I^(q-c)
            R_i = (g ** s_i) * (y_i ** (q - c_i))
            R_prime_i = (h ** s_i) * (I ** (q - c_i))
            
            # 2. Compute the *next* challenge
            current_challenge = int.from_bytes(
                sha256((str(R_i) + str(R_prime_i) + m_prime).encode()).digest()
            ) % q
            
        # 3. After n iterations, 'current_challenge' is the re-computed c1.
        # We check if it matches the c1 we started with.
        return c1 == current_challenge

if __name__ == "__main__":
    p, generator_val, order = 643, 4, 107
    
    # MODIFIED: We need a second generator h. 
    # For this academic example, we'll just use g^2.
    # In a real system, h should be chosen carefully, e.g., via hashing.
    h_val = 16 # 4^2 = 16. This is also in the subgroup.

    group = ZpStar(p)
    g = group.get_element(generator_val)
    h = group.get_element(h_val) # MODIFIED: Create h element

    # MODIFIED: Pass 'h' to the RingSetup
    ring = RingSetup(g, h, order, 2, group)
    signer = ring.get_random_participant()
    other_signer = ring.get_other_participant(signer) # MODIFIED: Get the other signer

    message = "Hello from IIC3253"
    print(f"Message: {message}")
    print(f"Public keys: {[str(x) for x in ring.get_public_keys()]}")
    print(f"Signer 1 Public Key: {signer.get_public_key()}")
    print(f"Signer 2 Public Key: {other_signer.get_public_key()}")
    print("---")

    # MODIFIED: The signature format has changed
    key_image_1, c1_1, signatures_1 = signer.generate_ring_signature(
        message, ring.get_public_keys()
    )
    print("--- SIGNATURE 1 (from Signer 1) ---")
    print(f"Key Image: {key_image_1}")
    print(f"c1: {c1_1}")
    print(f"Signatures: {signatures_1}")
    
    # MODIFIED: Pass 'h' to the Verifier
    verifier = Verifier(g, h, order)
    
    # MODIFIED: Call the new verify function
    result = verifier.verify_ring_signature(
        ring.get_public_keys(), message, key_image_1, c1_1, signatures_1
    )
    print(f"\nCorrect signature: {result}")
    
    # MODIFIED: Test invalid signature
    bad_signatures = signatures_1.copy()
    bad_signatures[0] = (bad_signatures[0] - 1) % order
    result = verifier.verify_ring_signature(
        ring.get_public_keys(), message, key_image_1, c1_1, bad_signatures
    )
    print(f"Incorrect signature: {result}")
    
    print("\n" + "="*30)
    print("DEMONSTRATING LINKABILITY")
    print("="*30)
    
    # MODIFIED: Sign *again* with the *same* signer
    print("Signer 1 signs a *new* message...")
    message_2 = "This is a second message"
    key_image_2, c1_2, signatures_2 = signer.generate_ring_signature(
        message_2, ring.get_public_keys()
    )
    print("--- SIGNATURE 2 (from Signer 1) ---")
    print(f"Key Image: {key_image_2}")
    
    # MODIFIED: Sign with the *other* signer
    print("\nSigner 2 signs...")
    message_3 = "This is from the other user"
    key_image_3, c1_3, signatures_3 = other_signer.generate_ring_signature(
        message_3, ring.get_public_keys()
    )
    print("--- SIGNATURE 3 (from Signer 2) ---")
    print(f"Key Image: {key_image_3}")
    
    print("\n--- LINKABILITY RESULTS ---")
    print(f"Signer 1 Key Image (Sig 1): {key_image_1}")
    print(f"Signer 1 Key Image (Sig 2): {key_image_2}")
    print(f"Signer 2 Key Image (Sig 3): {key_image_3}")
    
    # The key images from the same signer (1 and 2) MUST be identical
    print(f"\nSig 1 and 2 from same signer? {key_image_1 == key_image_2} (Should be True)")
    
    # The key images from different signers MUST be different
    print(f"Sig 1 and 3 from different signers? {key_image_1 != key_image_3} (Should be True)")
