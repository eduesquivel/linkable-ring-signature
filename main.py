from lib import ZpStar, RingSetup, Verifier

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
    print(f"--- SIGNATURE 1 (from Signer 1) ---")
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
    print(f"Signer 1 signs a *new* message...")
    message_2 = "This is a second message"
    key_image_2, c1_2, signatures_2 = signer.generate_ring_signature(
        message_2, ring.get_public_keys()
    )
    print(f"--- SIGNATURE 2 (from Signer 1) ---")
    print(f"Key Image: {key_image_2}")
    
    # MODIFIED: Sign with the *other* signer
    print(f"\nSigner 2 signs...")
    message_3 = "This is from the other user"
    key_image_3, c1_3, signatures_3 = other_signer.generate_ring_signature(
        message_3, ring.get_public_keys()
    )
    print(f"--- SIGNATURE 3 (from Signer 2) ---")
    print(f"Key Image: {key_image_3}")
    
    print("\n--- LINKABILITY RESULTS ---")
    print(f"Signer 1 Key Image (Sig 1): {key_image_1}")
    print(f"Signer 1 Key Image (Sig 2): {key_image_2}")
    print(f"Signer 2 Key Image (Sig 3): {key_image_3}")
    
    # The key images from the same signer (1 and 2) MUST be identical
    print(f"\nSig 1 and 2 from same signer? {key_image_1 == key_image_2} (Should be True)")
    
    # The key images from different signers MUST be different
    print(f"Sig 1 and 3 from different signers? {key_image_1 != key_image_3} (Should be True)")
