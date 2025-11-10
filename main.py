from lib import ZpStar, RingSetup, Verifier

if __name__ == "__main__":
    p, generator, order = 643, 4, 107

    group = ZpStar(p)
    g = group.get_element(generator)

    ring = RingSetup(g, order, 2, group)
    signer = ring.get_random_participant()

    message = "Hello from IIC3253"
    print(f"Message:               {message}")
    print(f"Public keys:           {[str(x) for x in ring.get_public_keys()]}")

    signatures, challenge, challenge_index = signer.generate_ring_signature(
        message, ring.get_public_keys()
    )
    print(f"Signatures:            {signatures}")
    print(f"Challenge index:       {challenge_index}")
    print(f"Challenge:             {challenge}")
    
    verifier = Verifier(g, order)
    result = verifier.verify_ring_signature(ring.get_public_keys(), message, signatures, challenge, challenge_index)
    print(f"Correct signature:     {result}")

    signatures[0] = (signatures[0] - 1) % order
    result = verifier.verify_ring_signature(ring.get_public_keys(), message, signatures, challenge, challenge_index)
    print(f"Incorrect signature:   {result}")
