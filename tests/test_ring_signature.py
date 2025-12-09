import pytest
import sys
import os

# Add the parent directory to sys.path to import main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import ZpStar, RingSetup, Signer, Verifier

# RFC 5114 Parameters (1024-bit MODP Group with 160-bit Prime Order Subgroup)
RFC5114_P = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
                "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
                "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
                "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)

RFC5114_G = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
                "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
                "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
                "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

RFC5114_Q = int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16)

@pytest.fixture(params=["small", "large"], ids=["small_params", "large_params"])
def ring_setup(request):
    if request.param == "small":
        p, generator_val, order = 643, 4, 107
        h_val = 16 # 4^2 = 16
    else:
        p, generator_val, order = RFC5114_P, RFC5114_G, RFC5114_Q
        # h must be in the subgroup of order q. Since g generates the subgroup,
        # g^k for any k will be in the subgroup. k=2 is simple and safe.
        h_val = pow(RFC5114_G, 2, RFC5114_P)

    group = ZpStar(p)
    g = group.get_element(generator_val)
    h = group.get_element(h_val)
    
    # Create ring with 5 participants
    ring = RingSetup(g, h, order, 5, group)
    verifier = Verifier(g, h, order)
    
    return {
        "ring": ring,
        "verifier": verifier,
        "group": group,
        "g": g,
        "h": h,
        "order": order
    }

def test_valid_signature(ring_setup):
    ring = ring_setup["ring"]
    verifier = ring_setup["verifier"]
    
    signer = ring.get_random_participant()
    message = "Test Message"
    public_keys = ring.get_public_keys()
    
    key_image, c1, signatures = signer.generate_ring_signature(message, public_keys)
    
    result = verifier.verify_ring_signature(public_keys, message, key_image, c1, signatures)
    assert result is True

def test_same_signer_linkability(ring_setup):
    ring = ring_setup["ring"]
    
    signer = ring.get_random_participant()
    public_keys = ring.get_public_keys()
    
    message1 = "Message 1"
    message2 = "Message 2"
    
    key_image1, _, _ = signer.generate_ring_signature(message1, public_keys)
    key_image2, _, _ = signer.generate_ring_signature(message2, public_keys)
    
    # Key images must be identical for the same signer
    assert key_image1 == key_image2

def test_different_signers_linkability(ring_setup):
    ring = ring_setup["ring"]
    public_keys = ring.get_public_keys()
    
    signer1 = ring.participants[0]
    signer2 = ring.participants[1]
    
    message = "Same Message"
    
    key_image1, _, _ = signer1.generate_ring_signature(message, public_keys)
    key_image2, _, _ = signer2.generate_ring_signature(message, public_keys)
    
    # Key images must be different for different signers
    assert key_image1 != key_image2

def test_tampered_signature(ring_setup):
    ring = ring_setup["ring"]
    verifier = ring_setup["verifier"]
    order = ring_setup["order"]
    
    signer = ring.get_random_participant()
    message = "Test Message"
    public_keys = ring.get_public_keys()
    
    key_image, c1, signatures = signer.generate_ring_signature(message, public_keys)
    
    # Tamper with the first signature component
    tampered_signatures = signatures.copy()
    tampered_signatures[0] = (tampered_signatures[0] + 1) % order
    
    result = verifier.verify_ring_signature(public_keys, message, key_image, c1, tampered_signatures)
    assert result is False

def test_tampered_message(ring_setup):
    ring = ring_setup["ring"]
    verifier = ring_setup["verifier"]
    
    signer = ring.get_random_participant()
    message = "Original Message"
    public_keys = ring.get_public_keys()
    
    key_image, c1, signatures = signer.generate_ring_signature(message, public_keys)
    
    # Verify with a different message
    tampered_message = "Tampered Message"
    
    result = verifier.verify_ring_signature(public_keys, tampered_message, key_image, c1, signatures)
    assert result is False
