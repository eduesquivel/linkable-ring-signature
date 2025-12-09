import pytest
import sys
import os

# Add the parent directory to sys.path to import main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import ZpStar, RingSetup, Signer, Verifier

@pytest.fixture
def ring_setup():
    p, generator_val, order = 643, 4, 107
    h_val = 16 # 4^2 = 16
    
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
