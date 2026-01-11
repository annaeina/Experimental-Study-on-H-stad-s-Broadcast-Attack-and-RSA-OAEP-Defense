import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Import broadcast attack function from broadcast.py
try:
    from broadcast import broadcast_attack
except ImportError:
    print("Eoor：cannot find broadcast.py")
    exit()

def oaep_defense_simulation():
    print("-" * 60)
    print("  PART 2: OAEP Defense Simulation (Counter-Experiment)")
    print("-" * 60)
    message = b"Secret Message: Only OAEP Padding can prevent this!"
    print(f"[*] Original Message: \"{message.decode()}\"")

    print("\n[*] Generating 3 pairs of 2048-bit RSA keys (forcing e=3)...")
    keys = []
    N_list = []
    for i in range(3):
        key = RSA.generate(2048, e=3)
        keys.append(key)
        N_list.append(key.n)
    print("    Done. Keys generated.")
    print("\n[*] Encrypting message using PKCS#1 v2.0 OAEP Standard...")
    C_list = []
    
    for i, key in enumerate(keys):
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(message)
        c_int = bytes_to_long(ciphertext)
        C_list.append(c_int)
        prefix = binascii.hexlify(ciphertext[:8]).decode()
        print(f"    Ciphertext {i+1} (Hex prefix): {prefix}... (Randomized)")
    print("\n[*] Attacker attempting Hastad's Broadcast Attack...")
    print("    (Applying CRT and Cubic Root on OAEP ciphertexts...)")
    
    try:        
        m_recovered_int = broadcast_attack(N_list, C_list)
        m_recovered_bytes = long_to_bytes(m_recovered_int)       
        print(f"    [ATTACK FINISHED] Result calculated.")
        
        # Verify attack failed (recovered content should be garbage)
        if m_recovered_bytes == message:
            print("    [FATAL] Attack Succeeded! (This is impossible if OAEP works)")
        else:
            print(f"    [DEFENSE SUCCESS] The recovered content is GARBAGE.")
            hex_preview = binascii.hexlify(m_recovered_bytes[-20:]).decode() if len(m_recovered_bytes) > 20 else binascii.hexlify(m_recovered_bytes).decode()
            print(f"    Raw Hex (suffix): ...{hex_preview}")
            print("\n    Analysis:")
            print("    The attack failed because OAEP introduces RANDOMNESS (Salt).")
            print("    Even with e=3, the ciphertexts no longer share the same structure.")
            print("    This confirms that OAEP is IND-CPA secure.")

    except Exception as e:
        print(f"    [DEFENSE SUCCESS] Attack logic crashed: {e}")

    print("-" * 60)

if __name__ == "__main__":
    oaep_defense_simulation()