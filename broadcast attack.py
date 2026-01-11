import time
from math import gcd
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long

# Mathematical Primitives
def integer_cube_root(n):
    """
    Computes the integer cube root of n using binary search.
    This avoids floating-point precision issues inherent in pow(n, 1/3).
    """
    low = 0
    high = n
    while low < high:
        mid = (low + high) // 2
        if mid**3 < n:
            low = mid + 1
        else:
            high = mid
    return low

# Broadcast Attack
def broadcast_attack(N_list, C_list):
    """
    Recovers the message m from 3 ciphertexts using CRT.
    Precondition: m^3 < N1 * N2 * N3
    """
    if gcd(N_list[0], N_list[1]) != 1 or \
       gcd(N_list[0], N_list[2]) != 1 or \
       gcd(N_list[1], N_list[2]) != 1:
        raise ValueError("Moduli are not pairwise coprime!")
    N1, N2, N3 = N_list
    C1, C2, C3 = C_list
    N_total = N1 * N2 * N3
    M1 = N2 * N3
    w1 = (C1 * M1 * pow(M1, -1, N1)) 
    M2 = N1 * N3
    w2 = (C2 * M2 * pow(M2, -1, N2))
    M3 = N1 * N2
    w3 = (C3 * M3 * pow(M3, -1, N3))

    C_combined = (w1 + w2 + w3) % N_total
    
    return integer_cube_root(C_combined)

# Simulation Experiment
def run_simulation():
    print("-" * 50)
    print("  RSA Broadcast Attack Simulation")
    print("-" * 50)
    print("[*] Generating 3 pairs of 1024-bit RSA keys (e=3)...")
    e = 3
    N_list = []
    for _ in range(3):
        p = getPrime(512)
        q = getPrime(512)
        N_list.append(p * q)
    print("    Done. Moduli generated.")
    message_str = "Secret Message: Only OAEP Padding can prevent this!"
    m = bytes_to_long(message_str.encode('utf-8'))  
    print(f"\n[*] Original Message: \"{message_str}\"")
    if m**3 >= N_list[0] * N_list[1] * N_list[2]:
        print("Error: Message is too long for this specific attack.")
        return
    print("[*] Encrypting for 3 different recipients...")
    C_list = [pow(m, e, n) for n in N_list]
    print("    Ciphertexts captured.")
    print("\n[*] Launching Attack (CRT + Cubic Root)...")
    start_time = time.time()
    
    try:
        m_recovered_int = broadcast_attack(N_list, C_list)
        end_time = time.time()
        m_recovered_str = long_to_bytes(m_recovered_int).decode('utf-8')      
        print(f"    [SUCCESS] Recovered in {end_time - start_time:.6f} seconds!")
        print(f"    Recovered: \"{m_recovered_str}\"")
        assert message_str == m_recovered_str
        print("    Verification: Exact match.")
        
    except Exception as err:
        print(f"    [FAILED] {err}")
    print("-" * 50)

if __name__ == "__main__":
    run_simulation()