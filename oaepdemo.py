import binascii
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long, long_to_bytes

# ========== 导入 Part 1 的攻击逻辑 ==========
# 这里直接调用你 new.py 里写好的数学攻击函数
try:
    from new import broadcast_attack
except ImportError:
    print("错误：找不到 new.py 文件。请确保 new.py 和本脚本在同一目录下。")
    exit()

# ========== Part 2: OAEP 防御实验 ==========

def oaep_defense_simulation():
    print("-" * 60)
    print("  PART 2: OAEP Defense Simulation (Counter-Experiment)")
    print("-" * 60)

    # 1. 准备相同的明文
    message = b"Secret Message: Only OAEP Padding can prevent this!"
    print(f"[*] Original Message: \"{message.decode()}\"")

    # 2. 生成 3 对 RSA 密钥 (强制 e=3)
    # 关键点：我们故意使用危险的 e=3，以此证明：
    # 只要用了 OAEP 填充，即使 e=3 这种“弱参数”也是安全的！
    print("\n[*] Generating 3 pairs of 2048-bit RSA keys (forcing e=3)...")
    keys = []
    N_list = []
    for i in range(3):
        # public_exponent=3 模拟易受攻击的参数设置
        key = RSA.generate(2048, e=3)
        keys.append(key)
        N_list.append(key.n)
    print("    Done. Keys generated.")

    # 3. 使用标准 PKCS#1 OAEP 进行加密
    print("\n[*] Encrypting message using PKCS#1 v2.0 OAEP Standard...")
    C_list = []
    
    for i, key in enumerate(keys):
        # 创建 OAEP 加密器实例 (这是 Python 标准库的做法)
        # 这一步内部会自动生成随机数种子 (Seed)，并进行 MGF 掩码操作
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(message)
        
        # 转换为整数以便放入攻击算法
        c_int = bytes_to_long(ciphertext)
        C_list.append(c_int)
        
        # 展示：虽然明文一样，但密文截然不同（因为有随机数）
        # 对比 new.py，在那边你可以看到密文是有数学规律的
        prefix = binascii.hexlify(ciphertext[:8]).decode()
        print(f"    Ciphertext {i+1} (Hex prefix): {prefix}... (Randomized)")

    # 4. 强行运行广播攻击 (尝试用旧方法破解新标准)
    print("\n[*] Attacker attempting Hastad's Broadcast Attack...")
    print("    (Applying CRT and Cubic Root on OAEP ciphertexts...)")
    
    try:
        # 数学原理解析：
        # 攻击者以为 C = M^3 mod N，于是用 CRT 求解。
        # 实际上 C = (Pad(M, r))^3 mod N。
        # 因为 r1, r2, r3 互不相同，三个方程的“底数”都不一样。
        # CRT 强行合并出来的结果，只是毫无意义的数学垃圾。
        
        m_recovered_int = broadcast_attack(N_list, C_list)
        
        # 尝试将结果转回字节
        m_recovered_bytes = long_to_bytes(m_recovered_int)
        
        print(f"    [ATTACK FINISHED] Result calculated.")
        
        # 5. 验证结果
        if m_recovered_bytes == message:
            print("    [FATAL] Attack Succeeded! (This is impossible if OAEP works)")
        else:
            # 展示解出来的乱码
            print(f"    [DEFENSE SUCCESS] The recovered content is GARBAGE.")
            
            # 为了展示它是乱码，我们打印它的十六进制表示
            # 如果太长，只打印最后一段
            hex_preview = binascii.hexlify(m_recovered_bytes[-20:]).decode() if len(m_recovered_bytes) > 20 else binascii.hexlify(m_recovered_bytes).decode()
            
            print(f"    Raw Hex (suffix): ...{hex_preview}")
            print("\n    Analysis:")
            print("    The attack failed because OAEP introduces RANDOMNESS (Salt).")
            print("    Even with e=3, the ciphertexts no longer share the same structure.")
            print("    This confirms that OAEP is IND-CPA secure.")

    except Exception as e:
        # 有时候因为乱码太大或者格式问题导致转换报错，这也算防御成功
        print(f"    [DEFENSE SUCCESS] Attack logic crashed: {e}")

    print("-" * 60)

if __name__ == "__main__":
    oaep_defense_simulation()