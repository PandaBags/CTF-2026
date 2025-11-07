import sys
import binascii

# The Master Key (Passphrase) found in FUN_00401800
PASSPHRASE = "VANGUARD2147".encode('ascii')

# The Encrypted Flag Data from FUN_00401870
ENCRYPTED_DATA = [
    0x37, 0xea, 0x27, 0xe5, 0x27, 0x4f, 0x8c, 0xc0, 0x1b, 0xe8, 0x3a, 0x8d, 0xa9, 0x4e, 0x88, 0x58,
    0x94, 0x31, 0x0b, 0x30, 0xa6, 0xd2, 0xd0, 0xc1, 0xf5, 0x7c, 0x9e, 0x46, 0x0a, 0x47, 0x58, 0x30,
    0x73, 0xd6, 0xed, 0x42, 0x24, 0x09, 0x73, 0x65, 0x09, 0xb5, 0xa0, 0x52, 0x23, 0xef, 0xa9, 0xee,
    0x4a, 0xf2, 0x41
]

def fun_00401760_kdf(passphrase):
    """
    Replicates the custom 16-byte key derivation logic from FUN_00401760.
    The output is the true 16-byte key used for RC4.
    """
    key = bytearray(16)  # local_228 [16] initialized to 0

    # Part 1: Passphrase Iteration
    # Iterates up to length of passphrase (12)
    for i in range(len(passphrase)):
        
        # Index in the 16-byte key is (i & 0xf) -> (i % 16)
        key_idx = i % 16
        
        # key[key_idx] = key[key_idx] ^ passphrase[i] 
        key[key_idx] ^= passphrase[i]
        
        # This is the complex rotation/mixing part:
        # bVar2 = (bVar3 ^ bVar2) + *pcVar1 * '\a'; 
        # bVar2 is the byte value *after* the XOR (key[key_idx])
        # *pcVar1 is the byte value *before* the XOR (key[key_idx] ^ passphrase[i])
        
        bVar2 = key[key_idx]
        
        # Calculate the next state (Python only supports 8-bit operations implicitly 
        # when using % 256 for addition results, but we cast to int for clarity)
        next_byte_val = (bVar2 + PASSPHRASE[i] * 7) % 256
        
        # key[key_idx] = next_byte_val * 8 | next_byte_val >> 5; 
        # Note: (x * 8) is equivalent to (x << 3)
        # This is an unusual rotation: key[key_idx] = ROTL(val, 3) where val is 8-bit
        key[key_idx] = ((next_byte_val << 3) & 0xFF) | (next_byte_val >> 5)

    # Part 2: Final Rotation/Mixing (3 rounds)
    for round_num in range(3):
        # Inner loop iterates 16 times (0 to 15) but the logic is complex
        # It's an unrolled loop from the original C code
        # uVar6 starts at 7 (i = 0)
        # uVar7 = uVar6 + 1; 
        # uVar6 = uVar7; 
        # The rotation uses key_byte[uVar6 & 0xf]
        
        # The function seems to perform a simple cyclic shift (rotation) of 2 bits on each byte, 
        # XORed with another byte (i+7), repeated 16 times.
        
        for i in range(16):
            # Index of XOR source: (i + 7) & 0xf
            xor_source_idx = (i + 7) % 16
            
            # The operation is: key[i] = ROTL((key[xor_source_idx] ^ key[i]), 2)
            temp = key[xor_source_idx] ^ key[i]
            
            # Rotation of 2 bits left: (temp << 2) | (temp >> 6)
            key[i] = ((temp << 2) & 0xFF) | (temp >> 6)

    return bytes(key)

def rc4_decrypt(key, data):
    """Standard RC4 KSA and PRGA using the derived key"""
    S = list(range(256))
    j = 0
    
    # 1. Key-Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # 2. Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    decrypted = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        
        k = S[(S[i] + S[j]) % 256]
        decrypted_byte = byte ^ k
        decrypted.append(decrypted_byte)
        
    return decrypted

# --- Execution ---
try:
    # 1. Derive the actual RC4 key
    TRUE_KEY = fun_00401760_kdf(PASSPHRASE)
    
    # 2. Decrypt the data
    decrypted_bytes = rc4_decrypt(TRUE_KEY, ENCRYPTED_DATA)

    # 3. Print debug information
    print("\n--- DEBUG INFORMATION ---")
    print(f"Passphrase: {PASSPHRASE.decode('ascii')}")
    print("Derived 16-Byte Key:", TRUE_KEY.hex())
    print("Raw Hex Decryption:", binascii.hexlify(decrypted_bytes).decode('ascii'))
    print("-------------------------\n")

    # 4. Decode the final flag
    decrypted_flag = decrypted_bytes.decode('ascii', errors='ignore')
    decrypted_flag = decrypted_flag.strip('\x00\r\n')

    print("[CIPHER CORE DECRYPTED]")
    print(f"Flag: {decrypted_flag}")
    
except Exception as e:
    print(f"An error occurred: {e}")
