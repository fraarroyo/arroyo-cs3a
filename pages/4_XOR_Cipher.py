def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ key [i % len (key)])
        print(f"Plaintext byte: {plaintext[i]:08b} = {chr (plaintext[i])}")
        print(f"Key byte:       {key[i % len(key)]:08b} = {chr(key[i % len(key)])}")
        print(f"XOR result:     {ciphertext[-1]:08b} = {chr(ciphertext[-1])}")
        print("--------------------")
    return ciphertext
    
    

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)


# Example usage:
plaintext = bytes(input().encode())
key = bytes(input().encode())



if not (1 < len(plaintext) >= len(key) >= 1):
    print("Plaintext length should be equal or greater than the length of key")
elif not plaintext != key:
    print("Plaintext should not be equal to the key")
else:
    ciphertext = xor_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext.decode())
    
    decrypted = xor_decrypt(ciphertext, key)
    print("Decrypted:",decrypted.decode())
    