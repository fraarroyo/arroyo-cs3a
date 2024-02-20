import streamlit as st

st.header("XOR Cipher")
def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        ciphertext.append(plaintext[i] ^ key [i % len (key)])
        st.write(f"Plaintext byte: {plaintext[i]:08b} = {chr (plaintext[i])}")
        st.write(f"Key byte:       {key[i % len(key)]:08b} = {chr(key[i % len(key)])}")
        st.write(f"XOR result:     {ciphertext[-1]:08b} = {chr(ciphertext[-1])}")
        st.write("--------------------")
    return ciphertext
    
    

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)

plaintext = bytes(st.text_area("Plain Text:").encode())
key = bytes(st.text_input("Key:").encode())

if st.button("Submit"):
    if not (1 < len(plaintext) >= len(key) >= 1):
        st.write("Plaintext length should be equal or greater than the length of key")
    elif not plaintext != key:
        st.write("Plaintext should not be equal to the key")
    else:
        ciphertext = xor_encrypt(plaintext, key)
        st.write("Ciphertext:", ciphertext.decode())
        
        decrypted = xor_decrypt(ciphertext, key)
        st.write("Decrypted:",decrypted.decode())