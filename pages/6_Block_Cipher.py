import streamlit as st

st.header("Block Cipher")

def pad(data, block_size):    
    padding_length = block_size - len(data) % block_size  
    padding = bytes([padding_length] * padding_length)  
    return data + padding                  

def unpad(data):
    padding_length = data[-1]
    assert padding_length>0
    message, padding = data[:-padding_length], data[-padding_length:]
    assert all(p == padding_length for p in padding)
    return message    

def xor_encrypt_block(plaintext_block, key):
    encrypted_block = b''
    for i in range(len(plaintext_block)):
        encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
    return encrypted_block       

def xor_decrypt_block(ciphertext_block, key):
    return xor_encrypt_block(ciphertext_block, key)

def xor_encrypt(plaintext, key, block_size):
    encrypted_data = b''
    padded_plaintext = pad(plaintext, block_size)

    st.write("Encrypted blocks")
    for x, i in enumerate (range(0, len(padded_plaintext), block_size)):
        plaintext_block = padded_plaintext[i:i+block_size]
        encrypted_block = xor_encrypt_block(plaintext_block, key)
        encrypted_data += encrypted_block
        st.write(f"Plain  block[{x}]: {plaintext_block.hex()} : {plaintext_block}")
        st.write(f"Cipher block[{x}]: {encrypted_block.hex()} : {encrypted_block}")
    return encrypted_data        

def xor_decrypt(ciphertext, key, block_size):
    decrypted_data = b''

    st.write("Decrypted blocks")
    for x, i in enumerate (range(0, len(ciphertext), block_size)):
        ciphertext_block = ciphertext[i:i+block_size]
        decrypted_block = xor_decrypt_block(ciphertext_block, key)
        decrypted_data += decrypted_block
        st.write(f"block[{x}]: {decrypted_block.hex()} :{decrypted_block}")
    unpadded_decrypted_data = unpad(decrypted_data)
    return unpadded_decrypted_data               

def main():
    st.title("XOR Encryption and Decryption")

    plaintext = st.text_input("Enter plaintext:")
    key = st.text_input("Enter encryption key:")
    block_size = st.input("Enter block size:")

    if block_size not in [8, 16, 32, 64, 128]:
        print("Block size must be one of 8, 16,  32, 64, or  128 bytes")
    else:
        key = pad(key, block_size)
        encrypted_data = xor_encrypt(plaintext, key,block_size)
        decrypted_data = xor_decrypt(encrypted_data, key, block_size)

    if st.button("Submit"):
        key = pad(bytes(key.encode()), block_size)
        encrypted_data = xor_encrypt(bytes(plaintext.encode()), key, block_size)
        st.write("Encrypted data:", encrypted_data.hex())
        decrypted_data = xor_decrypt(bytes.fromhex(encrypted_data.hex()), key, block_size)
        st.write("Decrypted data:", decrypted_data.decode())

if __name__ == "__main__":
    main()