import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

# Generate a symmetric key for AES encryption
def generate_symmetric_key():
    key = Fernet.generate_key()
    return key

# Encrypt plaintext using AES encryption with the symmetric key
def symmetric_encrypt(plaintext, key):
    cipher_suite = Fernet(key)
    ciphertext = cipher_suite.encrypt(plaintext.encode())
    return ciphertext

# Decrypt ciphertext using AES decryption with the symmetric key
def symmetric_decrypt(ciphertext, key):
    cipher_suite = Fernet(key)
    plaintext = cipher_suite.decrypt(ciphertext).decode()
    return plaintext

# Generate RSA key pair for asymmetric encryption
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt plaintext using RSA encryption with the recipient's public key
def asymmetric_encrypt(plaintext, public_key):
    cipher_text = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

# Decrypt ciphertext using RSA decryption with the recipient's private key
def asymmetric_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    return plaintext

def prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True
    
def modulus(base, exponent, mod):
    result = 1
    for _ in range(exponent):
        result = (result * base) % mod
    return result
    
def primitive_roots(p):       
    primitive_root = []
    for g in range(1, p):
        is_primitive = True
        primitive = set()
        for j in range(1,p):
            res = modulus(g,j,p)
            primitive.add(res)
            if res == 1:
                break
        if len(primitive) == p - 1:
            primitive_root.append(g)
    return primitive_root
    
def print_primitive(p, prim_num):
    if not prime(p):
        st.write(f"{p} is not a prime number!!")
        return
    
    print_result = []
    for g in range(1, p):
        output = []
        for j in range(1, p):
            res = modulus(g, j, p)
            output.append(f"{g}^{j} mod {p} = {res}")
            if res == 1:
                break
        if g in primitive_roots(p):
            output[-1] += f" ==> {g} is primitive root of {p},"
        else:
            output[-1] += ", "
        print_result.append(", ".join(output))
    
    st.write("\n".join(print_result))
    primitive_root = primitive_roots(p)
    if primitive_root:
        if prim_num in primitive_root:
            st.write(f"{prim_num} is primitive root: True {primitive_root}")
        else:
            st.write(f"{prim_num} is NOT primitive root of {p} - List of Primitive roots: {primitive_root}")
    else:
        st.write(f"{prim_num} is NOT primitive root of {p} - List of Primitive roots: {primitive_root}")

def main():
    st.title("Primitive Root Calculator with Encryption")
    st.write("This app calculates primitive roots of a prime number and includes encryption features.")

    p = st.number_input("Enter a prime number (p):", min_value=2, step=1)
    prim_num = st.number_input("Enter a number to check if it's a primitive root:", min_value=1, step=1)

    encryption_type = st.selectbox("Select encryption type:", ("Symmetric (AES)", "Asymmetric (RSA)"))

    if encryption_type == "Symmetric (AES)":
        key = generate_symmetric_key()
        st.write("Symmetric Key:", key.decode())
    elif encryption_type == "Asymmetric (RSA)":
        private_key, public_key = generate_rsa_keypair()
        st.write("Private Key:", private_key)
        st.write("Public Key:", public_key)

    if st.button("Calculate"):
        print_primitive(int(p), int(prim_num))

if __name__ == "__main__":
    main()
