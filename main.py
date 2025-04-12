import streamlit as st 
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)



stored_data = {}
failed_attempts = 0


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def  encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).hexdigest()





