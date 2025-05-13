

import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import os
import json


data_file = "data.json"
user_file = "user.json"


def load_json(file):
    if os.path.exists(file):
        with open(file , "r") as f:
            return json.load(f)
    return {}

def save_file(file , data):
    with open(file , "w") as f:
        json.dump(data , f , indent=4)
    



users = load_json(user_file)
store_data = load_json(data_file)

if not "username" in st.session_state:
    st.session_state.username = None

def hashed_password(key):
    return hashlib.sha256(key.encode()).hexdigest()

def derive_key(key):
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest())

def encrypted_with_passkey(message , key1):
    key = derive_key(key1)
    cipher = Fernet(key)
    return cipher.encrypt(message.encode()).decode()
def decrypt_message(message , key1):
    key = derive_key(key1)
    cipher = Fernet(key)
    return cipher.decrypt(message.encode()).decode()



st.title("Welcome TO Data Encryption System")
menu = ["Home","Login","Sinup","Store Data","Restore Data"]
choice = st.sidebar.selectbox("Navigation",menu)

if choice == "Home":
    st.subheader("Here you can store you private data with seckret key and retrive it when needed")
    

elif choice == "Login":
    st.subheader("login to your Account")
    username = st.text_input("Enter Username")
    password = st.text_input("Enter Password", type="password")
    if st.button("login"):
        if username and password:
            if username in users and users[username] == hashed_password(password):
                st.session_state.username = username
                st.success("login in successfully")
            else:
                st.error("Invalid username and password")
        else:
            st.error("Please fill Both Fileds")

elif choice == "Sinup":
    st.subheader("Create account for free and Enjoy encrypted world")
    username = st.text_input("Enter Username")
    password = st.text_input("Enter Password", type="password")
    if st.button("Sinup"):
        if not username and password:
            st.error("Please fill both first")
        elif username in users:
            st.error("User already exists")
        else:
            users[username] = hashed_password(password)
            save_file(user_file ,users)
            st.success(f"Successfully Create Account {username}")


elif choice == "Store Data":
    if not st.session_state.username:
        st.warning("please login first")
    else:
        st.subheader("Here You can store Secret encrypted message")
        message = st.text_input("Write your message here")
        pass_key = st.text_input("write pass key here", type="password")
        if st.button("Sava & Encrypt"):
            if message and pass_key:
                try:
                    encrypte = encrypted_with_passkey(message , pass_key)
                    user_data = store_data.get(st.session_state.username , [])
                    user_data.append(encrypte)
                    store_data[st.session_state.username] = user_data
                    save_file(data_file , store_data)
                    st.success("Data Sucessfully Encrypted")
                except Exception as e:
                    st.warning(f"Data can not be stored {e}")
            else:
                st.error("Both fields are Required")




    

elif choice == "Restore Data":
    if st.session_state.username:
        st.subheader("Restore You Secrete Message Here")
        passkey1 = st.text_input("Write your key here", type="password")
        if st.button("Encrypt Data"):
            if passkey1:
                user_current = store_data.get(st.session_state.username , [])
                if user_current:
                    for i , message in enumerate(user_current , 1):
                        try:
                            
                                decrypted = decrypt_message(message , passkey1)
                                
                                st.success(f"{i}: {decrypted}")
                                    

                                
                        except :
                            st.error("Decryption Failed")
                else:
                    st.error("NO Message stored yet")
            else:
                st.error("Please Enter pass key")
    else:
        st.error("Please login first")



