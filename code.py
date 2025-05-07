import os

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    if username == "admin" and password == "admin123":
        print("Login successful!")
        command = input("Enter command to run: ")
        os.system(command)
    else:
        print("Login failed!")

login()
