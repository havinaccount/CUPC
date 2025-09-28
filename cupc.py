
#           _____                    _____                    _____                    _____          
#          /\*   \                  /\*   \                  /\*   \                  /\    \
#         /::\    \                /::\____\                /::\    \                /::\    \
#        /::::\    \              /:::/    /               /::::\    \              /::::\    \       
#       /::::::\    \            /:::/    /               /::::::\    \            /::::::\    \      
#      /:::/\:::\    \          /:::/    /               /:::/\:::\    \          /:::/\:::\    \     
#     /:::/  \:::\    \        /:::/    /               /:::/__\:::\    \        /:::/  \:::\    \    
#    /:::/    \:::\    \      /:::/    /               /::::\   \:::\    \      /:::/    \:::\    \   
#   /:::/    / \:::\    \    /:::/    /      _____    /::::::\   \:::\    \    /:::/    / \:::\    \  
#  /:::/    /   \:::\    \  /:::/____/      /\    \  /:::/\:::\   \:::\____\  /:::/    /   \:::\    \ 
# /:::/____/     \:::\____\|:::|    /      /::\____\/:::/  \:::\   \:::|    |/:::/____/     \:::\____\
# \:::\    \      \::/    /|:::|____\     /:::/    /\::/    \:::\  /:::|____|\:::\    \      \::/    /
#  \:::\    \      \/____/  \:::\    \   /:::/    /  \/_____/\:::\/:::/    /  \:::\    \      \/____/ 
#   \:::\    \               \:::\    \ /:::/    /            \::::::/    /    \:::\    \             
#    \:::\    \               \:::\    /:::/    /              \::::/    /      \:::\    \            
#     \:::\    \               \:::\__/:::/    /                \::/    /        \:::\    \
#      \:::\    \               \::::::::/    /                  \/____/          \:::\    \
#       \:::\    \               \::::::/    /                                     \:::\    \
#        \:::\____\               \::::/    /                                       \:::\____\
#         \::/    /                \::/    /                                         \::/    /
#          \/____/                  \/____/                                           \/____/

# a simple password checking python code.
 
# CUPC stands for 'Constant Username and Password Checking'

# CUPC is a simple password checker written in python. this is just an example and nothing else.
# Note: this code is not protected from brute force, be warned.
# Update 1: Password now can be hashed easily.

import getpass
import json
import os
import bcrypt
from datetime import datetime

# 'USER_FILE' is the same as 'users.json'
USER_FILE = "users.json"

# Datetime for app execution.
c_date = datetime.now()
exp = "Current datetime is:"

# Load existing users from file
def load_users():
    # If 'USER_FILE' exist, try to open it with read-only permissions.
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, 'r') as file:
                return json.load(file)
        # If error occurred, return nothing (Basically exit program)
        except json.JSONDecodeError:
            return {}
    return {}

# Save users to file
def save_users(users_dict):
    with open(USER_FILE, 'w') as file:
        json.dump(users_dict, file)

# Sign up function with PIN validation and hashing
def sign_up():
    print("\n=== SIGN UP ===")
    users = load_users()

    while True:
        username = input("Choose a username: ")

        if username in users:
            print("Username already exists. Please choose a different one.")
            continue
        
        password = getpass.getpass("Choose a PIN (numbers only, Pass is hidden): ", stream=None)

        if not password.isdigit():
            print("PIN must contain only digits. Please try again.")
            continue

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users[username] = hashed_pw.decode()
        save_users(users)
        print("Account created successfully!")
        return True

# Login function with PIN validation and verification
def login():
    print("\n=== LOGIN ===")
    users = load_users()

    if not users:
        print("No users registered. Please sign up first.")
        return False

    username = input("Username: ")
    password = getpass.getpass("PIN (Pass is hidden): ")

    if not password.isdigit():
        print("PIN must contain only digits.")
        return False

    if username not in users:
        print("Username not found. Please try again.")
        return False

    stored_hash = users[username].encode()

    if username == "admin":
        if bcrypt.checkpw(password.encode(), stored_hash):
            print("Welcome Admin.")
            while True:
                print("\n1. Delete user file")
                print("2. Exit")
                choice = input("Choose a number (1-2): ")
                if choice == "1":
                    if os.path.exists(USER_FILE):
                        os.remove(USER_FILE)
                        print("'users.json' has been deleted.")
                    else:
                        print("User file not found.")
                    break
                elif choice == "2":
                    print("Goodbye!")
                    break
                else:
                    print("Invalid choice. Try again.")
        else:
            print("Incorrect Admin PIN.")
        return True
    
    # If password and the stored hash matches, print Login successful
    if bcrypt.checkpw(password.encode(), stored_hash):
        print("Login successful!")
        print("\n1. Calculation")
        print("2. Log out")
        while True: 
            chess = input("Please select a number: ")
            if chess == "1":
                while True:
                    num1 = input("Enter a number: ")
                    num2 = input("Enter a secondary number: ")
                    
                    if num1.isdigit() and num2.isdigit():
                        num1 = int(num1)
                        num2 = int(num2)
                    else:
                        print("Only digits are allowed.")
                        continue
                            
                    print("Multiplication =", num1 * num2)
                    if num2 == 0 or num1 == 0:
                        print("Division = Cannot divide by zero.")
                        print("Integer Division = Cannot divide by zero.")
                        print("Remainder = Cannot divide by zero.")
                    else:    
                        print("Division =", round(num1 / num2, 3))
                        print("Integer Division =", num1 // num2)
                        print("Remainder =", num1 % num2)
                    print("Addition =", num1 + num2)
                    print("Subtraction =", num1 - num2)    
                    break    
            elif chess == "2":
                print("Goodbye!")
                break
            else:
                print("Wrong choice, Please try again.")
                continue
            break
        
# Hidden admin setup function (PIN only)
def hidf():
    users = load_users()

    while True:
        password = getpass.getpass("Enter new admin PIN (Pass is hidden): ")

        if not password.isdigit():
            print("PIN must contain only digits.")
            continue

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users["admin"] = hashed_pw.decode()
        save_users(users)
        print("Admin PIN set successfully.")
        break

# Main program
def main():
    print(exp, c_date)
    while True:
        print("\n1. Sign Up")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option (1-3): ")
        
        if choice == "1":
            sign_up()
        elif choice == "2":
            if login():
                print("Welcome! You are now logged in.")
                break
        elif choice == "3":
            print("Goodbye!")
            break
        elif choice == "9783":  # Hidden admin setup trigger
            hidf()
        else:
            print("Invalid choice. Please try again.")

# Run the program
if __name__ == "__main__":
    main()
