
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
# Update 2: Logging is added for debugging program.

import getpass
import ujson as json # type: ignore
import os
import bcrypt
from datetime import datetime
import logging

# AI Generated (line 40-44)
logging.basicConfig(
    filename='ex.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 'USER_FILE' is the same as 'users.json'
USER_FILE = "users.json"
MAX_ATTEMPTS = 5
attempts = 0

# Datetime for app execution.
c_date = datetime.now()
fc_date = c_date.strftime("%Y-%m-%d %H:%M")
exp = "Current datetime is:"

# Load existing users from file
def load_users():
    # If 'USER_FILE' exist, try to open it with read-only permissions.
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, 'r') as file:
                logging.info("User file loaded successfully.")
                return json.load(file)
        # If error occurred, return nothing (Basically exit program)
        except json.JSONDecodeError:
            print("Error reading user file, it may be corrupted or not available.")
            return {}
    logging.warning("User file not found, Starting with empty user list.")
    return {}

# Save users to file
def save_users(users_dict):
    with open(USER_FILE, 'w') as file:
        json.dump(users_dict, file)
    logging.info("User data saved.")
# Sign up function with PIN validation and hashing
def sign_up():
    print("\n=== SIGN UP ===")
    users = load_users()

    while True:
        username = input("Choose a username: ")

        if username in users:
            print("Username already exists. Please choose a different one.")
            logging.warning(f"Sign-up failed: Username '{username}' already exists.")
            continue
        
        password = getpass.getpass("Choose a PIN (numbers only, Pass is hidden): ", stream=None)

        if not password.isdigit():
            print("PIN must contain only digits. Please try again.")
            logging.warning("Sign-up failed: Non-digit pin detected.")
            continue

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users[username] = hashed_pw.decode()
        save_users(users)
        logging.info(f"New user '{username}' registered.")
        print("Account created successfully!")
        return True

# Login function with PIN validation and verification
def login():
    print("\n=== LOGIN ===")
    users = load_users()
    global attempts
    
    if not users:
        print("No users registered. Please sign up first.")
        return False
    
    username = input("Username: ")
     
    if username not in users:
        print("Username not found. Please try again.")
        logging.warning("Login attempt failed: No users registered")
        return False
    
    stored_hash = users[username].encode()
    
    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass("PIN (Pass is hidden): ")
        if not password.isdigit():
            print("PIN must contain only digits.")
            logging.warning("Login attempt failed: Non-digit PIN entered.")
            return False
        if bcrypt.checkpw(password.encode(), stored_hash):
            logging.info(f"User '{username}' logged in successfully.")
            if username == "admin":
                logging.info("Admin panel executed.")
                return admin_panel()
            return user_panel()
        elif attempts < 5:
            attempts += 1
            logging.warning(f"Incorrect PIN for user '{username}'. Attempts left: {MAX_ATTEMPTS - attempts}")
            print(f"Incorrect PIN. Attempts left: {MAX_ATTEMPTS - attempts}")
    return {}

    # If password and the stored hash matches, print Login successful
def user_panel():    
    print("Login successful!")
    print("\n1. Calculation")
    print("2. Log out")
    while True: 
        chess = input("Please select a number: ")
        if chess == "1":
            calc()
        elif chess == "2":
            print("Goodbye!")
            logging.info("User successfully logged out.")
            break
        else:
            print("\nWrong choice, Please try again.")
            logging.warning("Wrong Choice Entered, repeating choice process.")
            continue

def admin_panel():
    print("Welcome Admin.")
    logging.info("Admin panel accessed.")
    while True:
        print("\n1. Delete user file")
        print("2. Exit")
        choice = input("Choose an option: ")
        if choice == "1":
            if os.path.exists(USER_FILE):
                os.remove(USER_FILE)
                logging.info("User file deleted by admin.")
                print("'users.json' has been deleted.")
            else:
                logging.warning("Admin tried to delete user file, but it was not found.")
                print("User file not found.")
            break
        elif choice == "2":
            print("Goodbye!")
            logging.info("Admin Exited Panel")
            break
        else:
            print("Invalid choice.")
            logging.warning("Wrong choice in func 'admin_panel()'")
    return True
    
# Hidden admin setup function (PIN only)
def hidf():
    users = load_users()
    logging.warning("Admin Setup executed.")
    
    while True:
        password = getpass.getpass("Enter new admin PIN (Pass is hidden): ")

        if not password.isdigit():
            print("PIN must contain only digits.")
            logging.warning("Admin Setup failed (partially), Non-digit password entered.")
            continue

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        users["admin"] = hashed_pw.decode()
        save_users(users)
        print("Admin PIN set successfully.")
        logging.info("Admin account successfully created")
        break

def calc():
    while True:
        num1 = input("Enter a number: ")
        num2 = input("Enter a secondary number: ")
                    
        if num1.isdigit() and num2.isdigit():
            num1 = int(num1)
            num2 = int(num2)
        else:
            print("Only digits are allowed.")
            logging.warning("Calculations gone wrong, non-digit entered.")
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
    return {}
# Log testing
def crash():
    exec(type((lambda: 0).__code__)(0, 0, 0, 0, 0, 0, b'\x053', (), (), (), '', '', 0, b''))
# Main program
def main():
    logging.info("\nProgram started.")
    print(exp, fc_date)
    while True:
        print("\n1. Sign Up")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option (1-3): ")
        
        if choice == "1":
            sign_up()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Goodbye!")
            logging.info("Program exited successfully.")
            break
        elif choice == "9783":  # Hidden admin setup trigger
            logging.warning("Admin Setup triggered.")
            hidf()
        elif choice == "5":
            raise ValueError("Test crash")
        else:
            logging.warning("Incorrect choice made, repeating process.")
            print("Invalid choice. Please try again.")

# Run the program
if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.exception("Unexpected crash in main execution")
        print("An unexpected error occurred. Please check the log file for details.")
        raise
        
