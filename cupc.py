
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
import ujson as json 
import os
import bcrypt
from datetime import datetime
import logging
import random
import time

# AI Generated (line 40-45)
logging.basicConfig(
    filename='ex.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(funcName)s - Line %(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 'USER_FILE' is the same as 'users.json'
USER_FILE = "users.json"
MAX_ATTEMPTS = 5
attempts = 0
users_cache = None
delay = 2 ** attempts

# Datetime for app execution.
fc_date = datetime.now().strftime("%Y-%m-%d %H:%M")
exp = "Current datetime is:"

def recreate_user():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w") as file:
            file.write("{}")

# Load existing users from file
def load_users():
    global users_cache

    if users_cache is not None:
        return users_cache

    if not os.path.exists(USER_FILE):
        logging.warning("User file not found, starting with empty user list.")
        with open(USER_FILE, "w") as file:
            file.write("{}")
        users_cache = {}
        return users_cache

    try:
        with open(USER_FILE, 'r') as file:
            users_cache = json.load(file)
            logging.info("User file loaded successfully.")
    except json.JSONDecodeError:
        logging.error("User file is corrupted. Starting with empty user list.")
        print("Warning, User data file was corrupted, All accounts have been removed.")
        users_cache = {}

    return users_cache

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
        logging.info(f"Sign-up attempt for username: {username}")
        
        if username in users:
            print("Username already exists. Please choose a different one.")
            logging.warning(f"Sign-up failed: Username '{username}' already exists.")
            continue
        
        if not username:
            print("Username cannot be empty or spaces, Please try again.")
            logging.warning("Login failed: Empty username entered.")
            continue  
        
        if len(username) < 4:
            print("Please choose a longer username.")
            logging.warning("Entered username has less the 4 characters.")
            continue
        
        password = getpass.getpass("Choose a PIN (numbers only, Pass is hidden): ", stream=None)

        if not password.isdigit():
            print("PIN must contain only digits. Please try again.")
            logging.warning("Sign-up failed: Non-digit pin detected.")
            continue
        
        if len(password) < 4:
            print("Password must contain 4 digits.")
            continue

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        users[username] = hashed_pw.decode()
        save_users(users)
        logging.info(f"New user '{username}' registered.")
        print("Account created successfully!")
        return True

# Login function with PIN validation and verification
def login():
    print("\n=== LOGIN ===")
    users = load_users()
    
    if not users:
        print("No users registered. Please sign up first.")
        return False
    
    username = input("Username: ").strip()

    if len(username) < 4:
        print("Usernames should be longer, are you brute-forcing?")
        time.sleep(4)
     
    if username not in users:
        print("Invalid Credentials. Please try again.")
        logging.warning("Login attempt failed: Username is not registered")
        return False
    
    if not username:
        print("Username cannot be empty or spaces, Please try again.")
        logging.warning("Login failed: Empty username entered.")
    
    
    dummy_hash = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12))
    stored_hash = users.get(username, dummy_hash).encode()
    
    attempts = 0
    
    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass("PIN (Pass is hidden): ")
        if not password.isdigit():
            print("PIN must contain only digits.")
            logging.warning("Login attempt failed: Non-digit PIN entered.")
            return False
        
        if len(password) < 4:
            print("Password must contain 4 digits.")
            continue
        
        if bcrypt.checkpw(password.encode(), stored_hash):
            logging.info(f"User '{username}' logged in successfully.")
            
            if username == "admin":
                logging.info("Admin panel executed.")
                return admin_panel()
            return user_panel(username)
        elif attempts < 5:
            attempts += 1
            logging.warning(f"Incorrect PIN for user '{username}'. Attempts left: {MAX_ATTEMPTS - attempts}")
            print(f"Incorrect PIN. Attempts left: {MAX_ATTEMPTS - attempts}")
            time.sleep(delay)
    return {}

# User Panel
def user_panel(username):    
    print("Login successful!")
    
    while True: 
        print("\n1. Calculation")
        print("2. Change PIN")
        print("3. Guess the Number")
        print("4. Log out")
        
        chess = input("Please select a number: ")
        
        if chess == "1":
            calc(username)
        elif chess == "2": 
            change_pin(username)
        elif chess == "3":
            guess_game(username)
        elif chess == "4":
            print("Goodbye!")
            logging.info("User successfully logged out.")
            break
        else:
            print("\nWrong choice, Please try again.")
            logging.warning("Wrong Choice Entered, repeating choice process.")
            continue

# Change PIN
def change_pin(username):
    users = load_users()
    logging.info(f"{username} requests a PIN change.")
    new_pin = getpass.getpass("Enter new PIN: ")
    if new_pin.isdigit():
        hashed_pw = bcrypt.hashpw(new_pin.encode(), bcrypt.gensalt(rounds=12))
        users[username] = hashed_pw.decode()
        save_users(users)
        print("PIN changed successfully.")
        logging.info(f"{username} Changed PIN successfully.")

# Admin Panel
def admin_panel():
    print("Welcome Admin.")
    logging.info("Admin panel accessed.")
    
    while True:
        print("\n1. Delete user file")
        print("2. List of users")
        print("3. Exit")
        choice = input("Choose an option: ")
        
        if choice == "1":
            if os.path.exists(USER_FILE):
                os.remove(USER_FILE)
                global users_cache
                with open(USER_FILE, 'w') as file:
                    file.write("{}")
                logging.info(f"Admin deleted user file at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("'users.json' has been deleted.")
            else:
                logging.warning("Admin tried to delete user file, but it was not found.")
                print("User file not found.")
            break
        elif choice == "3":
            print("Goodbye!")
            logging.info("Admin Exited Panel")
            break
        elif choice == "2":
            print("\nRegistered Users:")
            for user in load_users().keys():
                print("\n-", user)
        else:
            print("Invalid choice.")
            logging.warning("Wrong choice made, repeating process.")
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

        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        users["admin"] = hashed_pw.decode()
        save_users(users)
        print("Admin PIN set successfully.")
        logging.info("Admin account successfully created")
        break
# Calculator
def calc(username):
    print(f"Welcome {username}")
    logging.info(f"User {username} accessed calculator.")
    
    while True:
        num1 = input("Enter a number: ").strip()
        num2 = input("Enter a secondary number: ").strip()
                    
        try:
            num1 = int(num1)
            num2 = int(num2)
        except:
            print("Only digits are allowed.")
            logging.warning(f"Calculations gone wrong, non-digit entered by {username}.")
            continue
        
        numbers = [num1 , num2]
        
        # All types of math are combined.                    
        print("Multiplication =", numbers[0] * numbers[1])
        if numbers[1] == 0:
            logging.warning(f"One num have the value 0 by {username}, Canceling (Integer Division, Remainder)")
            print("Integer Division = Cannot divide by zero.")
            print("Remainder = Cannot divide by zero.")
        else:    
            print("Integer Division =", round(numbers[0] // numbers[1], 3))
            print("Remainder =", numbers[0] % numbers[1])
        print("Addition =", sum(numbers))
        print("Subtraction =", numbers[0] - numbers[1])    
        break    
    return {}

def guess_game(username):
    MAX_A = 5
    attempt = 0
    target = random.randint(1, 20)
    logging.info(f"{username} Playing game.")
    
    while True:    
        guess = input("Guess a number (1-20): ").strip()
        
        if not guess:
            print("Your guess could not be empty, Pick a number.")
            continue
        
        if guess.isdigit():
            guess = int(guess)
        else:
            print("You should guess a number.")
            continue
        
        if guess < 1 or guess > 20:
            print("You should pick a number between 1 and 10")
        
        if guess == target:
            print("You won!")
            logging.info(f"{username} Exited game successfully")
            break
        elif guess < target:
            attempt += 1
            print(f"Pick a higher number, Attempts remaining {MAX_A - attempt}")
        elif guess > target:
            attempt += 1
            print(f"You should pick a smaller number. Attempts remaining {MAX_A - attempt}")
        
        if attempt == 5:
            print(f"You lost {username}, The number was {target}")
            logging.info(f"{username} Exited game successfully")
            break
            
# Log testing
# def crash():
#     exec(type((lambda: 0).__code__)(0, 0, 0, 0, 0, 0, b'\x053', (), (), (), '', '', 0, b''))
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
        # Second phase testing.
        elif choice == "5":
            raise ValueError("Test crash")
        else:
            print("Invalid choice. Please try again.")
            logging.warning("Incorrect choice made, repeating process.")
            continue

# Run the program
if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.exception("Unexpected crash in main execution")
        print("An unexpected error occurred. Please check the log file for details.")
        raise
        
