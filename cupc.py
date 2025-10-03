
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
# Update 3: Added time for avoiding brute-force attacks

import getpass # Using getpass to hide input
import orjson # Using orjson for faster read and write (ujson deprecated)
import os # Using os for user file deletion and dumping
import bcrypt # Using bcrypt for hashing passwords
from datetime import datetime # Using datetime for the main program
import logging # Using logging to capture every event
import random # Using random for the guess game
import time # Using time for preventing brute-force attacks
import threading # Using threading for more optimized thread usage
import shutil # Using shutil for creating file backups

# Following explanations may change depending on bugfixes and new features

# AI Generated (line 40-45)
logging.basicConfig(
    filename='ex.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(funcName)s - Line %(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 'USER_FILE' is the same as 'users.json'
USER_FILE = os.path.join(os.path.dirname(__file__), "users.json")
MAX_ATTEMPTS = 5
attempts = 0
users_cache = None
delay = 2 ** attempts
user_file_lock = threading.Lock()

# Datetime for app execution.
fc_date = datetime.now().strftime("%Y-%m-%d %H:%M")
exp = "Current datetime is:"

print(f"Using USER_FILE at : {USER_FILE}")
print("Exists:", os.path.exists(USER_FILE))

def recreate_user():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "wb") as file:
            file.write(orjson.dumps({}))

# Load existing users from file
def load_users():
    global users_cache # Make the user cache globally available

    if users_cache is not None:
        return users_cache # Make user_cache none if it has any variable in it

    if not os.path.exists(USER_FILE):
        logging.warning("User file not found, starting with empty user list.")
        with open(USER_FILE, "wb") as file:
            file.write(orjson.dumps({})) # Reset the USER_FILE
        users_cache = {} # Give user_cache a storage
        return users_cache # Flush users_cache

    try:
        with user_file_lock: # With the following thread lock, open user_file
            with open(USER_FILE, 'rb') as file:
                users_cache = orjson.loads(file.read())
                logging.info("User file loaded successfully.")
    except orjson.JSONDecodeError: # Catch the USER_FILE Corruption
        logging.error("User file is corrupted. Starting with empty user list.")
        print("Warning, User data file was corrupted, All accounts have been removed.")
        try:
            os.rename(USER_FILE, USER_FILE + ".corrupted") # Take a backup of the corrupted user_file
            logging.info(f"Corrupted user file backed up as '{USER_FILE}.corrupted'")
        except Exception as e: # Catch the following exception
            logging.error(f"Failed to backup corrupted user file: {e}")
        users_cache = {}
    except Exception as e: # Catch another exception
        logging.error(f"Failed to load user file {e}")
        print("System error, Starting with empty user list.")
        users_cache = {}
    
    return users_cache # Flush the user_cache

# Save users to file
def save_users(users_dict):
    try:
        if os.path.exists(USER_FILE):
            shutil.copy(USER_FILE, USER_FILE + '.bak') # Create a backup of the USER_FILE
    except FileNotFoundError:
        print()
        
    with user_file_lock: # With the thread lock inbound
        try:
            with open(USER_FILE, 'wb') as file:
                file.write(orjson.dumps(users_dict, file)) # Dump the sign-up info
            logging.info("User data saved.")
        except Exception as e: # Catch the exception
            print("Error saving user data. Please try again.")
            logging.error(f"Failed to save user data: {e}")
# Sign up function with PIN validation and hashing
def sign_up():
    print("\n=== SIGN UP ===")
    try:
        users = load_users()
    except (orjson.JSONDecodeError, FileNotFoundError):
        print("User file not found.")
        return False
    while True:
        username = input("Choose a username: ").strip()
        logging.info(f"Sign-up attempt for username: {username}")
        
        if username in users:
            print("Username already exists. Please choose a different one.")
            logging.warning(f"Sign-up failed: Username '{username}' already exists.")
            continue
        
        if not username:
            print("Username cannot be empty or spaces, Please try again.")
            logging.warning("Sign-up failed: Empty username entered.")
            continue  
        
        if len(username) < 4: # Username length verification
            print("Please choose a longer username.")
            logging.warning("Entered username has less the 4 characters.")
            continue
        
        if username.lower() == 'admin': # Prevent any user to sign-up as admin without admin setup
            print("Username admin is reserved")
            logging.warning("A User tried to sign-up as admin.")
            continue
        
        password = getpass.getpass("Choose a PIN (numbers only, Pass is hidden): ", stream=None)

        if not password.isdigit(): # Numeric Verification
            print("PIN must contain only digits. Please try again.")
            logging.warning("Sign-up failed: Non-digit pin detected.")
            continue
        
        if len(password) < 4: # Password length verification
            print("Password must contain 4 digits.")
            continue
        
        confirm = getpass.getpass('Confirm your PIN: ').strip() # Give a confirmation check
        
        if confirm != password:
            print("PINs do not match, Please try again.")
            continue
        
        t = threading.Thread(target=hash_verify, args=(username, password))
        t.start()
        t.join()
        logging.info(f"New user '{username}' registered.")
        break
    
# Hashing sequence.    
def hash_verify(username, password):
    users = load_users() # Load the USER_FILE
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)) # Declare the hash_pw variable
    users[username] = hashed_pw.decode() # Assign the password to the user
    save_users(users) # Dump all the info
    print("Account created successfully!")
    return {}

def hash_new_pin(username, new_pin):
    users = load_users()
    hashed_pw = bcrypt.hashpw(new_pin.encode(), bcrypt.gensalt(rounds=12))
    users[username] = hashed_pw.decode()
    save_users(users)
    print("PIN changed successfully.")
    logging.info(f"{username} Changed PIN successfully.")

# Login function with PIN validation and verification
def login():
    print("\n=== LOGIN ===")
    users = load_users()
    
    if not users:
        print("No users registered. Please sign up first.")
        return False
    
    username = input("Username: ").strip()

    if len(username) < 4: # Username length verification.
        print("Usernames should be longer, are you brute-forcing?")
        time.sleep(4)
     
    if username not in users: # Checking for username existence.
        print("Invalid Credentials. Please try again.")
        logging.warning("Login attempt failed: Username is not registered")
        return False
    
    if not username: # Checking for empty username inputs
        print("Username cannot be empty or spaces, Please try again.")
        logging.warning("Login failed: Empty username entered.")
        return False
    
    dummy_hash = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=4)) # Making an easy dummy hash for securing brute-force attacks
    stored_hash = users.get(username, dummy_hash).encode()
    
    attempts = 0
    
    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass("PIN (Pass is hidden): ") # Getting password
        
        if not password.isdigit(): # Making Password only look for digits. 
            print("PIN must contain only digits.")
            logging.warning("Login attempt failed: Non-digit PIN entered.")
            return False
        
        if len(password) < 4: # Verifying password length.
            print("Password must contain 4 digits.")
            continue
        
        if bcrypt.checkpw(password.encode(), stored_hash): # If the encoded password that we received matches our stored hash, log in.
            logging.info(f"User '{username}' logged in successfully.")
            
            if username == "admin": # if the username is admin and password matches, launch admin panel, otherwise, launch user panel
                logging.info("Admin panel executed.")
                return admin_panel()
            return user_panel(username)
    return {}

# User Panel
def user_panel(username):    
    print("Login successful!")
    
    while True: 
        print("\n1. Calculation")
        print("2. Change PIN")
        print("3. Guess the Number")
        print("4. Log out")
        
        choice = input("Please select a number: ").strip() # Get a number from user.
        
        # Depending on the choice, launch the following functions
        if choice == "1":
            calc(username)
        elif choice == "2":
            change_pin(username)
        elif choice == "3":
            guess_game(username)
        elif choice == "4":
            print("Goodbye!")
            logging.info("User successfully logged out.")
            break
        # If wrong choice is given, ask again.
        else:
            print("\nWrong choice, Please try again.")
            logging.warning("Wrong Choice Entered, repeating choice process.")
            continue

# Change PIN
def change_pin(username):
    try: # Using an try/except block to prevent errors
        users = load_users()
    except (orjson.JSONDecodeError, FileNotFoundError):
        print("User file not found")
        return
    
    logging.info(f"{username} requests a PIN change.")
    
    while True:
        new_pin = getpass.getpass("Enter new PIN: ").strip() # Ask the user for the following new PIN
        
        if len(new_pin) < 4: # PIN length verification
            print("PIN must be 4 digits or higher.")
            continue
        
        confirm = getpass.getpass("Confirm your following PIN: ").strip() # Password Confirmation.
        if confirm != new_pin:
            print("PINs do not match, Please try again.")
            continue
        
        if username not in users: # If username got corrupt in changing PIN section, Stop the process.
            print("User not found.")
            logging.warning(f"PIN change failed: {username} not found")
        
        if new_pin.isdigit(): # If all the requirements are fulfilled, change the pin using hashing mechanic
            b = threading.Thread(target=hash_new_pin, args=(username, new_pin))
            b.start()
            b.join()
            break
        else:
            print("Password must contain only digits.")
        return
    
# Admin Panel
def admin_panel(username="admin"):
    print("Welcome Admin.")
    logging.info("Admin panel accessed.")
    
    while True:
        print("\n1. Reset user file")
        print("2. List of users")
        print('3. User Panel')
        print("4. Exit")
        choice = input("Choose an option: ").strip()
        
        # Depending on the choice, Execute the following functions.
        if choice == "1":
            if os.path.exists(USER_FILE): # User file deletion mechanic
                os.remove(USER_FILE)
                with open(USER_FILE, 'w') as file:
                    file.write(orjson.dumps({}))
                logging.info(f"Admin reset user file at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("'users.json' has been reset.")
                continue
            else:
                logging.warning("Admin tried to reset user file, but it was not found.")
                print("User file not found.")
                continue
        elif choice == "4":
            print("Goodbye!")
            logging.info("Admin Exited Panel")
            break
        elif choice == "2":
            print("\nRegistered Users:")
            try:
                for user in load_users().keys():
                    print("-", user)
            except orjson.JSONDecodeError:
                print("User file corrupted.")
                logging.warning("User file corrupted.")
                continue
        elif choice == "3":
            user_panel(username)
        else:
            print("Invalid choice.")
            logging.warning("Wrong choice made, repeating process.")
    return True
    
# Hidden admin setup function (PIN only)
def hidden_function():
    users = load_users()
    
    while True:
        password = getpass.getpass("Enter new admin PIN (Pass is hidden): ").strip() # Get a new PIN for registering admin

        if not password.isdigit(): # Verify Digits
            print("PIN must contain only digits.")
            logging.warning("Admin Setup failed (partially), Non-digit password entered.")
            continue

        if len(password) < 4: # Password length verification
            print("Password must be at least 4 digits.")
            continue
        
        confirm = getpass.getpass("Confirm your PIN: ").strip() # Password confirmation
        if password != confirm:
            print('Passwords do not match, Please try again.')
            continue
        
        if "admin" in users: # If the 'admin' is already registered, confirm the overwrite.
            ease = input('Admin PIN already exists, Overwrite? (y/n): ')
            if ease == 'n':
                break
            else:
                print("Wrong choice, Please try again later.")
        
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
    
    # Get two numbers (both will be saved in 'numbers')
    while True:
        num1 = input("Enter a number: ").strip()
        num2 = input("Enter a secondary number: ").strip()
                 
        try: # Using an try/except block for catching errors
            num1 = float(num1)
            num2 = float(num2)
        except ValueError:
            print("Invalid Input, Please enter numeric values.")
            logging.warning(f"Calculations gone wrong, non-digit entered by {username}.")
            continue
        
        numbers = [num1, num2]
        
        # All types of math are combined.    
        print("Multiplication =", num1 * num2)
        if numbers[1] == 0:
            logging.warning(f"One number have the value 0 by {username}, Canceling (Integer Division, Remainder)")
            print("Integer Division = Cannot divide by zero.")
            print("Remainder = Cannot divide by zero.")
        else:    
            print("Integer Division =", round(num1 // num2, 3))
            print("Remainder =", num1 % num2)
        print("Addition =", sum(numbers))
        print("Subtraction =", num1 - num2)        
        again = input("Do you want to recalculate again?: ")
        if again != 'y':
            break
    return

def guess_game(username):
    MAX_A = 5 # Give a attempt amount 
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
            print("You should pick a number between 1 and 20")
            continue
        
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
            logging.info(f"{username} Lost the game after {MAX_A}")
            break
            
# Log testing, Hanging test.
# def crash():
#     exec(type((lambda: 0).__code__)(0, 0, 0, 0, 0, 0, b'\x053', (), (), (), '', '', 0, b''))
# Main program
def main():
    logging.info("\nProgram started.")
    print(exp, fc_date)
    
    while True:
        print('\n1. Sign-up')
        print("2. Login")
        print("3. Exit")

        choice = input("Choose an option (1-3): ")
        
        # Depending on the choice, run the following functions
        if choice == "1":
            t = threading.Thread(target=sign_up, args=())
            t.start()
            t.join()
        elif choice == "2":
            s = threading.Thread(target=login, args=())
            s.start()
            s.join()
        elif choice == "3":
            print("Goodbye!")
            logging.info("Program exited successfully.")
            break
        elif choice == "9783":  # Hidden admin setup trigger
            logging.info("Admin Setup triggered.")
            h = threading.Thread(target=hidden_function, args=())
            h.start()
            h.join()
        # Second phase testing.
        # elif choice == "5":
        #     print("Thread object:", threading.Thread)
        else:
            print("Invalid choice. Please try again.")
            logging.warning("Incorrect choice made, repeating process.")
            continue

# Run the program
if __name__ == "__main__":
    try:
        c = threading.Thread(target=main, name=None, args=())
        c.start()
        c.join()
    except Exception:
        logging.exception("Unexpected crash in main execution")
        print("\nAn unexpected error occurred. Please check the log file for details.\n")
        exit(1)
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        exit()
