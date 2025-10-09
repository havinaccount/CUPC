#!/usr/bin/env python3
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


# -------------------- Library --------------------

from functools import lru_cache
from getpass import getpass # Using getpass to hide input
import orjson # Using orjson for faster read and write (ujson deprecated)
import os # Using os for user file deletion and dumping
import bcrypt # Using bcrypt for hashing passwords
from datetime import datetime # Using datetime for the main program
import logging # Using logging to capture every event
from random import randint # Using random for the guess game
import time # Using time for preventing brute-force attacks
import threading # Using threading for more optimized thread usage
import shutil # Using shutil for creating file backups
from blake3 import blake3 # For multithreaded cryptography and file hashing
import unicodedata # For username normalizations
import sys # For a cleaner and more stable code exit

# Following explanations may change depending on bugfixes and new features

# AI Generated (line 40-45)
logging.basicConfig(
    filename='ex.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s - Line %(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# -------------------- Variables --------------------

# 'USER_FILE' is the same as 'users.json'
USER_FILE = os.path.join(os.path.dirname(__file__), "users.json")
MAX_ATTEMPTS = 5
attempts = 0
users_cache = None
delay = 2 ** attempts
user_file_lock = threading.RLock()
USER_HASH = os.path.join(os.path.dirname(__file__), "users.hash")
win_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
# Datetime for app execution.
fc_date = datetime.now().strftime("%Y-%m-%d %H:%M")
exp = "Current datetime is:"

print(f"Using USER_FILE at : {USER_FILE}")
print("Exists:", os.path.exists(USER_FILE))

# -------------------- Still in development --------------------

def recreate_user():
    try:
        with open(USER_FILE, "wb") as file:
            file.write(orjson.dumps({}))
    except orjson.JSONDecodeError as e:
        print("USER_FILE is corrupted")
        logging.warning(f"User file corrupted, starting fresh: {e}")

@lru_cache(maxsize=128)
def normalize_username(username):
    return unicodedata.normalize('NFC', username.strip())

# -------------------- JSON Handling --------------------

# Load existing users from file
def load_users():
    global users_cache # Make the user cache globally available

    if users_cache is not None:
        return users_cache # Return cached users if already loaded

    if not os.path.exists(USER_FILE):
        logging.warning("User file not found, starting with empty user list.")
        with user_file_lock:
            try:
                recreate_user() # Reset the USER_FILE
            except orjson.JSONDecodeError as e:
                print("User file is corrupted, exiting.")
                logging.error(f"User file is corrupted: {e}")
        users_cache = {} # Give user_cache a storage
        return users_cache # Flush users_cache

    if not verify_user_file_integrity():
        logging.error("User file integrity tampered")
        print("Warning: User file integrity is tampered. Resetting users.")
        with user_file_lock:
            if os.path.exists(USER_FILE + '.tamp'):
                os.remove(USER_FILE + ".tamp")
            os.rename(USER_FILE, USER_FILE + '.tamp')
            recreate_user()
        users_cache = {}
        return users_cache
    try:
        with user_file_lock: # With the following thread lock, open user_file
            with open(USER_FILE, 'rb') as file:
                data = orjson.loads(file.read())
                if not isinstance(data, dict):
                    raise ValueError("User file corrupted: expected dict, got " + str(type(data)))
                users_cache = data
                logging.info("User file loaded successfully.")
    except orjson.JSONDecodeError as e: # Catch the USER_FILE Corruption
        logging.error(f"User file is corrupted: {e}\n\n Starting with empty user list.")
        print("Warning, User data file was corrupted, All accounts have been removed.")
        try:
            with user_file_lock:    
                os.rename(USER_FILE, USER_FILE + ".corrupted") # Take a backup of the corrupted user_file
            logging.info(f"Corrupted user file backed up as '{USER_FILE}.corrupted'")
        except Exception as e: # Catch the following exception
            logging.error(f"Failed to backup corrupted user file: {e}")
        finally:
            users_cache = {}
    except Exception as e: # Catch another exception
        logging.error(f"Failed to load user file {e}")
        print("System error, Starting with empty user list.")
        users_cache = {}
    
    if not users_cache:
        logging.warning("User cache is empty after load.")
    
    return users_cache # Flush the user_cache

def validate_users_dict(users_dict):
    try:
        if not isinstance(users_dict, dict):
            return False
        for username, hashed_pw in users_dict.items():
            if not isinstance(username, str):
                return False
            if not isinstance(hashed_pw, str):
                return False
        return True
    except Exception as e:
        logging.error(f"Validation failed: {e}")
        return False
# Save users to file
def save_users(users_dict):
    if not validate_users_dict(users_dict):
        raise ValueError("Invalid user data format")
    try:
        if os.path.exists(USER_FILE):
            with user_file_lock:
                shutil.copy(USER_FILE, f'{USER_FILE}.{win_date}.bak') # Create a backup of the USER_FILE
    except:
        logging.exception("Unexpected error in save_users")
        raise
    with user_file_lock: # With the thread lock inbound
        try:
            with open(USER_FILE, 'wb') as file:
                file.write(orjson.dumps(users_dict)) # Dump the sign-up info
            logging.info("User data saved.")
        except Exception as e: # Catch the exception
            print("Error saving user data. Please try again.")
            logging.error(f"Failed to save user data: {e}")
    
        try:  
            with open (USER_FILE, 'rb') as file:
                data = file.read()
            hasher_value = blake3(data).hexdigest()          
            with open(USER_HASH, 'wb') as hasher_file:
                hasher_file.write(hasher_value.encode('utf-8'))
            logging.info(f"User file hashed successfully {hasher_value}")
        except Exception as e:
            print("Error saving user data. Please try again.")
            logging.error(f"Failed to save user data or hash: {e}")

# -------------------- User Actions --------------------

# Sign up function with PIN validation and hashing
def sign_up():
    print("\n=== SIGN UP ===")
    users = load_users()
    
    while True:
        try:
            username = normalize_username(input("Choose a username: ").strip())
        except (KeyboardInterrupt, EOFError):
            print("\n\nInput stream closed. Cannot read input.\n")
            logging.error(f"EOFError: Input failed")
            return  # or break, or fallback logic
        
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
        
        try:
            password = getpass("Choose a PIN (numbers only, Pass is hidden): ", stream=None)
        except (KeyboardInterrupt, EOFError):
            print("Input stream closed. Cannot read input.")
            logging.error(f"EOFError: Input failed for {username}")
            return  # or break, or fallback logic
        
        if not password.isdigit(): # Numeric Verification
            print("PIN must contain only digits. Please try again.")
            logging.warning("Sign-up failed: Non-digit pin detected.")
            continue
        
        if len(password) < 4: # Password length verification
            print("Password must contain 4 digits.")
            continue
        
        try:
            confirm = getpass('Confirm your PIN: ').strip() # Give a confirmation check
        except (KeyboardInterrupt, EOFError):
            print("Input stream closed. Cannot read input.")
            logging.error(f"EOFError: Input failed for {username}")
            break  # or break, or fallback logic
        
        if confirm != password:
            print("PINs do not match, Please try again.")
            continue

        success = hash_verify(username, password)
        
        try:    
            if success:
                print("Account created successfully!")
            else:
                print("Account creation failed.")
        except (KeyboardInterrupt, EOFError):
                print("\nInput stream closed. Exiting program.")
                logging.error(f"EOFError: Input failed for {username}")
                sys.exit(1)  # Clean exit
        
        logging.info(f"New user '{username}' registered.")
        return
    
# -------------------- Hash handling --------------------
    
# Hashing sequence.    
def hash_verify(username, password):
    try:
        if not isinstance(password, str):
            raise TypeError(f"Expected password as str, got {type(password)}")

        users = load_users() # Load the USER_FILE       

        salt = bcrypt.gensalt(rounds=12)
  
        try:
            hashed_pw = bcrypt.hashpw(password.encode("utf-8"), salt) # Declare the hash_pw variable
            logging.debug(f"hashed_pw type: {type(hashed_pw)}")
        except Exception as e:
            logging.error(f"bcrypt.hashpw failed: {e}")
            return False
        users[username] = hashed_pw.decode("utf-8") # Assign the password to the user
        save_users(users) # Dump all the info
        return True
    except Exception as e:
        logging.error(f"Hashing failed: {e}")
        return False

def hash_new_pin(username, new_pin):
    try:
        users = load_users()
        hashed_pw = bcrypt.hashpw(new_pin.encode(), bcrypt.gensalt(rounds=12))
        users[username] = hashed_pw.decode()
        save_users(users)
        logging.info(f"{username} Changed PIN successfully.")
        return True
    except Exception as e:
        logging.error(f"Changing PIN failed: {e}")
        return False
    
def hash_admin_pin(password):
    try:
        users = load_users()
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        admin_normal = normalize_username("admin")
        users[admin_normal] = hashed_pw.decode()
        save_users(users)
        print("Admin PIN set successfully.")
        logging.info("Admin account successfully created")
        return True
    except Exception as e:
        print("New PIN registration unsuccessful")
        logging.error(f"Failed to change admin PIN: {e}")
        return False

def verify_user_file_integrity():
    try:
        with user_file_lock:
            with open(USER_FILE, 'rb') as file:
                data = file.read()
            current_hash = blake3(data).hexdigest()
            
            with open(USER_HASH, 'r') as hasher_file:
                stored_hash = hasher_file.read().strip()
            
        return current_hash == stored_hash
    except Exception as e:
        logging.warning(f"Integrity check failed: {e}")
        return False

# Login function with PIN validation and verification
def login():
    print("\n=== LOGIN ===")
    users = load_users()
    
    if not users:
        print("No users registered. Please sign up first.")
        return False
    
    try:
        username = normalize_username(input("Username: ").strip())
    except (KeyboardInterrupt, EOFError):
        print("\n\nInput stream closed. Cannot read input.\n")
        logging.error(f"EOFError: Input failed")
        return  # or break, or fallback logic
    
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
        try:    
            password = getpass("PIN (Pass is hidden): ") # Getting password
        except (KeyboardInterrupt, EOFError):
            print("\n\nInput stream closed. Cannot read input.\n")
            logging.error(f"EOFError: Input failed")
            break  # or break, or fallback logic
        
        if not password.isdigit(): # Making Password only look for digits. 
            print("PIN must contain only digits.")
            logging.warning("Login attempt failed: Non-digit PIN entered.")
            continue
        
        if len(password) < 4: # Verifying password length.
            print("Password must contain 4 digits.")
            continue
        
        if bcrypt.checkpw(password.encode(), stored_hash): # If the encoded password that we received matches our stored hash, log in.
            logging.info(f"User '{username}' logged in successfully.")
 
            if username == "admin": # if the username is admin and password matches, launch admin panel, otherwise, launch user panel
                logging.info("Admin panel executed.")
                admin_panel()
            user_panel(username)
            break
        else:
            print("\nPassword is incorrect, Please try again\n")
            attempts += 1 
    
# -------------------- User Abilities --------------------
 
# User Panel
def user_panel(username):    
    print("Login successful!")
    
    while True: 
        print("\n1. Calculation")
        print("2. Change PIN")
        print("3. Guess the Number")
        print("4. Log out")
        
        try:
            choice = input("Please select a number: ").strip() # Get a number from user.
        except (KeyboardInterrupt, EOFError):
            print("\n\nInput stream closed. Cannot read input.\n")
            logging.error(f"EOFError: Input failed for {username}")
            return  # or break, or fallback logic
        
        # Depending on the choice, launch the following functions
        if choice == "1":
            calc(username)
        elif choice == "2":
            success = change_pin(username)
            if success:
                print("PIN changed successfully!")
            else:
                print("PIN change failed.")
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
        try:
            new_pin = getpass("Enter new PIN: ").strip() # Ask the user for the following new PIN
        except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed. Cannot read input.\n")
                logging.error(f"EOFError: Input failed for {username}")
                return  # or break, or fallback logic
        
        if len(new_pin) < 4: # PIN length verification
            print("PIN must be 4 digits or higher.")
            continue
        try:
            confirm = getpass("Confirm your following PIN: ").strip() # Password Confirmation.
        except (KeyboardInterrupt, EOFError):
            print("\n\nInput stream closed. Cannot read input.\n")
            logging.error(f"EOFError: Input failed for {username}")
            return  # or break, or fallback logic    
        
        if confirm != new_pin:
            print("PINs do not match, Please try again.")
            continue
        
        if username not in users: # If username got corrupt in changing PIN section, Stop the process.
            print("User not found.")
            logging.warning(f"PIN change failed: {username} not found")
        
        if new_pin.isdigit(): # If all the requirements are fulfilled, change the pin using hashing mechanic
            success = hash_new_pin(username, new_pin)
            if success:
                return True
            else:
                return False
        else:
            print("Password must contain only digits.")
        return
    
# -------------------- Admin Abilities --------------------
    
# Admin Panel
def admin_panel(username="admin"):
    print("Welcome Admin.")
    logging.info("Admin panel accessed.")
    
    while True:
        print("\n1. Reset user file")
        print("2. List of users")
        print('3. User Panel')
        print("4. Exit")
        
        try:
            choice = input("Choose an option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nInput stream closed. Cannot read input.\n")
            logging.error(f"EOFError: Input failed for {username}")
            return  # or break, or fallback logic")
        
        # Depending on the choice, Execute the following functions.
        if choice == "1":
            if os.path.exists(USER_FILE): # User file deletion mechanic
                os.remove(USER_FILE)
                with open(USER_FILE, 'wb') as file:
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
  
# -------------------- Hidden functions --------------------
  
# Hidden admin setup function (PIN only)
def hidden_function():
    users = load_users()
    
    try:
        while True:
            try:
                password = getpass("Enter new admin PIN (Pass is hidden): ").strip() # Get a new PIN for registering admin
            except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed, Cannot read input.\n")
                logging.error(f"EOFError: Input failed")
                return  # or break, or fallback logic
            if not password.isdigit(): # Verify Digits
                print("PIN must contain only digits.")
                logging.warning("Admin Setup failed (partially), Non-digit password entered.")
                continue

            if len(password) < 4: # Password length verification
                print("Password must be at least 4 digits.")
                continue
            try:
                confirm = getpass("Confirm your PIN: ").strip() # Password confirmation
            except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed. Cannot read input.\n")
                logging.error("EOFError: Input failed")
                return  # or break, or fallback logic    
            
            if password != confirm:
                print('Passwords do not match, Please try again.')
                continue
            
            if "admin" in users: # If the 'admin' is already registered, confirm the overwrite.
                try:
                    choice = input('Admin PIN already exists, Overwrite? (y/n): ')
                except (KeyboardInterrupt, EOFError):
                    print("\n\nInput stream closed. Cannot read input.\n")
                    logging.error("EOFError: Input failed")
                    return  # or break, or fallback logic    
                if choice == 'n':
                    break
                elif choice == 'y':
                    try:
                        hash_admin_pin(password)
                        print("Admin PIN overwritten successfully.")
                        logging.info("Admin PIN overwritten.")
                        break
                    except Exception as e:
                        logging.error(f"Admin hashing failed: {e}")
                        break
                else:
                    print("Wrong choice, Please try again later.")
            else:
                try:
                    hash_admin_pin(password)
                    logging.info("Admin PIN created.")
                    break
                except Exception as e:
                    logging.error(f"Admin hashing failed: {e}")
                    break
    except Exception as e:
        logging.error(f"Login failed: {e}")
        return False
    
# -------------------- User Abilities (pt2) --------------------

# Calculator
def calc(username):
    print(f"Welcome {username}")
    logging.info(f"User {username} accessed calculator.")
    
    # Get two numbers (both will be saved in 'numbers')
    while True:
        try:
            try:
                num1 = input("Enter a number: ").strip()
                num2 = input("Enter a secondary number: ").strip()
            except (KeyboardInterrupt, EOFError):
                    print("\n\nInput stream closed. Cannot read input.\n")
                    logging.error(f"EOFError: Input failed for {username}")
                    return  # or break, or fallback logic         
            
            try: # Using an try/except block for catching errors
                num1 = float(num1)
                num2 = float(num2)
            except ValueError:
                print("Invalid Input, Please enter numeric values.")
                logging.warning(f"Calculations gone wrong, non-digit entered by {username}.")
                continue
            
            numbers = [num1, num2]
            
            # All types of math are combined.    
            print("\nMultiplication =", num1 * num2)
            if numbers[1] == 0:
                logging.warning(f"One number have the value 0 by {username}, Canceling (Integer Division, Remainder)")
                print("Integer Division = Cannot divide by zero.")
                print("Remainder = Cannot divide by zero.")
            else:    
                print("Integer Division =", integer_division(num1 ,num2))
                print("Remainder =", remainder(num1, num2))
            print("Addition =", sum(numbers))
            print("Subtraction =", subtraction(num1 , num2))        
            
            try:
                again = input("\nDo you want to recalculate again?: \n").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed. Cannot read input.\n")
                logging.error(f"EOFError: Input failed for {username}")
                return  # or break, or fallback logic    v
            
            if again != 'y':
                break
        except Exception as e:
            logging.error(f"Calculation failed: {e}")
    return

def subtraction(x, y):
    return x - y
def integer_division(x, y):
    return round(x // y, 3)
def remainder(x, y):
    return x % y

# -------------------- User Abilities (pt3) --------------------

def guess_game(username):
    MAX_A = 5 # Give a attempt amount 
    attempt = 0
    target = randint(1, 20)
    logging.info(f"{username} Playing game.")
    
    try:
        while True:   
            try:
                guess = input("Guess a number (1-20): ").strip()
            except (KeyboardInterrupt, EOFError):
                    print("\n\nInput stream closed. Cannot read input.\n")
                    logging.error(f"EOFError: Input failed for {username}")
                    return  # or break, or fallback logic
            
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
    except Exception as e:
        logging.error(f"Game failed: {e}")

# Log testing, Hanging test.
# def crash():
#     exec(type((lambda: 0).__code__)(0, 0, 0, 0, 0, 0, b'\x053', (), (), (), '', '', 0, b''))

# -------------------- Main program --------------------
@lru_cache(None)
def main():
    logging.info("\nProgram started.")
    print(exp, fc_date)
    
    try:
        while True:
            print('\n1. Sign-up')
            print("2. Login")
            print("3. Exit")
            try:
                choice = input("Choose an option (1-3): ")
            except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed. Cannot read input.\n")
                logging.error(f"EOFError: Input failed")
                return  # or break, or fallback logic
            
            # Depending on the choice, run the following functions
            if choice == "1":
                print("\nStarting Sign-up")
                time.sleep(2)
                sign_up()
            elif choice == "2":
                print("\nStarting Login\n")
                time.sleep(2)
                login()
            elif choice == "3":
                print("Goodbye!")
                logging.info("Program exited successfully.")
                break
            elif choice == "9783":  # Hidden admin setup trigger
                logging.info("Admin Setup triggered.")
                hidden_function()
            # Second phase testing.
            # elif choice == "5":
            #     print("Thread object:", threading.Thread)
            else:
                print("Invalid choice. Please try again.")
                logging.warning("Incorrect choice made, repeating process.")
                continue
    except Exception as e:
        logging.error(f"Program failed: {e}")
        
# Run the program
if __name__ == "__main__":
    try:
        main()
    except Exception:
        logging.exception("Unexpected crash in main execution")
        print("\nAn unexpected error occurred. Please check the log file for details.\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit()
