#!/usr/bin/env python3
# -*- coding=utf-8 -*-
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
# Update 4: Added colorama for colored exception catching
# Update 5: Limiting const choices, Example: 'const: str = value' means const is only getting strings

# -------------------- Library --------------------

from functools import lru_cache # Using lru_cache to call 'normalize_username()' faster
import getpass # Using getpass to hide input
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
import numpy as np # For fast calculations
import colorama # For coloring Exceptions
from numba import jit

# Following explanations may change depending on bugfixes and new features

# AI Generated (line 59-64)
logging.basicConfig(
    filename='ex.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(funcName)s - Line %(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# -------------------- Variables --------------------
def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

BASE_DIR = os.path.dirname(__file__)
USER_FILE = os.path.join(BASE_DIR, "users.json")
MAX_ATTEMPTS = 5
attempts = 0
users_cache = None
delay = lambda attempt: 2 ** attempt
user_file_lock = threading.RLock()
USER_HASH = os.path.join(BASE_DIR, "users.hash")
win_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
# Datetime for app execution.
exp = "Current datetime is:"
date = current_timestamp()

print(f"Using USER_FILE at : {USER_FILE}")
print(f"Exists: {os.path.exists(USER_FILE)}")

# -------------------- Still in development --------------------

def recreate_user():
    try:
        empty_list = b'{}'
        with open(USER_FILE, "wb") as file:
            file.write(empty_list)
        return True
    except Exception as e:
        print(colorama.Fore.RED + "FATAL: USER_FILE is corrupted" + colorama.Style.RESET_ALL)
        logging.warning(f"Failed to recreate user file: {e}")
        return False

@lru_cache(maxsize=128)
def normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValueError("Username must be a string")
    return unicodedata.normalize('NFC', username.strip())

# -------------------- JSON Handling --------------------

# Load existing users from file
def load_users():
    global users_cache # Make the user cache globally available

    if users_cache is not None:
        return users_cache # Return cached users if already loaded
    
    # Check for 'USER_FILE' existence
    if not os.path.exists(USER_FILE):
        logging.warning("User file not found, starting with empty user list.")
        with user_file_lock:
            recreate_user() # Reset the USER_FILE
        if not recreate_user():
            print(colorama.Fore.RED + "FATAL: Reset unsuccessful" + colorama.Style.RESET_ALL)
            sys.exit(1)
        users_cache = {} # Give user_cache a storage
        return users_cache # Flush users_cache

    if not verify_user_file_integrity():
        logging.error(colorama.Fore.RED + "FATAL: User file integrity tampered" + colorama.Style.RESET_ALL)
        print("Warning: User file integrity is tampered. Resetting users.")
        with user_file_lock:
            if os.path.exists(USER_FILE + '.tamp'):
                os.remove(USER_FILE + ".tamp")
            os.rename(USER_FILE, USER_FILE + '.tamp')
            recreate_user()
            if not recreate_user():
                print(colorama.Fore.RED + "FATAL: Reset unsuccessful." + colorama.Style.RESET_ALL)
                sys.exit(1)
        users_cache = {}
        return users_cache
    try:
        with user_file_lock: # With the following thread lock, open user_file
            with open(USER_FILE, 'rb') as file:
                data = orjson.loads(file.read())
                if not isinstance(data, dict):
                    raise ValueError(colorama.Fore.RED + f"FATAL: User file corrupted: expected dict, got {type(data)}" + colorama.Style.RESET_ALL)
                users_cache = data
                logging.info("User file loaded successfully.")
    except orjson.JSONDecodeError as e: # Catch the USER_FILE Corruption
        logging.error(f"User file is corrupted: {e}\n\n Starting with empty user list.")
        print(colorama.Fore.YELLOW + "Warning: User data file was corrupted, All accounts have been removed." + colorama.Style.RESET_ALL)
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
        print(colorama.Fore.RED + "FATAL: System error, Starting with empty user list." + colorama.Style.RESET_ALL)
        users_cache = {}
    
    if not users_cache:
        logging.warning("User cache is empty after load.")
    
    return users_cache # Flush the user_cache

def validate_users_dict(users_dict) -> bool:
    if not isinstance(users_dict, dict):
        return False
    try:
        for username, hashed_pw in users_dict.items():
            if not isinstance(username, str) or not isinstance(hashed_pw, str):
                return False
        return True
    except Exception as e:
        logging.error(f"Validation failed: {e}")
        return False
# Save users to file
def save_users(users_dict) -> None:
    if not validate_users_dict(users_dict):
        raise ValueError("Invalid user data format")

    # Backup the existing files
    try:
        if os.path.exists(USER_FILE):
            shutil.copy(USER_FILE, f'{USER_FILE}.{win_date}.bak') # Create a backup of the USER_FILE
    except Exception as e:
        logging.exception(f"Unexpected error when backing up user file: {e}")
        raise

    # Save new user data
    try:
        with user_file_lock:  # With the thread lock inbound
            with open(USER_FILE, 'wb') as file:
                file.write(orjson.dumps(users_dict)) # Dump the sign-up info
            logging.info("User data saved.")
    except Exception as e: # Catch the exception
        print(colorama.Fore.RED + "FATAL: Error saving user data. Please try again." + colorama.Style.RESET_ALL)
        logging.error(f"Failed to save user data: {e}")

    # Hash and store integrity value
    try:
        with open (USER_FILE, 'rb') as file:
            data = file.read()
        hasher_value = blake3(data).hexdigest()
        with open(USER_HASH, 'wb') as hasher_file:
            hasher_file.write(hasher_value.encode('utf-8'))
        logging.info(f"User file hashed successfully {hasher_value}")
    except Exception as e:
        print(colorama.Fore.RED + "FATAL: Error saving user data. Please try again." + colorama.Style.RESET_ALL)
        logging.error(f"Failed to save user data or hash: {e}")

# -------------------- User Actions --------------------

# Sign up function with PIN validation and hashing
def sign_up():
    print("\n=== SIGN UP ===")
    users = load_users()
    
    while True:

        username: str = normalize_username(safe_input("Choose a username: ", strip=True)) # Make a str username const
        
        logging.info(f"Sign-up attempt for username: {username}")

        if username is None:
            print("Nothing entered, Pleases try again.")
            continue

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

        password = safe_getpass("Choose a PIN (numbers only, Pass is hidden): ")

        if password is None:
            print("Nothing Entered, Please try again.")
            continue

        
        if not password.isdigit(): # Numeric Verification # type: ignore
            print("PIN must contain only digits. Please try again.")
            logging.warning("Sign-up failed: Non-digit pin detected.")
            continue

        if len(password) < 4: # Password length verification # type: ignore
            print("Password must contain 4 digits.")
            continue
        
        confirm = safe_getpass("Confirm your PIN: ")

        if confirm is None:
            print("Nothing Entered, Please try again.")
            continue

        if confirm != password:
            print("PINs do not match, Please try again.")
            continue
        if isinstance(password, str):
            success = hash_pass(username, password)
            if success:
                print("Account created successfully!")
            else:
                print("Account creation failed.")
        else:
            return False
    
        logging.info(f"New user '{username}' registered.")
        return True

def safe_getpass(string: str, strip: bool = True) -> str | bool | None:
    try:
        value = getpass.getpass(string)
        if not value: return None
        return value.strip() if strip else value
    except Exception as e:
        print("Exiting or error.")
        logging.error(f"Password interception: {e}")
        return False

# -------------------- Hash handling --------------------

def _set_user_secret(username: str, secret: str, label: str) -> bool:
    try:
        users = load_users()
        hashed = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt(rounds=12))
        users[username] = hashed.decode("utf-8")
        save_users(users)
        logging.info(f"{username} {label} updated successfully.")
        return True
    except Exception as e:
        logging.error(f"Failed to set {label} for {username}: {e}")
        return False

def hash_pass(username: str, password: str | None) -> bool:
    if not isinstance(password, str):
        logging.error(f"Expected password as str, got {type(password)}")
        return False
    return _set_user_secret(username, password, "Password")

def hash_new_pin(username: str, new_pin: str) -> bool:
    if not isinstance(new_pin, str):
        logging.error(f"Expected new_pin as str, got {type(new_pin)}")
        return False
    return _set_user_secret(username, new_pin, "PIN")

def hash_admin_pin(password: str) -> bool:
    success = _set_user_secret(normalize_username("admin"), password, "admin PIN")
    if success:
        print("Admin PIN set successfully.")
    else:
        print(colorama.Fore.RED + "FATAL: New PIN registration unsuccessful" + colorama.Style.RESET_ALL)
    return success

def verify_user_file_integrity() -> bool:
    try:
        with user_file_lock, open(USER_FILE, "rb") as file:
            hasher = blake3()
            for chunk in iter(lambda: file.read(8192), b""):
                hasher.update(chunk)
            current_hash = hasher.hexdigest()

        with open(USER_HASH, "rb") as hasher_file:
            stored_hash = hasher_file.read().decode("utf-8").strip()

        return current_hash == stored_hash
    except FileNotFoundError as e:
        logging.warning(f"Integrity check failed, missing file: {e.filename}")
        return False
    except Exception as e:
        logging.warning(f"Integrity check failed: {e}")
        return False

# New type of input with error handling (Please don't change this unless improving it)
def safe_input(prompt: str = "", strip: bool = True, lower: bool = False, upper: bool = False) -> str | bool | None:
    try:
        value = input(prompt)
        if strip:
            value = value.strip()
        if lower:
            value = value.lower()
        elif upper:
            value = value.upper()
        if lower and upper:
            raise ValueError(colorama.Fore.YELLOW + "Warning: Can't apply both lower and upper case transformations." + colorama.Style.RESET_ALL)
        return None if not value else value
    except (KeyboardInterrupt, EOFError):
        print("\n\nInput stream closed. Cannot read input.\n")
        logging.error(f"EOFError: Input failed")
        return False # or break, or fallback logic

# Login function with PIN validation and verification
def login():
    print("\n=== LOGIN ===")
    users = load_users()
    
    if not users:
        print("No users registered. Please sign up first.")
        return False

    username: str = normalize_username(safe_input("Username: ", strip=True))
    
    if username is None:
        print("Nothing entered, Please try again later.")
        return False

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
    stored_hash = users.get(username, dummy_hash)
    
    if isinstance(stored_hash, str):
        try:
            stored_hash = stored_hash.encode()
        except Exception as e:
            logging.error(f"Failed to encode stored hash for '{username}': {e}")
            print(colorama.Fore.RED + "FATAL: Unexpected error occurred. Please contact support." + colorama.Style.RESET_ALL)
            return False

    attempt: int = 0 # Make an int const
    
    while attempt < MAX_ATTEMPTS:
            
            password = safe_getpass("PIN (Pass is hidden): ") # Getting password

            if password is None:
                print("Login cancelled.")
                return False

            if password == False:
                print("Aborting Password.")
                time.sleep(2)
                break
            
            if not password.isdigit(): # Making Password only look for digits. # type: ignore
                print("PIN must contain only digits.")
                logging.warning("Login attempt failed: Non-digit PIN entered.")
                continue
        
            if len(password) < 4: # Verifying password length. # type: ignore
                print("Password must contain 4 digits.")
                continue
        
            if bcrypt.checkpw(password.encode(), stored_hash): # If the encoded password that we received matches our stored hash, log in. # type: ignore
                logging.info(f"User '{username}' logged in successfully.")

                if username == "admin": # if the username is admin and password matches, launch admin panel, otherwise, launch user panel
                    logging.info("Admin panel executed.")
                    admin_panel()
                    return True
                user_panel(username)
                return True
            else:
                print("\nPassword is incorrect, Please try again\n")
                attempt += 1

    print("Maximum login attempts reached.")
    return False

# -------------------- User Abilities --------------------

# User Panel
def user_panel(username):    
    print("Login successful!")
    
    while True: 
        print("\n1. Calculation", "\n2. Change PIN", "\n3. Guess the Number", "\n4. Exit")

        choice = safe_input("Please select a number: ", strip=True) # Get a number from user.

        if not choice:
            print("Nothing entered, Please try again.")
            continue

        # Depending on the choice, launch the following functions
        match choice:
            case "1":
                calc(username)
            case "2":
                success = change_pin(username)
                if success:
                    print("PIN changed successfully!")
                else:
                    print("PIN change failed.")
            case "3":
                guess_game(username)
            case "4":
                print("Goodbye!")
                logging.info("User successfully logged out.")
                break
            # If wrong choice is given, ask again.
            case _:
                print("\nWrong choice, Please try again.")
                logging.warning("Wrong Choice Entered, repeating choice process.")
                continue

# Change PIN
def change_pin(username):
    try: # Using a try/except block to prevent errors
        users = load_users()
    except (orjson.JSONDecodeError, FileNotFoundError):
        print("User file not found")
        return False
    
    logging.info(f"{username} requests a PIN change.")
    
    while True:

        new_pin = safe_getpass("Enter new PIN: ") # Ask the user for the following new PIN 

        if len(new_pin) < 4: # PIN length verification # type: ignore
            print("PIN must be 4 digits or higher.")
            continue

        confirm = safe_getpass("Confirm your following PIN: ") # Password Confirmation. # type: ignore
        
        if confirm != new_pin:
            print("PINs do not match, Please try again.")
            continue
        
        if username not in users: # If username got corrupt in changing PIN section, Stop the process.
            print("User not found.")
            logging.warning(f"PIN change failed: {username} not found")
        if not isinstance(new_pin, str):
            print("Invalid PIN Input")
            return False 
        if not new_pin.isdigit(): # If all the requirements are fulfilled, change the pin using hashing mechanic # type: ignore
            print("Password must contain only digits.")
            return False
        
        return hash_new_pin(username, new_pin)
# -------------------- Admin Abilities --------------------
    
# Admin Panel
def admin_panel(username: str = "admin"):
    """_summary_

    Args:
        username (str, optional): _description_. Defaults to "admin".

    Returns:
        TrTrue, None: Essential admin panel for admin
    """
    print("Welcome Admin.")
    logging.info("Admin panel accessed.")
    
    global users_cache
    
    while True:
        print("\n1. Reset user file", "\n2. List of users", "\n3. User Panel", "\n4. Logout")

        choice = safe_input("Choose an option: ", strip=True)
        
        # Depending on the choice, Execute the following functions.
        match choice:
            case "1":
                if not os.path.exists(USER_FILE):
                    logging.warning("Admin tried to reset user file, but it was not found.")
                    print(colorama.Fore.YELLOW + "Warning: User file not found." + colorama.Style.RESET_ALL)
                    continue    
                
                try:
                    os.remove(USER_FILE)
                    with user_file_lock:
                        success = recreate_user()
                    if success:
                        print("'users.json' has been reset.")
                        users_cache = {}
                        logging.info(f"Admin reset user file at {current_timestamp()}")
                    else:
                        raise RuntimeError("User file reset failed.")
                except Exception as e:
                    print(colorama.Fore.RED + "FATAL: User file reset failed. Exiting program." + colorama.Style.RESET_ALL)
                    logging.error(str(e))
                    sys.exit(1)
                continue
            case "4":
                print("Goodbye!")
                logging.info("Admin Exited Panel")
                break
            case "2":
                print("\nRegistered Users:")
                try:
                    users = users_cache if users_cache else load_users()
                    if not users: print("User file isn't available."); logging.warning("User file isn't available for admin or empty."); continue
                    print("\n".join(f"- {user}" for user in users))
                except orjson.JSONDecodeError:
                    print(colorama.Fore.RED + "FATAL: User file corrupted." + colorama.Style.RESET_ALL)
                    logging.warning("User file corrupted.")
                    continue
            case "3":
                user_panel(username)
            case _:
                print("Invalid choice.")
                logging.warning("Wrong choice made, repeating process.")
    return True

# -------------------- Hidden functions --------------------

# Hidden admin setup function (PIN only)
def hidden_function() -> bool | None:
    """_summary_

    Returns:
        bool: It does not need to be returning data
    """
    users = load_users()
    print("\n===ADMIN SETUP===")

    try:
        while True:
            password = safe_getpass("Enter new admin PIN (Pass is hidden): ") # Get a new PIN for registering admin

            if not password.isdigit(): # Verify Digits # type: ignore
                print("PIN must contain only digits.")
                logging.warning("Admin Setup failed (partially), Non-digit password entered.")
                continue

            if password is None:
                print("Nothing entered. Please try again.")
                continue

            if len(password) < 4: # Password length verification # type: ignore 
                print("Password must be at least 4 digits.")
                continue
            try:
                confirm = safe_getpass("Confirm your PIN: ") # Password confirmation
            except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed. Cannot read input.\n")
                logging.error("EOFError: Input failed")
                return False # or break, or fallback logic

            if confirm is None:
                print("Nothing entered, Please try again.")
                continue

            if password != confirm:
                print('Passwords do not match, Please try again.')
                continue
            
            if "admin" in users: # If the 'admin' is already registered, confirm to overwrite.
                    choice = safe_input('Admin PIN already exists, Overwrite? (y/n): ', lower=True, strip=True)

                # Choice checking
                    if choice.lower().strip() == 'n': # type: ignore
                        break
                    elif choice == 'y':
                        try:
                            if not isinstance(password, str):
                                print("Invalid admin PIN input.")
                                logging.warning("Admin PIN setup aborted: non-string input.")
                                return False  
                            success = hash_admin_pin(password)
                            if success:
                                print("Admin PIN overwritten successfully.")
                                logging.info("Admin PIN overwritten.")
                                break
                            else:
                                logging.error("Admin PIN overwrite failed.")
                        except Exception as e:
                            logging.error(f"Admin hashing failed: {e}")
                            break
                    elif choice is None:
                        print("Nothing entered, Please try again.")
                        continue
                    else:
                        print("Wrong choice, Please try again later.")
            else:
                try:
                    if not isinstance(password, str):
                        print("Invalid admin PIN input.")
                        logging.warning("Admin PIN setup aborted: non-string input.")
                        return False  
                    success = hash_admin_pin(password)
                    if success:
                        logging.info("Admin PIN created.")
                        break
                    else:
                        print("Admin PIN creation failed.")
                        break
                except Exception as e:
                    logging.error(f"Admin hashing failed: {e}")
                    break
    except Exception as e:
        logging.error(f"Login failed: {e}")
        return False
    
# -------------------- User Abilities (pt2) --------------------

def get_input(prompt: str) -> str | bool | None: # Limit the return options
    try:
        while True:
            value = input(prompt).strip()
            return value if value else None
    except (KeyboardInterrupt, EOFError):
        print("\n\nInput stream closed. Cannot read input.\n")
        logging.error(f"EOFError: Input failed")
        return False # or break, or fallback logic
    
# Calculator
def calc(username: str):
    """A Simple, interactive calculator"""
    print(f"Welcome {username}")
    logging.info(f"User {username} accessed calculator.")
    while True:
        try:
            raw_input = []
    
            # Get numbers (they will be saved in 'numbers')
            while True:
                user_input = get_input("\nEnter numbers one by one (Type 'done' when finished): ") 
                if user_input is None:
                    print("Nothing entered, Please try again.")
                    continue
                if user_input == False:
                    print("Aborting Calculator")
                    return None
                
                normalized = user_input.lower().strip() # type: ignore
                
                if normalized == 'done': # type: ignore
                    break

                raw_input.append(user_input)
            
            try:
                numbers = [float(x) for x in raw_input]
                # Use numpy array for a large chunk of numbers
                arr = np.round(np.array(numbers, dtype=np.float64), 6)
            except ValueError:
                print("One or multiple numbers were invalid")
                return False
            
            # Check if any numbers entered
            if not numbers:
                print("No numbers entered")
                return None

            print(f"Numbers entered: {arr}")
            # All types of math are combined.    
            print(f"\nMultiplication = {multiplication(arr)}")
            if len(numbers) == 2:
                print(f"Remainder = {remainder(numbers)}")
            else:
                print("For remainder, You need enter two numbers only.")
            print(f"Average = {average(arr)}")
            print(f"Addition = {addition(arr)}")
            print(f"Subtraction = {subtraction(arr)}")
            try:
                again = safe_input("\nDo you want to recalculate again?: \n", lower=True, strip=True)
            except (KeyboardInterrupt, EOFError):
                print("\n\nInput stream closed. Cannot read input.\n")
                logging.error(f"EOFError: Input failed for {username}")
                return False  # or break, or fallback logic

            if again is None:
                print("Nothing entered, Please try again later.")
                return None

            if again.lower().strip() != 'y': # type: ignore
                break
        except Exception as e:
            print(colorama.Fore.RED + "FATAL: An error occurred. Please try again." + colorama.Style.RESET_ALL)
            logging.error(f"Calculation failed: {e}")
            return None

def remainder(arr: list[float]) -> float:
    """
    This Python function calculates the remainder of two numbers safely, checking for division by zero.
    
    :param arr: The `arr` parameter is expected to be a list of two float numbers `[x, y]` where `x` is
    the dividend and `y` is the divisor. The function `remainder` calculates the remainder of `x`
    divided by `y` using NumPy's `remainder`
    :type arr: list[float]
    :return: The function `remainder` is returning the remainder of the first element in the input list
    divided by the second element in the input list using NumPy's `remainder` function. If either of the
    elements in the input list is 0.0, a `ValueError` is raised with the message "Cannot divide by
    zero".
    """
    if len(arr) != 2: raise ValueError(colorama.Fore.YELLOW + "Warning: Input list must be a list of two float numbers." + colorama.Style.RESET_ALL)
    if arr[1] == 0: raise ValueError(colorama.Fore.RED + "FATAL: Cannot divide by zero" + colorama.Style.RESET_ALL)
    x, y = arr
    return np.remainder(x, y)
@jit(nopython=True, cache=True, parallel=True)
def average(arr: np.ndarray) -> float:
    """This python function calculates the average of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `mean`
    :type arr: np.ndarray:
    :return: The function `average` is returning the average of `arr` using the NumPy's `mean` function.
    """
    return float(np.round(np.mean(arr), 3))
@jit(nopython=True, cache=True, parallel=True)
def addition(arr: np.ndarray) -> float:
    """This python function calculates the addition of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `sum`
    :type arr: np.ndarray:
    :return: The function `addition` is returning the average of `arr` using the NumPy's `sum` function.
    """
    return float(np.round(np.sum(arr), 2))
@jit(nopython=True, cache=True, parallel=True)
def subtraction(arr: np.ndarray) -> float:
    """This python function calculates the average of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `subtract.reduce()`
    :type arr: np.ndarray:
    :return: The function `subtraction` is returning the average of `arr` using the NumPy's `subtract.reduce()` function.
    """
    return float(np.round(np.subtract.reduce(arr), 2))
@jit(nopython=True, cache=True, parallel=True)
def multiplication(arr: np.ndarray) -> float:
    """This python function calculates the average of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `prod`
    :type arr: np.ndarray:
    :return: The function `multiplication` is returning the average of `arr` using the NumPy's `prod` function.
    """
    return float(np.round(np.prod(arr), 3))
# -------------------- User Abilities (pt3) --------------------

def guess_game(username) -> None: # Can be changed for new return arguments
    """_summary_

    Args:
        username (str): Gets a username for logging

    Returns:
        None: Returns nothing since it's an essential calculator 
    """
    max_a: int = 5 # Give n attempt amount
    attempt = 0
    target = randint(1, 20)
    logging.info(f"{username} Playing game.")
    
    try:
        while True:   

            guess = safe_input("Guess a number (1-20): ", strip=True)
            
            if guess is None:
                print("Your guess could not be empty, Pick a number.")
                continue
            # Check for the number being digits
            try:
                guess = int(guess)
            except ValueError:
                print(colorama.Fore.YELLOW + "Warning: You should guess a number." + colorama.Style.RESET_ALL)
                continue
            # Minimize the options
            if guess < 1 or guess > 20:
                print("You should pick a number between 1 and 20")
                continue
            # Check for equality of target
            if guess == target:
                print("You won!")
                logging.info(f"{username} Exited game successfully")
                break
            elif guess < target:
                attempt += 1
                print(f"Pick a higher number, Attempts remaining {max_a - attempt}")
            elif guess > target:
                attempt += 1
                print(f"You should pick a smaller number. Attempts remaining {max_a - attempt}")
            
            if attempt == 5: # Check for attempt count
                print(f"You lost {username}, The number was {target}")
                logging.info(f"{username} Lost the game after {max_a}")
                break       
    except Exception as e:
        logging.error(f"Game failed: {e}")

# Log testing, Hanging test.
# def crash():
#    raise Exception

def warm_up_terminal():
    # noinspection PyBroadException
    try:
        getpass.getpass(prompt="Press enter to continue...")
    except Exception:
        pass

# -------------------- Main program ------------------
def main():
    """
    The main function in the Python code handles user input for sign-up, login, and exit options, with
    error handling and logging implemented.
    :return: In the `main()` function, if an `EOFError` occurs while trying to read , the program
    will log an error message and then return from the function.
    """
    logging.info("\nProgram started.")

    # For faster I/O executions
    warm_up_terminal()
    print(exp, current_timestamp())
    actions = {
        "1": lambda: (print("Starting sign-up"), time.sleep(0.5), sign_up()),
        "2": lambda: (print("Starting Login"), time.sleep(0.5), login()),
        "3": lambda: (print("Exiting"), exit()),
        "9783": lambda: hidden_function()
    }
    while True:
        print('\n1. Sign-up', "\n2. Login", "\n3. Exit") # Inlining the print function for less overhead

        choice = safe_input("Choose an option (1-3): ", strip=True)

        if choice is None:
            print("No input received")
            return
            # Depending on the choice, run the following functions
        action = actions.get(choice)
        if action:
            action()
        else:
            print("Invalid choice, Please try again.")
            continue
        # Second phase testing.
        #    case "5":
        #        print("Thread object:", threading.Thread)

# Launch script for modularizing
def launch():
    # noinspection PyBroadException
    try:
        main()
    except Exception as e:
        logging.exception(f"FATAL: Unexpected crash in main execution: {e}")
        print(colorama.Fore.RED + "\nAn unexpected error occurred. Please check the log file for details.\n" + colorama.Style.RESET_ALL)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit()

# Run the program
if __name__ == "__main__":
    launch()