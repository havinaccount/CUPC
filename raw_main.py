try:
    import getpass
    import logging
    import shutil
    import sys
    import threading
    import time
    import unicodedata
    from datetime import datetime
    from functools import lru_cache
    from pathlib import Path
    from random import randint
    from typing import Any, Callable, Final, NoReturn, Optional, Union

    import bcrypt
    import colorama
    import numpy as np
    import orjson
    from blake3 import blake3
except ModuleNotFoundError as e:
    print(f"One of the programs modules not found: {e}")
    raise
except ImportError as e:
    print(f"Failed to import modules: {e}")
    raise


logging.basicConfig(
    filename="ex.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(funcName)s - Line %(lineno)d - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


@lru_cache(maxsize=128)
def normalize_username(username: str) -> Optional[str]:
    if isinstance(username, bool):
        return None
    if not isinstance(username, str):
        raise ValueError("Username must be a string")
    return unicodedata.normalize("NFKC", username.strip())


BASE_DIR: Path = Path.cwd()
USER_FILE: Path = BASE_DIR / "users.json"
USER_HASH: Path = BASE_DIR / "users.hash"


MAX_ATTEMPTS: Final[int] = 5
attempts: int = 0
delay: Callable[[int], int] = lambda attempt: 2**attempt
users_cache: Union[dict, None] = None
USER_FILE_LOCK: Final[threading.RLock] = threading.RLock()
ADMIN_USER: Final[Optional[str]] = normalize_username("admin")

print(f"Using USER_FILE at : {USER_FILE}")
print(f"Exists: {USER_FILE.exists()}")

EXP: Final[str] = "Current datetime is:"
win_date: str = current_timestamp()


def recreate_user() -> bool:
    """
    The function `recreate_user` attempts to recreate a user file by writing an empty list in binary
    format, handling exceptions and logging errors if necessary.
    :return: The function `recreate_user()` is returning a boolean value. If the operation is
    successful, it returns `True`. If there is an exception during the operation, it returns `False`.
    """
    try:
        empty_list: bytes = b"{}"
        u_f = USER_FILE
        with open(u_f, "wb") as file:
            file.write(empty_list)
        return True
    except orjson.JSONDecodeError as e:
        print(
            colorama.Fore.RED
            + "FATAL: USER_FILE is corrupted"
            + colorama.Style.RESET_ALL
        )
        logging.warning(f"Failed to recreate user file: {e}")
        return False
    except FileNotFoundError as e:
        print(
            colorama.Fore.RED
            + "FATAL: USER_FILE is not found"
            + colorama.Style.RESET_ALL
        )
        logging.error(f"Failed to find user file: {e}")
        return False


def load_users() -> dict:
    """
    The `load_users` function loads user data from a file, handles file integrity checks, and returns
    the cached user data.
    :return: The function `load_users()` returns the `users_cache` after loading the user data from a
    file. If the user cache is already loaded, it returns the cached users. If the user file is not
    found or corrupted, it resets the user data and returns an empty user cache. If there are any errors
    during the loading process, it also returns an empty user cache.
    """
    global users_cache

    if users_cache is not None:
        return users_cache

    lock = USER_FILE_LOCK
    user_file = USER_FILE
    file_exists: bool = user_file.exists()
    tamp_path: Path = user_file.with_name(USER_FILE.name + ".tamp")

    if users_cache:
        if not verify_user_file_integrity():
            logging.error(
                colorama.Fore.RED
                + "FATAL: User file integrity tampered"
                + colorama.Style.RESET_ALL
            )
            print("Warning: User file integrity is tampered. Resetting users.")
            with lock:
                if tamp_path.exists():
                    tamp_path.unlink()
                if file_exists:
                    user_file.rename(tamp_path)
                else:
                    logging.error(f"Cannot rename missing file: {user_file}")
                success: bool = recreate_user()
                if not success:
                    print(
                        colorama.Fore.RED
                        + "FATAL: Reset unsuccessful."
                        + colorama.Style.RESET_ALL
                    )
                    sys.exit(1)
            users_cache = {}
            return users_cache
    else:
        print("First initialization, Getting user file ready.\n\n")

    if not file_exists:
        logging.warning("User file not found, starting with empty user list.")
        with lock:
            success = recreate_user()
        if not success:
            print(
                colorama.Fore.RED
                + "FATAL: Reset unsuccessful"
                + colorama.Style.RESET_ALL
            )
            sys.exit(1)
        users_cache = {}
        return users_cache

    try:
        with (
            lock,
            open(USER_FILE, "rb") as file,
        ):
            raw_data: bytes = file.read()
            temp_cache: dict[Any, Any] = orjson.loads(raw_data)
            if not isinstance(temp_cache, dict):
                raise ValueError(
                    colorama.Fore.RED
                    + f"FATAL: User file corrupted: expected dict, got {type(temp_cache)}"
                    + colorama.Style.RESET_ALL
                )
            users_cache = temp_cache
            logging.info("User file loaded successfully.")
    except orjson.JSONDecodeError as e:
        logging.error(f"User file is corrupted: {e}\n\n Starting with empty user list.")
        print(
            colorama.Fore.YELLOW
            + "Warning: User data file was corrupted, All accounts have been removed."
            + colorama.Style.RESET_ALL
        )
        try:
            with lock:
                if file_exists:
                    user_file.rename(user_file.with_name(user_file.name + ".corrupted"))
                    logging.info(
                        f"Corrupted user file backed up as '{user_file}.corrupted'"
                    )
        except Exception as e:
            logging.error(f"Failed to backup corrupted user file: {e}")
        finally:
            users_cache = {}
    except Exception as e:
        logging.error(f"Failed to load user file {e}")
        print(
            colorama.Fore.RED
            + "FATAL: System error, Starting with empty user list."
            + colorama.Style.RESET_ALL
        )
        users_cache = {}

    if not users_cache:
        logging.warning("User cache is empty after load.")

    return users_cache


def validate_users_dict(users_dict: dict) -> bool:
    """
    The code snippet includes a function to validate a dictionary of users and another function to save
    the users to a file, with error handling for invalid user data format.

    :param users_dict: The `users_dict` parameter is expected to be a dictionary where the keys are
    usernames (strings) and the values are hashed passwords (strings).
    The `validate_users_dict`
    function checks if the input dictionary has the correct format by ensuring that it is indeed a
    dictionary and that both the keys (user
    """
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


def save_users(users_dict: dict) -> Union[bool, None]:
    """
    The `save_users` function takes a dictionary of user data, validates it, creates a backup of
    existing user data, saves the new user data to a file, and hashes the data for integrity
    verification.

    :param users_dict: The `save_users` function takes a dictionary `users_dict` as input, which
    contains user data to be saved. The function first validates the format of the user data in the
    dictionary. If the data format is invalid, it raises a `ValueError`
    :return: The `save_users` function returns a boolean value (`True` or `False`). It returns `True` if
    the user data is successfully saved and hashed, and it returns `False` if there is an error during
    the process of saving or hashing the user data.
    """
    if not validate_users_dict(users_dict):
        raise ValueError("Invalid user data format")

    lock = USER_FILE_LOCK
    file_exists = USER_FILE.exists()
    u_f = USER_FILE

    try:
        if file_exists:
            backup_path: Union[str, Path] = u_f.with_name(f"{u_f.stem}.{win_date}.bak")
            shutil.copy(u_f, backup_path)
            logging.info(f"Successfully backed up {u_f} at {win_date}")
    except shutil.ReadError as e:
        logging.exception(f"Unexpected error when backing up user file: {e}")
        raise
    except FileNotFoundError as e:
        logging.exception(f"User file not found while trying to backup: {e}")
        raise

    try:
        serialized_data: bytes = orjson.dumps(users_dict)
        with lock, open(u_f, "wb") as file:
            file.write(serialized_data)
        logging.info("User data saved.")
    except Exception as e:
        print(
            colorama.Fore.RED
            + "FATAL: Error saving user data. Please try again."
            + colorama.Style.RESET_ALL
        )
        logging.error(f"Failed to save user data: {e}")
        return False

    u_h = USER_HASH
    try:
        hasher_value: str = blake3(serialized_data).hexdigest()
        with open(u_h, "wb") as hasher_file:
            hasher_file.write(hasher_value.encode("utf-8"))
        logging.info(f"User file hashed successfully {hasher_value}")
    except Exception as e:
        print(
            colorama.Fore.RED
            + "FATAL: Error saving user data. Please try again."
            + colorama.Style.RESET_ALL
        )
        logging.error(f"Failed to save user data or hash: {e}")
        return False

    return True


def sign_up() -> Optional[bool]:

    print("\n=== SIGN UP ===")
    users: dict[Any, Any] = load_users()

    while True:

        username: Union[str, bool, None] = normalize_username(
            safe_input("Choose a username: ", strip=True)
        )

        logging.info(f"Sign-up attempt for username: {username}")

        if username is None:
            print("Nothing entered, Please try again.")
            continue

        if username in users:
            print("Username already exists. Please choose a different one.")
            logging.warning(f"Sign-up failed: Username '{username}' already exists.")
            continue

        if not username:
            print("Username cannot be empty or spaces, Please try again.")
            logging.warning("Sign-up failed: Empty username entered.")
            continue

        if not isinstance(username, str):
            print("Invalid PIN Input.")
            return False

        if len(username) < 4:
            print("Please choose a longer username.")
            logging.warning("Entered username has less the 4 characters.")
            continue

        if username.lower() == "admin":
            print("Username admin is reserved")
            logging.warning("A User tried to sign-up as admin.")
            continue

        password: Union[str, bool, None] = safe_getpass(
            "Choose a PIN (numbers only, Pass is hidden): "
        )

        if password is None:
            print("Nothing Entered, Please try again.")
            continue

        if not isinstance(password, str):
            print("Invalid password Input.")
            return False

        if not password.isdigit():
            print("PIN must contain only digits. Please try again.")
            logging.warning("Sign-up failed: Non-digit pin detected.")
            continue

        if len(password) < 4:
            print("Password must contain 4 digits.")
            continue

        confirm: Union[str, bool, None] = safe_getpass("Confirm your PIN: ")

        if not isinstance(confirm, str):
            print("Invalid PIN Input.")
            return False

        if confirm is None:
            print("Nothing Entered, Please try again.")
            continue

        if confirm != password:
            print("PINs do not match, Please try again.")
            continue
        if isinstance(password, str):
            success: bool = hash_pass(username, password)
            if success:
                print("Account created successfully!")
            else:
                print("Account creation failed.")
        else:
            return False

        logging.info(f"New user '{username}' registered.")
        return True


def safe_getpass(
    string: str = "Enter Password: ", strip: bool = True
) -> Union[str, bool, None]:
    """
    The function `safe_getpass` securely prompts the user for a password input, handling exceptions and
    optionally stripping whitespace.

    :param string: The `string` parameter in the `safe_getpass` function is a string type that
    represents the prompt message displayed to the user when requesting input for the password
    :type string: str
    :param strip: The `strip` parameter in the `safe_getpass` function is a boolean parameter that
    determines whether to strip leading and trailing whitespaces from the password input before
    returning it. If `strip` is set to `True`, the leading and trailing whitespaces will be removed from
    the password input, defaults to True
    :type strip: bool (optional)
    :return: The function `safe_getpass` returns a string if successful, `None` if the input is empty,
    `False` if an exception occurs during execution.
    """
    try:
        value: str = getpass.getpass(string)
        if not value:
            return None
        return value.strip() if strip else value
    except Exception as e:
        print("Exiting or error.")
        logging.error(f"Password interception: {e}")
        return False


def _set_user_secret(username: str, secret: str, label: str) -> bool:
    """
    The function `_set_user_secret` takes a username, secret, and label, hashes the secret using bcrypt,
    updates the user's secret in the database, and logs the result.

    :param username: The `username` parameter is a string that represents the username of the user for
    whom the secret is being set
    :type username: str
    :param secret: The `secret` parameter in the `_set_user_secret` function is the user's secret
    information that will be hashed and stored securely in the system. It is the sensitive information
    that the user wants to keep confidential, such as a password or any other secret data
    :type secret: str
    :param label: The `label` parameter in the `_set_user_secret` function is used to specify the
    purpose or type of secret being set for a user. It is a descriptive label that helps in logging and
    identifying the specific action being performed on the user's secret
    :type label: str
    :return: The function `_set_user_secret` is returning a boolean value. It returns `True` if the
    user's secret is successfully set and saved, and it returns `False` if there is an exception or
    error during the process.
    """
    try:
        users: dict[Any, Any] = load_users()
        hashed: bytes = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt(rounds=12))
        users[username] = hashed.decode("utf-8")
        save_users(users)
        logging.info(f"{username} {label} updated successfully.")
        return True
    except Exception as e:
        logging.error(f"Failed to set {label} for {username}: {e}")
        return False


def hash_pass(username: str, password: str | None) -> bool:
    """
    The function `hash_pass` takes a username and password as input, logs an error if the password is
    not a string, and then sets the user's password as a secret using `_set_user_secret`.

    :param username: The `username` parameter is a string that represents the username of a user
    :type username: str
    :param password: The `password` parameter in the `hash_pass` function is expected to be a string. If
    it is not a string, an error message will be logged, and the function will return `False`. The
    function then calls `_set_user_secret` function with the `username`, `password`, and
    :type password: str | None
    :return: The function `hash_pass` is returning a boolean value. It returns `True` if the password is
    a string and the `_set_user_secret` function is successfully called with the provided username,
    password, and secret type "Password". If the password is not a string, it logs an error message and
    returns `False`.
    """
    if not isinstance(password, str):
        logging.error(f"Expected password as str, got {type(password)}")
        return False
    return _set_user_secret(username, password, "Password")


def hash_new_pin(username: str, new_pin: str) -> bool:
    """
    The function `hash_new_pin` sets a new PIN for a user and returns a boolean value based on the
    success of the operation.

    :param username: The `username` parameter is a string that represents the user's username
    :type username: str
    :param new_pin: The `new_pin` parameter is expected to be a string containing the new PIN that the
    user wants to set
    :type new_pin: str
    :return: The function `hash_new_pin` is returning a boolean value. If the `new_pin` parameter is not
    a string, the function logs an error message and returns `False`. Otherwise, it calls a private
    function `_set_user_secret` with the `username`, `new_pin`, and a string "PIN", but the result of
    this call is not shown in the provided code snippet.
    """
    if not isinstance(new_pin, str):
        logging.error(f"Expected new_pin as str, got {type(new_pin)}")
        return False
    return _set_user_secret(username, new_pin, "PIN")


def hash_admin_pin(password: str) -> bool:
    """
    The function `hash_admin_pin` sets the admin PIN using the provided password and returns a boolean
    indicating whether the operation was successful.

    :param password: The `password` parameter in the `hash_admin_pin` function is a string that
    represents the password that will be used to set the admin PIN
    :type password: str
    :return: The function `hash_admin_pin` is returning a boolean value. It returns `True` if the
    `_set_user_secret` function was successful in setting the admin PIN with the provided password, and
    `False` otherwise.
    """
    a_d = ADMIN_USER
    if a_d is None:
        print("ADMIN_USER is not set.")
        logging.error(f"Expected ADMIN_USER as str, got {type(a_d)}")
        return False
    if password is None:
        raise ValueError(f"Expected password as str, got {type(password)}")
    success: bool = _set_user_secret(a_d, password, "admin PIN")
    if success:
        print("Admin PIN set successfully.")
    else:
        print(
            colorama.Fore.RED
            + "FATAL: New PIN registration unsuccessful"
            + colorama.Style.RESET_ALL
        )
    return success


def verify_user_file_integrity() -> bool:
    """
    The function `verify_user_file_integrity` checks the integrity of a user file by computing its hash
    and comparing it to a stored hash.
    :return: The `verify_user_file_integrity()` function returns a boolean value. It returns `True` if
    the hash of the `USER_FILE` matches the stored hash in the `USER_HASH` file, indicating that the
    file integrity is intact. If there is a file missing or an exception occurs during the integrity
    check process, it returns `False`.
    """
    lock = USER_FILE_LOCK
    try:

        with lock, open(USER_FILE, "rb") as file:
            hasher: blake3 = blake3()
            for chunk in iter(lambda: file.read(8192), b""):
                hasher.update(chunk)
            current_hash: str = hasher.hexdigest()

        u_h = USER_HASH
        with open(u_h, "r", encoding="utf-8") as hasher_file:
            stored_hash: str = hasher_file.read().strip()

        return current_hash == stored_hash
    except FileNotFoundError as e:
        logging.warning(f"Integrity check failed, missing file: {e.filename}")
        return False
    except Exception as e:
        logging.warning(f"Integrity check failed: {e}")
        return False


def safe_input(
    prompt: str = "Enter an input: ",
    strip: bool = True,
    lower: bool = False,
    upper: bool = False,
) -> Union[str, bool, None]:
    """
    The `safe_input` function in Python takes user input with optional stripping, lowercasing, or
    uppercasing, and handles exceptions like KeyboardInterrupt and EOFError.

    :param prompt: The `prompt` parameter in the `safe_input` function is a string that represents the
    message or question displayed to the user when requesting input. It serves as a prompt to guide the
    user on what input is expected from them
    :type prompt: str
    :param strip: The `strip` parameter in the `safe_input` function is a boolean flag that determines
    whether leading and trailing whitespaces should be removed from the user input. If `strip` is set to
    `True`, the input will be stripped of any leading or trailing whitespaces before further processing.
    If `, defaults to True
    :type strip: bool (optional)
    :param lower: The `lower` parameter in the `safe_input` function is a boolean flag that, when set to
    `True`, converts the input string to lowercase before returning it. This means that if `lower` is
    `True`, any alphabetic characters in the input will be converted to lowercase. If `, defaults to
    False
    :type lower: bool (optional)
    :param upper: The `upper` parameter in the `safe_input` function is a boolean flag that, when set to
    `True`, converts the input string to uppercase before returning it. This means that if `upper` is
    `True`, the input string will be transformed to all uppercase characters, defaults to False
    :type upper: bool (optional)
    :return: The function `safe_input` returns a string if input is successfully read and processed
    according to the specified conditions. It returns `None` if the input is empty after processing, and
    it returns `False` if there is an `EOFError` or `KeyboardInterrupt` during input reading.
    """
    try:
        value: str = input(prompt)
        if strip:
            value = value.strip()
        if lower:
            value = value.lower()
        elif upper:
            value = value.upper()
        if lower and upper:
            raise ValueError(
                colorama.Fore.YELLOW
                + "Warning: Can't apply both lower and upper case transformations."
                + colorama.Style.RESET_ALL
            )
        return None if not value else value
    except (KeyboardInterrupt, EOFError):
        print("\n\nInput stream closed. Cannot read input.\n")
        logging.error(f"EOFError: Input failed")
        return False


def login() -> bool:
    """
    The `login` function in Python handles user authentication by verifying credentials and allowing
    access to either the admin panel or user panel based on the input.
    :return: The `login()` function returns a boolean value. It returns `True` if the login is
    successful and either the user panel or admin panel is launched based on the username. It returns
    `False` in various scenarios such as no users registered, invalid credentials, empty username
    inputs, incorrect password, or when the maximum login attempts are reached.
    """
    print("\n=== LOGIN ===")
    users: dict[Any, Any] = load_users()

    if not users:
        print("No users registered. Please sign up first.")
        return False

    username: Union[str, bool, None] = normalize_username(
        safe_input("Username: ", strip=True)
    )

    if not isinstance(username, str):
        print("Invalid username Input.")
        return False

    if username is None:
        print("Nothing entered, Please try again later.")
        return False

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
        return False

    dummy_hash: bytes = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=4))
    stored_hash: Any = users.get(username, dummy_hash)

    if isinstance(stored_hash, str):
        try:
            stored_hash = stored_hash.encode()
        except Exception as e:
            logging.error(f"Failed to encode stored hash for '{username}': {e}")
            print(
                colorama.Fore.RED
                + "FATAL: Unexpected error occurred. Please contact support."
                + colorama.Style.RESET_ALL
            )
            return False

    attempt: int = 0

    while attempt < MAX_ATTEMPTS:

        password: Union[str, bool, None] = safe_getpass("PIN (Pass is hidden): ")

        if password is None:
            print("Login cancelled.")
            return False

        if not password:
            print("Aborting Password.")
            time.sleep(2)
            return False

        if not isinstance(password, str):
            print("Invalid password Input.")
            return False

        if not password.isdigit():
            print("PIN must contain only digits.")
            logging.warning("Login attempt failed: Non-digit PIN entered.")
            continue

        if len(password) < 4:
            print("Password must contain 4 digits.")
            continue

        if bcrypt.checkpw(password.encode(), stored_hash):
            logging.info(f"User '{username}' logged in successfully.")

            if username == "admin":
                logging.info("Admin panel executed.")
                admin_panel()
                return True
            if isinstance(username, str):
                user_panel(username)
                return True
            else:
                return False
        else:
            print("\nPassword is incorrect, Please try again\n")
            attempt += 1
            time.sleep(delay(attempt))

    print("Maximum login attempts reached.")
    return False


def exits() -> bool:
    """
    The function `exits` logs a message indicating that the user has successfully logged out and returns
    `True`.
    :return: The function `exits()` is returning the boolean value `True`.
    """
    logging.info("User successfully logged out.")
    return True


def user_panel(username: str) -> bool | None:
    """
    The function `user_panel` takes a username as input, displays a menu of actions for the user to
    choose from, and executes the corresponding action based on the user's choice until the user decides
    to exit.

    :param username: The `username` parameter is a string representing the username of the user who has
    logged in to the user panel. This username is used to personalize the user's experience within the
    panel by performing actions such as calculations, changing PIN, playing games, and exiting the panel
    :return: The `user_panel` function returns a boolean value or None.
    """
    print("Login successful!")

    actions = {
        "1": lambda: calc(username),
        "2": lambda: (
            print("PIN changed successfully!")
            if change_pin(username)
            else print("PIN change failed.")
        ),
        "3": lambda: guess_game(username),
        "4": exits,
    }

    while True:
        print(
            "\n1. Calculation", "\n2. Change PIN", "\n3. Guess the Number", "\n4. Exit"
        )

        choice: Union[str, bool, None] = safe_input(
            "Please select a number: ", strip=True
        )

        if not choice:
            print("Nothing entered, Please try again.")
            continue

        if not isinstance(choice, str):
            print("You have to enter a string.")
            return False
        else:
            action: Union[Optional[Callable[[], Any]], None] = actions.get(choice)
            if action:
                action()
            else:
                print("Invalid choice, Please try again.")
                continue
        if exits():
            return True


def change_pin(username: str) -> Union[bool, None]:
    """
    The `change_pin` function in Python allows a user to change their PIN securely by verifying the new
    PIN and updating it in the user data.

    :param username: The `change_pin` function you provided seems to be a part of a program that allows
    users to change their PIN. It loads user data, prompts the user to enter a new PIN, verifies the
    PIN, and then changes the PIN if all conditions are met
    :return: The `change_pin` function is returning the result of the `hash_new_pin(username, new_pin)`
    function call if all the conditions are met successfully.
    """
    try:
        users: dict[Any, Any] = load_users()
    except (orjson.JSONDecodeError, FileNotFoundError):
        print("User file not found")
        return False

    logging.info(f"{username} requests a PIN change.")

    while True:

        new_pin: Union[str, bool, None] = safe_getpass("Enter new PIN: ")

        if not isinstance(new_pin, str):
            return False

        if len(new_pin) < 4:
            print("PIN must be 4 digits or higher.")
            continue

        confirm: Union[str, bool, None] = safe_getpass("Confirm your following PIN: ")

        if confirm != new_pin:
            print("PINs do not match, Please try again.")
            continue

        if username not in users:
            print("User not found.")
            logging.warning(f"PIN change failed: {username} not found")
        if not isinstance(new_pin, str):
            print("Invalid PIN Input")
            return False
        if not new_pin.isdigit():
            print("Password must contain only digits.")
            return False

        return hash_new_pin(username, new_pin)


def admin_panel(username: str = "admin") -> bool:
    """_summary_

    Args:
        username (str, optional): _description_. Defaults to "admin".

    Returns:
        bool: True when admin panel exits successfully.
    """
    print("Welcome Admin.")
    logging.info("Admin panel accessed.")

    global users_cache

    try:
        while True:
            print(
                "\n1. Reset user file",
                "\n2. List of users",
                "\n3. User Panel",
                "\n4. Logout",
            )

            choice: Union[str, bool, None] = safe_input(
                "Choose an option: ", strip=True
            )

            u_f: Path = USER_FILE
            lock = USER_FILE_LOCK
            object_hash: Path = USER_HASH

            match choice:
                case "1":
                    if not u_f.exists():
                        logging.warning(
                            "Admin tried to reset user file, but it was not found."
                        )
                        print(
                            colorama.Fore.YELLOW
                            + "Warning: User file not found."
                            + colorama.Style.RESET_ALL
                        )
                        continue

                    try:
                        u_f.unlink()
                        with lock:
                            success: bool = recreate_user()
                        if success:
                            print("'users.json' has been reset.")
                            users_cache = {}
                            logging.info(
                                f"Admin reset user file at {current_timestamp()}"
                            )
                        if not object_hash.exists():
                            print(
                                colorama.Fore.RED
                                + "Hash file not available."
                                + colorama.Fore.RED
                            )
                            return False

                        with lock:
                            object_hash.unlink()
                            print("user.hash successfully deleted.")
                            logging.info("Both user file and user hash were reset")

                    except Exception as e:
                        print(
                            colorama.Fore.RED
                            + "FATAL: User file reset failed. Exiting program."
                            + colorama.Style.RESET_ALL
                        )
                        logging.error(str(e))
                        sys.exit(1)
                case "4":
                    print("Goodbye!")
                    logging.info("Admin Exited Panel")
                    break
                case "2":
                    print("\nRegistered Users:")
                    try:
                        users: dict[Any, Any] = (
                            users_cache if users_cache else load_users()
                        )
                        if not users:
                            print("No users found.")
                            logging.warning(
                                "User file isn't available for admin or empty."
                            )
                            continue
                        print("\n".join(f"   - {user}" for user in users))
                    except orjson.JSONDecodeError:
                        print(
                            colorama.Fore.RED
                            + "FATAL: User file corrupted."
                            + colorama.Style.RESET_ALL
                        )
                        logging.warning("User file corrupted.")
                        continue
                case "3":
                    user_panel(username)
                case _:
                    print("Invalid choice.")
                    logging.warning("Wrong choice made, repeating process.")
                    continue
    except Exception as e:
        logging.error(f"Admin panel failed: {e}")
        return False

    return True


def hidden_function() -> bool | None:
    """Sets up or updates the admin PIN securely."""
    users: dict[Any, Any] = load_users()
    print("\n===ADMIN SETUP===")

    try:
        while True:
            password: Union[str, bool, None] = safe_getpass(
                "Enter new admin PIN (Pass is hidden): "
            )

            if not isinstance(password, str) or not password:
                print("Invalid input. Please try again.")
                continue

            if not password:
                print("Input error. Aborting.")
                return False

            if password is None:
                print("Nothing Entered, Please try again")
                continue

            if not password.isdigit():
                print("PIN must contain only digits.")
                continue

            if len(password) < 4:
                print("Password must be at least 4 digits.")
                continue

            confirm: Union[str, bool, None] = safe_getpass("Confirm your PIN: ")
            if confirm != password:
                print("Passwords do not match. Please try again.")
                continue

            if "admin" not in users:
                if hash_admin_pin(password):
                    logging.info("Admin PIN created.")
                    return True
                print("Admin PIN creation failed.")
                return False

            choice: Union[str, bool, None] = safe_input(
                "Admin PIN already exists. Overwrite? (y/n): ", lower=True, strip=True
            )
            if choice == "n":
                print("Admin Setup cancelled.")
                return False
            if choice != "y":
                print("Invalid choice. Please try again.")
                continue

            check: Union[str, bool, None] = safe_getpass(
                "Please enter admin's previous PIN: "
            )
            stored_hash: Any = users.get("admin")
            if not stored_hash:
                print("Stored hash is damaged or empty")
                return False
            if not isinstance(check, str) or not isinstance(stored_hash, str):
                raise ValueError(
                    f"Invalid input or stored hash format. Got {type(check)} and {type(stored_hash)}"
                )

            if not bcrypt.checkpw(check.encode(), stored_hash.encode()):
                print("Incorrect previous PIN. Setup aborted.")
                return False

            if hash_admin_pin(password):
                print("Admin PIN overwritten successfully.")
                logging.info("Admin PIN overwritten.")
                return True

            print("Admin PIN overwrite failed.")
            return False

    except Exception as e:
        logging.error(f"Admin setup failed: {e}")
        return False


def get_input(prompt: str) -> Union[str, bool, None]:
    try:
        while True:
            value: str = input(prompt).strip()
            return value if value else None
    except (KeyboardInterrupt, EOFError):
        print("\n\nInput stream closed. Cannot read input.\n")
        logging.error(f"EOFError: Input failed")
        return False


def calc(username: str) -> None | bool:
    """A Simple, interactive calculator"""
    print(f"Welcome {username}")
    logging.info(f"User {username} accessed calculator.")
    while True:
        try:
            raw_input: list[str] = []

            while True:
                user_input: Union[str, bool, None] = get_input(
                    "\nEnter numbers one by one (Type 'done' when finished): "
                )
                if user_input is None:
                    print("Nothing entered, Please try again.")
                    continue
                if user_input == False:
                    print("Aborting Calculator")
                    return None

                if not isinstance(user_input, str):
                    return False
                else:
                    normalized: str = user_input.lower().strip()

                if normalized == "done":
                    break

                raw_input.append(user_input)

            try:
                numbers: list[float] = [float(x) for x in raw_input]

                arr: np.ndarray = np.round(np.array(numbers, dtype=np.float64), 6)
            except ValueError:
                print("One or multiple numbers were invalid")
                return False

            if not numbers:
                print("No numbers entered")
                return None

            print(f"Numbers entered: {arr}")

            print(f"\nMultiplication = {multiplication(arr)}")
            if len(numbers) == 2:
                print(f"Remainder = {remainder(numbers)}")
            else:
                print("For remainder, You need enter two numbers only.")
            print(f"Average = {average(arr)}")
            print(f"Addition = {addition(arr)}")
            print(f"Subtraction = {subtraction(arr)}")

            again: Union[str, bool, None] = safe_input(
                "\nDo you want to recalculate again? (y/n): \n", lower=True, strip=True
            )

            if again is None:
                print("Nothing entered, Please try again later.")
                return None

            if not isinstance(again, str):
                return False

            if again.lower().strip() != "y":
                break
        except Exception as e:
            print(
                colorama.Fore.RED
                + "FATAL: An error occurred. Please try again."
                + colorama.Style.RESET_ALL
            )
            logging.error(f"Calculation failed: {e}")
            return None

    return True


def remainder(arr: list[float] | np.ndarray) -> float:
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
    if len(arr) != 2:
        raise ValueError(
            colorama.Fore.YELLOW
            + "Warning: Input list must be a list of two float numbers."
            + colorama.Style.RESET_ALL
        )
    if arr[1] == 0:
        raise ValueError(
            colorama.Fore.RED
            + "FATAL: Cannot divide by zero"
            + colorama.Style.RESET_ALL
        )
    x, y = arr
    return np.remainder(x, y)


def average(arr: list[float] | np.ndarray) -> float:
    """This python function calculates the average of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `mean`
    :type arr: np.ndarray:
    :return: The function `average` is returning the average of `arr` using the NumPy's `mean` function.
    """
    return float(np.round(np.mean(arr), 3))


def addition(arr: list[float] | np.ndarray) -> float:
    """This python function calculates the addition of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `sum`
    :type arr: np.ndarray:
    :return: The function `addition` is returning the average of `arr` using the NumPy's `sum` function.
    """
    return float(np.round(np.sum(arr), 2))


def subtraction(arr: list[float] | np.ndarray) -> float:
    """This python function calculates the average of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `subtract.reduce()`
    :type arr: np.ndarray:
    :return: The function `subtraction` is returning the average of `arr` using the NumPy's `subtract.reduce()` function.
    """
    return float(np.round(np.subtract.reduce(arr), 2))


def multiplication(arr: list[float] | np.ndarray) -> float:
    """This python function calculates the average of numbers

    :param arr: The `arr` parameter is expected to be list of multiple float numbers using the NumPy's `prod`
    :type arr: np.ndarray:
    :return: The function `multiplication` is returning the average of `arr` using the NumPy's `prod` function.
    """
    return float(np.round(np.prod(arr), 3))


def guess_game(username: str) -> None:
    """_summary_

    Args:
        username (str): Gets a username for logging

    Returns:
        None: Returns nothing since it's an essential calculator
    """
    max_a: Final[int] = 5
    attempt = 0
    target: Final[int] = randint(1, 20)
    logging.info(f"{username} Playing game.")

    try:
        while True:

            raw_guess: Union[str, bool, None] = safe_input(
                "Guess a number (1-20): ", strip=True
            )

            if not raw_guess:
                print("Aborting game.")
                break

            if raw_guess is not None:
                pass
            else:
                print("Your guess could not be empty, Pick a number.")
                continue

            if isinstance(raw_guess, str):
                try:
                    guess: int = int(raw_guess)
                except ValueError:
                    print(
                        colorama.Fore.YELLOW
                        + "Warning: You should guess a number."
                        + colorama.Style.RESET_ALL
                    )
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
                print(f"Pick a higher number, Attempts remaining {max_a - attempt}")
            elif guess > target:
                attempt += 1
                print(
                    f"You should pick a smaller number. Attempts remaining {max_a - attempt}"
                )

            if attempt == 5:
                print(f"You lost {username}, The number was {target}")
                logging.info(f"{username} Lost the game after {max_a}")
                break
    except Exception as e:
        logging.error(f"Game failed: {e}")
    except KeyboardInterrupt:
        return None


def warm_up_terminal() -> None:

    try:
        getpass.getpass(
            prompt=colorama.Fore.YELLOW
            + "\nPress enter to continue...\n"
            + colorama.Style.RESET_ALL
        )
    except Exception:
        pass


def start_signup() -> None:
    print("Starting sign-up")
    time.sleep(0.5)
    sign_up()


def start_login() -> None:
    print("Starting Login")
    time.sleep(0.5)
    login()


def main() -> Optional[bool]:
    """
    The main function in the Python code handles user input for sign-up, login, and exit options, with
    error handling and logging implemented.
    :return: In the `main()` function, if an `EOFError` occurs while trying to read , the program
    will log an error message and then return from the function.
    """
    logging.info("\nProgram started.")

    warm_up_terminal()
    print(EXP, current_timestamp())

    actions: dict[str, Callable[[], Union[None, NoReturn, bool]]] = {
        "1": start_signup,
        "2": start_login,
        "3": lambda: (print("\nExiting\n") or sys.exit()),
        "9783": lambda: hidden_function(),
    }

    while True:
        print("\n1. Sign-up", "\n2. Login", "\n3. Exit")

        choice: Union[str, bool, None] = safe_input(
            "Choose an option (1-3): ", strip=True
        )

        if choice is None:
            print("No input received")
            return None

        if not isinstance(choice, str):
            print("You have to enter a string.")
            return False

        action = actions.get(choice)
        if action:
            action()
        else:
            print("Invalid choice, Please try again.")
        continue


def launch():
    """
    The `launch` function attempts to execute the `main` function, handling any exceptions that may
    occur and providing appropriate messages before exiting the program.
    """

    try:
        main()
    except Exception as e:
        logging.exception(f"FATAL: Unexpected crash in main execution: {e}")
        print(
            colorama.Fore.RED
            + "\nAn unexpected error occurred. Please check the log file for details.\n"
            + colorama.Style.RESET_ALL
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit()


if __name__ == "__main__":
    launch()
