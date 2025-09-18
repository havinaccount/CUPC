import json
import os

# File to store user data
USER_FILE = "users.json"

# Load existing users from file
def load_users():
    if os.path.exists(USER_FILE):
        try:
            with open(USER_FILE, 'r') as file:
                return json.load(file)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    return {}

# Save users to file
def save_users(users_dict):
    with open(USER_FILE, 'w') as file:
        json.dump(users_dict, file)

# Sign up function
def sign_up():
    print("\n=== SIGN UP ===")
    users = load_users()
    
    while True:
        username = input("Choose a username: ")
        
        # Check if username already exists
        if username in users:
            print("Username already exists. Please choose a different one.")
            continue
            
        while True:
            password = input("Choose a PIN (numbers only): ")
            
            if password.isdigit():
                # Store the user with their PIN
                users[username] = int(password)
                save_users(users)
                print("Account created successfully!")
                return True
            else:
                print("PIN must contain only numbers. Please try again.")

# Modified login function
def login():
    print("\n=== LOGIN ===")
    users = load_users()
    
    # Check if there are any users
    if not users:
        print("No users registered. Please sign up first.")
        return False
    
    while True:
        username = input("Username: ")
        password = input("PIN: ")
        
        # Check if username exists
        if username not in users:
            print("Username not found. Please try again.")
            continue
            
        # Check if password is correct
        if password.isdigit() and users[username] == int(password):
            print("Login successful!")
            return True
        else:
            print("Incorrect PIN. Please try again.")

# Main program
def main():
    while True:
        print("\n1. Sign Up")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Choose an option (1-3): ")
        
        if choice == "1":
            sign_up()
        elif choice == "2":
            if login():
                # Add your post-login code here
                print("Welcome! You are now logged in.")
                break
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

# Run the program
if __name__ == "__main__":
    main()