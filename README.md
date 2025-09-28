# CUPC
CUPC – Constant Username and Password Checking
CUPC is a simple Python-based password checker that allows users to sign up and log in using a numeric PIN. It demonstrates basic user authentication, password hashing with bcrypt, and includes a built-in calculator for logged-in users.
 
> [!CAUTION] 
> This project is for educational purposes only. It is not secure against brute-force attacks or suitable for production use.

# Features
- User sign-up with PIN validation

- Secure password hashing using bcrypt

- Login system with basic access control

- Admin panel for file deletion

- Hidden admin setup trigger

- Simple calculator for logged-in users

## Getting Started
Requirements
Python 3.8+

`bcrypt`

`ujson` (optional for performance)

## Installation

```
pip install bcrypt ujson
```
## Run the App
```
python main.py
```
## PyInstaller Build (Optional) (Prebuilt)
To compile into a standalone executable:
```
pyinstaller main.py --onefile --optimize=2 --clean --noupx
```
Do not use `--strip` because modules aren't compiled with it.
### Security Notes
- PINs are hashed, but the app does not limit login attempts.

- No encryption or secure storage beyond basic hashing.

- Avoid using real credentials.

### Hidden Admin Setup
To set an admin PIN, run the app and enter 9783 at the main menu.

### File Structure
```
├── main.py
├── users.json
├── README.md
```
### License
This project is released under the MIT License. See `LICENSE` for details.
