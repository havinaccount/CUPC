# CUPC
CUPC – Constant Username and Password Checking
CUPC is a simple Python-based password checker that allows users to sign up and log in using a numeric PIN. It demonstrates basic user authentication, password hashing with `bcrypt`, and includes a built-in calculator for logged-in users.
 
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

`orjson` (optional for performance)

`getpass4`

`numpy` (For Fast calculations)

`blake3`

## Installation

```
pip install bcrypt orjson numpy blake3 getpass4
```
## Run the App
```
python cupc.py
```
## PyInstaller Build (Optional) (Prebuilt)
To compile into a standalone executable:
```
pyinstaller main.py --onefile --optimize=2 --clean --noupx
```
- Do not use `--strip` because modules aren't compiled with it.

- You can use `upx-dir=` for upx but, it will make the pyinstaller file slower

## Nuitka Build (Optional)
```
nuitka main.py --standalone --onefile --lto=yes --remove-output --output-dir=dist --mingw64
```
- MSVC is not tested but recommended
### Security Notes
- PINs are hashed, and the app does limit login attempts.

- No encryption or secure storage beyond basic hashing and file hash verifying.

- Avoid using real credentials.

### Hidden Admin Setup
To set an admin PIN, run the app and enter 9783 at the main menu.

### File Structure
```
├── setup.py
├── __init__.py
├── cupc.py
├── LICENSE
├── README.md
```
### License
This project is released under the MIT License. See `LICENSE` for details.
