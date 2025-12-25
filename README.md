# CUPC
CUPC – Constant Username and Password Checking

CUPC is a simple Python-based password checker that allows users to sign up and log in using a numeric PIN. It demonstrates basic user authentication, password hashing with `bcrypt`, and includes a built-in panel for logged-in users.
 
> [!CAUTION] 
> This project is for educational purposes only. It is not secure against brute-force attacks or suitable for production use.

# Features
- User sign-up with PIN validation

- Secure password hashing using bcrypt

- Login system with basic access control

- Admin panel for file deletion

- Hidden admin setup trigger

- Simple Panel for normal logged-in users

- User File Hashing for anti-tampering

- Wrapped up for crashes and hangs

## Getting Started
### Requirements
- Python 3.10+ (Because of `match` usage)

- `bcrypt`

- `orjson` (optional for performance)

- `numpy` (For Fast calculations)

- `blake3`

- `colorama`

## Installation

```
pip install bcrypt orjson numpy blake3 colorama
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

- And for linux:
```
nuitka main.py --standalone --onefile --lto=yes --output-dir=dist
```
> [!IMPORTANT]
> You will need `gcc` or `clang` to compile the program on linux

### Security Notes
- PINs are hashed, and the app does limit login attempts.

- No encryption or secure storage beyond basic hashing and file hash verifying.

- Avoid using real credentials.

### Hidden Admin Setup
To set an admin PIN, run the app and enter 9783 at the main menu.

### File Structure
```
├── setup.py
├── .gitignore
├── cupc.py
├── LICENSE
├── README.md
├── requirements.txt
├── start.bat
```
### License
This project is released under the MIT License. See `LICENSE` for details.
