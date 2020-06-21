# AES-Python
A file encryption tool written with Python 3 using AES-256 bits, PBKDF2 and argon2id algorithm.

# Requirements
- [Pycryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [Argon2-cffi](https://pypi.org/project/argon2-cffi/)

Run `pip3 install -r requirements.txt`

# Usage
Run `python3 AES.py -f [path of the file or folder] -e|d [e for encrypt | d for decrypt] 1` and follow instructions on the terminal

# Warning
Please save your password carefully. You will not be able to retrieve your data otherwise.