# AES-Python
A file encryption tool written with Python 3 using AES-256 bits, PBKDF2 and argon2id algorithm. 

AES-Python encrypts|decrypts a file or all files in a folder (even files in subfolders).

# Requirements
- [Pycryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [Argon2-cffi](https://pypi.org/project/argon2-cffi/)

Run `pip3 install -r requirements.txt`

# Usage
Run `python3 AES.py -f [path of the file or folder] -e|d [e for encrypt | d for decrypt]`

and follow instructions on the terminal.

# Explanation scheme
![](Images/scheme.gif)

# Example
> **Plain text:**  Hello, I'm a test for Gaëtan Serré's Python-AES repository.

> **Encrytped text with the password azerty:** �i����ı�^'�W�
oG>b#�ܨ˔�a=�`7I�/�:`�Q@���}�#$argon2id$v=19$m=33555,t=16,p=2$j2mIiIvDxLHkXifbV6ANb0c+YiPY3KjLlJJhPeNgN0k$KcGduLYkVTVIXCGzuxmTO95R9K+Y6mjy2cdqYfD8iNb8ZTHnPbJ8Uy/3qBwaLXXQyLzdkZVE2zk6N7KeZ6ibDspLxx1qXx8BL3K+SK6PE8mWKYX381GZdQwAR1jvqwVJyjfQvvxrXTk1tVdNndOFtZBR3opZSJRreoW3g8CX85M�u��t��s��!�V_��"I�
��D�X�u~�:��SɝQ[���+��Y����]:a�s

- The 32 first bits are the salt used in the argon2id hashing
- The next 32 bits are the initialization vector for AES-256
- The next 247 bits are the hashed password
- The next bits are of the encrypted data



# Warning
Please save your password carefully. You will not be able to retrieve your data otherwise.
