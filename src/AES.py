#
# Created in 2022 by Gaëtan Serré
#

import os
import argparse
import getpass
import subprocess
from tqdm.auto import tqdm
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_512

RED = "\033[1;31m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"

buffer_size = 65536  # 64Kb


def print_red(str):
    print(RED + str + RESET)


def print_green(str):
    print(GREEN + str + RESET)


def checkExtension(filepath, ext):
    _, file_extension = os.path.splitext(filepath)
    return file_extension == ext


def shred_file(path):
    print("Shredding...")
    subprocess.call(["shred", "-uz", path])


def generate_salt():
    return get_random_bytes(32)


def get_salt_from_file(input_file_path):
    input_file = open(input_file_path, "rb")
    return input_file.read(32)


def generate_AES256_key(passwd, salt):
    return scrypt(passwd, salt, 32, N=2**20, r=8, p=1)


def check_password(passwd, input_file_path):
    input_file = open(input_file_path, "rb")
    bytes_temp = input_file.read(112)
    hashed_pwd = bytes_temp[48:112]
    salt = get_salt_from_file(input_file_path)

    return SHA3_512.new(data=passwd.encode("utf-8")).update(salt).digest() == hashed_pwd


def encrypt_key(key, passwd, salt, input_file_path):
    hashed_passwd = SHA3_512.new(data=passwd.encode("utf-8"))
    hashed_passwd.update(salt)
    hashed_passwd = hashed_passwd.digest()

    input_file = open(input_file_path, "rb")
    output_file = open(input_file_path + ".aes", "wb")

    cipher_encrypt = AES.new(key, AES.MODE_CFB)

    output_file.write(salt)  # 32 bytes
    output_file.write(cipher_encrypt.iv)  # 16 bytes
    output_file.write(hashed_passwd)  # 64 bytes

    # Progress bar
    file_size = os.path.getsize(input_file_path)
    pbar = tqdm(total=file_size, unit="B", unit_scale=True, desc="Encrypting")

    buffer = input_file.read(buffer_size)
    pbar.update(len(buffer))
    while len(buffer) > 0:
        ciphered_bytes = cipher_encrypt.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)
        pbar.update(len(buffer))

    input_file.close()
    output_file.close()
    shred_file(input_file_path)


def encrypt(passwd, input_file_path):
    print("Generating key from password...")
    salt = generate_salt()
    key = generate_AES256_key(passwd, salt)

    print(f"Encrypting {input_file_path}")
    encrypt_key(key, passwd, salt, input_file_path)
    print_green("File is encrypted.")

    return True


def decrypt_key(key, input_file_path):
    input_file = open(input_file_path, "rb")

    bytes_temp = input_file.read(112)
    iv = bytes_temp[32:48]

    output_file = open(input_file_path[:-4], "wb")

    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)

    # Progress bar
    file_size = os.path.getsize(input_file_path) - 112
    pbar = tqdm(total=file_size, unit="B", unit_scale=True, desc="Decrypting")

    buffer = input_file.read(buffer_size)
    pbar.update(len(buffer))
    while len(buffer) > 0:
        decrypted_bytes = cipher_decrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)
        pbar.update(len(buffer))

    input_file.close()
    output_file.close()
    os.remove(input_file_path)


def decrypt(passwd, input_file_path):
    print("Checking password...")
    if not check_password(passwd, input_file_path):
        return False

    print("Generating key from password...")
    salt = get_salt_from_file(input_file_path)
    key = generate_AES256_key(passwd, salt)

    print(f"Decrypting {input_file_path}")
    decrypt_key(key, input_file_path)
    print_green("File is decrypted.")

    return True


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="path to the file")
    parser.add_argument("-e", "--encrypt", action="store_true", default=False)
    parser.add_argument("-d", "--decrypt", action="store_true", default=False)
    args = parser.parse_args()

    is_file = os.path.isfile(args.file)
    is_dir = os.path.isdir(args.file)

    if not is_file and not is_dir:
        raise ValueError("File or directory doesn't exist.")

    elif not args.encrypt and not args.decrypt:
        raise ValueError("Please specify an action.")

    elif args.encrypt:
        while True:
            pwd = getpass.getpass("Set a password: ")
            pwd_conf = getpass.getpass("Confirm password: ")
            if pwd == pwd_conf:
                break
            else:
                print_red("Password doesn't match. Please try again.")
        if is_file:
            encrypt(pwd, args.file)

        elif is_dir:

            for dirpath, dirname, filenames in os.walk(
                args.file
            ):  # Files of each subdirectory
                for filename in filenames:
                    filename = os.path.join(dirpath, filename)
                    if checkExtension(filename, ".aes"):
                        print(f"Skipping {filename}")
                        continue
                    encrypt(pwd, filename)

    elif args.decrypt:
        pwd = getpass.getpass("Enter password : ")

        if is_file:
            if not decrypt(pwd, args.file):
                raise ValueError("Wrong password.")

        elif is_dir:
            for dirpath, dirname, filenames in os.walk(
                args.file
            ):  # Files of each subdirectory
                for filename in filenames:
                    filename = os.path.join(dirpath, filename)
                    if not checkExtension(filename, ".aes"):
                        print(f"Skipping {filename}")
                        continue
                    if not decrypt(pwd, filename):
                        print_red(f"Wrong password. Skipping {filename}.")
