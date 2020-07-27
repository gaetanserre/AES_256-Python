import os
import argparse
import getpass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_512

RED = "\033[1;31m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"

buffer_size = 65536 # 64Kb

def print_red(str):
    print(RED+str+RESET)

def print_green(str):
    print(GREEN+str+RESET)



def generate_salt():
    return get_random_bytes(32)


def get_salt_from_file(input_file_path):
    input_file = open(input_file_path, 'rb')
    return input_file.read(32)


def generate_AES256_key(passwd, salt):
    return scrypt(passwd, salt, 32, N=2**20, r=8, p=1)


def checkPwd(passwd, salt, input_file_path):
    input_file = open(input_file_path, 'rb')
    bytes_temp = input_file.read(112)
    hashed_pwd = bytes_temp[48:112]

    return SHA3_512.new(data=passwd.encode('utf-8')).update(salt).digest() == hashed_pwd


def encrypt(key, passwd, salt, input_file_path):
    hashed_passwd = SHA3_512.new(data=passwd.encode('utf-8'))
    hashed_passwd.update(salt)
    hashed_passwd = hashed_passwd.digest()

    input_file = open(input_file_path, 'rb')
    output_file = open(input_file_path + '.aes', 'wb')

    cipher_encrypt = AES.new(key, AES.MODE_CFB)

    output_file.write(salt) #32 bytes
    output_file.write(cipher_encrypt.iv) #16 bytes
    output_file.write(hashed_passwd) #64 bytes

    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        ciphered_bytes = cipher_encrypt.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)

    input_file.close()
    output_file.close()
    os.remove(input_file_path)


def decrypt(key, input_file_path):
    input_file = open(input_file_path, 'rb')

    bytes_temp = input_file.read(112)
    iv = bytes_temp[32:48]
        
    output_file = open(input_file_path[:-4], 'wb')

    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)

    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        decrypted_bytes = cipher_decrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)

    input_file.close()
    output_file.close()
    os.remove(input_file_path)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required = True, help = "path to the file")
    parser.add_argument("-e", "--encrypt", action = "store_true", default=False)
    parser.add_argument("-d", "--decrypt", action = "store_true", default=False)
    args = parser.parse_args()

    is_file = os.path.isfile(args.file)
    is_dir = os.path.isdir(args.file)

    if args.encrypt and (is_file or is_dir):
        while True:
            pwd = getpass.getpass("Set a password : ")
            pwd_conf = getpass.getpass("Confirm password : ")
            if pwd == pwd_conf: 
                break
            else:
                print_red("Password doesn't match. Please try again.")

        if is_file:
            print("Generating key from password..")
            salt = generate_salt()
            key = generate_AES256_key(pwd, salt)

            print("Encrypting file..")
            encrypt(key, pwd, salt, args.file)

            print_green("File is encrypted.")
            
        elif is_dir:
            files = []
            for (dirpath, dirnames, filenames) in os.walk(args.file):
                for f in filenames:
                    print("Generating key from password..")

                    salt = generate_salt()
                    key = generate_AES256_key(pwd, salt)

                    filename = os.path.join(dirpath, f)

                    print("Encrypting " + filename)
                    encrypt(key, pwd, salt, filename)

                    print_green("File is encrypted.")
            


    elif args.decrypt and (is_file or is_dir):
        if is_file:
            salt = get_salt_from_file(args.file)
            while True:
                pwd = getpass.getpass("Password? : ")

                if checkPwd(pwd, salt, args.file):
                    print("Generating key from password..")
                    key = generate_AES256_key(pwd, salt)

                    print("Decrypting file..")
                    decrypt(key, args.file)

                    break
                else:
                    print_red("Wrong password. Try again.")

            print_green("File is decrypted")

        elif is_dir:
            pwd = getpass.getpass("Password? : ")
            files = []
            for (dirpath, dirnames, filenames) in os.walk(args.file):
                for f in filenames:
                    filename = os.path.join(dirpath, f)
                    salt = get_salt_from_file(filename)

                    print("Generating key from password..")

                    if checkPwd(pwd, salt, filename):
                        print("Decrypting " + filename)
                        key = generate_AES256_key(pwd, salt)
                        decrypt(key, filename)

                        print_green("File is decrypted.")
                    else:
                        print_red("Wrong password. Ignoring file.")
                        

    elif is_file or is_dir:
        print_red("-e (encrypt) or -d (decrypt) argument is needed. Please try again.")

    else:
        print_red("The path is wrong. Please try again.")

