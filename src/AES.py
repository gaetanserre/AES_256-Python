import argparse
import getpass
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import argon2


RED = "\033[1;31m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"

def print_red(str):
    print(RED+str+RESET)

def print_green(str):
    print(GREEN+str+RESET)

buffer_size = 65536 # 64Kb
is_file = False
is_dir = False

def encrypt(pwd, input_file_path):
    salt = get_random_bytes(32)
    key = PBKDF2(pwd, salt, dkLen=32)
    hashed_pwd = argon2.low_level.hash_secret(pwd.encode('utf-8'), salt, 16, 33555, 2, 128, argon2.low_level.Type.ID)
    
    input_file = open(input_file_path, 'rb')
    output_file = open(input_file_path + '.aes', 'wb')

    cipher_encrypt = AES.new(key, AES.MODE_CFB)

    output_file.write(salt)
    output_file.write(cipher_encrypt.iv)
    output_file.write(cipher_encrypt.iv)

    print(len(salt))

    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        ciphered_bytes = cipher_encrypt.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)

    input_file.close()
    output_file.close()
    os.remove(input_file_path)


def decrypt(pwd, input_file_path):
    input_file = open(input_file_path, 'rb')

    bytes_temp = input_file.read(295)
    salt = bytes_temp[:32]
    iv = bytes_temp[32:48]
        
    output_file = open(input_file_path[:-4], 'wb')
    key = PBKDF2(pwd, salt, dkLen=32)

    cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)

    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        decrypted_bytes = cipher_decrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)

    input_file.close()
    output_file.close()
    os.remove(input_file_path)


def checkPwd(pwd, path):
    input_file = open(path, 'rb')
    bytes_temp = input_file.read(295)
    hashed_pwd = bytes_temp[48:295]

    try: 
        argon2.low_level.verify_secret(hashed_pwd, pwd.encode('utf-8'), argon2.low_level.Type.ID)
        return True
    except:
        return False

    
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required = True, help = "path to the file")
    parser.add_argument("-e", "--encrypt", action = "store_true", default=False)
    parser.add_argument("-d", "--decrypt", action = "store_true", default=False)
    args = parser.parse_args()

    if os.path.isfile(args.file):
        is_file = True
    if os.path.isdir(args.file):
        is_dir = True

    if args.encrypt and (is_file or is_dir):
        while True:
            pwd = getpass.getpass("Set a password : ")
            pwd_conf = getpass.getpass("Confirm password : ")
            if pwd == pwd_conf: 
                break
            else:
                print_red("Password doesn't match. Please try again.")

        if is_file:
            print("Encrypting file...")
            encrypt(pwd, args.file)
            print_green("File is ecrypted.")
            
        elif is_dir:
            files = []
            for (dirpath, dirnames, filenames) in os.walk(args.file):
                for f in filenames:
                    filename = os.path.join(dirpath, f)
                    print("Encrypting " + filename)
                    encrypt(pwd, filename)
                    print_green("File is encrypted.")
            


    elif args.decrypt and (is_file or is_dir):
        if is_file:
            while True:
                pwd = getpass.getpass("Password? : ")
                if checkPwd(pwd, args.file):
                    print("Decrypting file...")
                    decrypt(pwd, args.file)
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
                    print("Decrypting " + filename)
                    if checkPwd(pwd, filename):
                        decrypt(pwd, filename)
                        print_green("File is decrypted.")
                    else:
                        print_red("Wrong password. Ignoring file.")
                        

    elif is_file or is_dir:
        print_red("-e (encrypt) or -d (decrypt) argument is needed. Please try again.")

    else:
        print_red("The path is wrong. Please try again.")
