import os
import argparse
import getpass
from itertools import repeat
from multiprocessing import Pool
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_512
import random
from tqdm import tqdm
import subprocess

RED = "\033[1;31m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"

buffer_size = 65536 # 64Kb

def print_red(str):
    print(RED+str+RESET)

def print_green(str):
    print(GREEN+str+RESET)

def checkExtension (filepath, ext):
  _, file_extension = os.path.splitext(filepath)
  return file_extension == ext

def shred_file(path):
  print("Shredding...")
  abs_dir = os.path.abspath(os.path.join(__file__, os.pardir))
  shred_prog = os.path.join(abs_dir, "shredder")
  subprocess.call([shred_prog, path])


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
    shred_file(input_file_path)
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


def pool_encrypt(f, dirpath, pwd):
  if not checkExtension(f, '.aes'):
    print("Generating key from password...")

    salt = generate_salt()
    key = generate_AES256_key(pwd, salt)

    filename = os.path.join(dirpath, f)

    print("Encrypting " + filename)
    
    try:
        encrypt(key, pwd, salt, filename)
    except:
        return

    print_green("File is encrypted.")
  else:
    print_red(f"{f} already encrypted. Skipping...")


def pool_decrypt(f, dirpath, pwd):
  if not checkExtension(f, '.aes'):
    print_red(f"{f} already decrypted. Skipping...")
    return

  filename = os.path.join(dirpath, f)
  try:
      salt = get_salt_from_file(filename)
  except:
      return

  print("Generating key from password...")

  if checkPwd(pwd, salt, filename):
      print("Decrypting " + filename)
      key = generate_AES256_key(pwd, salt)
      try:
        decrypt(key, filename)
      except:
        return

      print_green("File is decrypted.")
  else:
      print_red("Wrong password. Skipping...")

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
            print("Generating key from password...")
            salt = generate_salt()
            key = generate_AES256_key(pwd, salt)

            print("Encrypting file...")
            encrypt(key, pwd, salt, args.file)

            print_green("File is encrypted.")
            
        elif is_dir:
            files = []
            for (dirpath, dirnames, filenames) in os.walk(args.file):
              with Pool(5) as p:
                p.starmap(pool_encrypt, zip(filenames, repeat(dirpath), repeat(pwd)))
                

    elif args.decrypt and (is_file or is_dir):
        if is_file:
            salt = get_salt_from_file(args.file)
            while True:
                pwd = getpass.getpass("Password? : ")

                if checkPwd(pwd, salt, args.file):
                    print("Generating key from password...")
                    key = generate_AES256_key(pwd, salt)

                    print("Decrypting file...")
                    decrypt(key, args.file)

                    break
                else:
                    print_red("Wrong password. Try again.")

            print_green("File is decrypted")

        elif is_dir:
            pwd = getpass.getpass("Password? : ")
            files = []
            for (dirpath, dirnames, filenames) in os.walk(args.file):
                with Pool(5) as p:
                  p.starmap(pool_decrypt, zip(filenames, repeat(dirpath), repeat(pwd)))
                    

    elif is_file or is_dir:
        print_red("-e (encrypt) or -d (decrypt) argument is needed. Please try again.")

    else:
        print_red("The path is wrong. Please try again.")

