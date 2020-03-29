# Programmed by TH3_S1LENC3
# Contains all cli interface code

import getpass
import os
import time
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
import sys
import re
from aes import aes_mode, clearScreen
from aes.mode import write_mode
from aes import algorithms

#---------------------------------------------------------------------------

def menu():
    mode = get_mode()
    print("AES256 Encryption & Decryption Script Version 3.0 \n")
    print("Mode: " + mode)
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Change AES Mode")
    print("4. Help")
    print("5. ReadMe")
    print("6. Changelog")
    print("7. Exit \n")
    choice = int(input("Enter Your Choice [1|2|3|4|5|6|7]: "))

    default = print("Invalid Input. Please enter [1|2|3|4|5|6|7]. \n"); menu()

    options = {
        1 : EncryptMenu(),
        2 : DecryptMenu(),
        3 : ChangeAESMode(),
        4 : Help(),
        5 : ReadMe(),
        6 : Changelog(),
        7 : sys.exit()
    }

    options.get(choice,default)

def EncryptMenu():
    print("1. Encrypt String")
    print("2. Encrypt File")
    choice = input("Enter Your Choice [1|2]")

    if choice == "1":
        EncryptMessage()
    elif choice == "2":
        print("Function In Development")
        EncryptMenu()
        #EncryptFile()
    else:
        print("Invalid Input. Please enter [1|2]. \n")
        EncryptMenu()

def DecryptMenu():
    print("1. Decrypt String")
    print("2. Decrypt File")
    choice = input("Enter Your Choice [1|2]")

    if choice == "1":
        DecryptMessage()
    elif choice == "2":
        print("Function In Development")
        DecryptMenu()
        #EncryptFile()
    else:
        print("Invalid Input. Please enter [1|2]. \n")
        DecryptMenu()

def ChangeAESMode():
    default = "CBC"

    print("Supported AES Modes:")
    print("1. CBC")
    print("2. GCM")
    choice = int(input("Enter Your Choice [1|2] [Default: " + default + "]."))

    supportedModesDictionary = {
        1 : "CBC",
        2 : "GCM"
    }

    mode = supportedModesDictionary.get(choice, default)
    write_mode(mode)

def Help():
    filename = "Help.txt"
    # Open Help
    open_file(filename)

def ReadMe():
    filename = "ReadMe.md"
    # Open ReadMe
    open_file(filename)

def Changelog():
    filename = "Changelog.txt"
    # Open Changelog
    open_file(filename)

#---------------------------------------------------------------------------

def EncryptMessage():
    # Get plaintext to encrypt
    plaintext = input("Enter string to encrypt: ")
    # Get password
    password = getPassword()
    # Generate salt
    salt = get_random_bytes(32)
    # Derive key from password and require 1gb of ram to do so
    key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
    # Get mode set by user
    if aes_mode == "CBC":
        # Create an aes object
        aes = algorithms.cbc()
        # Get plaintext to encrypt
        secretmessage = input("Enter plaintext: ")
        # Get password
        password = getPassword()
        # Generate Salt & Derive key from password and require 1gb of ram to do so
        salt = get_random_bytes(32)
        key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
        # Encrypt and print result
        ciphertext = aes.encryptString(secretmessage, key)
        print("Encrypted message: " + ciphertext)
        print("Salt: " + salt)
        print("WARNING: If any components are lost you will be unable to decrypt your message.")
        # -----------
        time.sleep(1)
        Continue()
    elif aes_mode == "GCM":
        # Create an aes object
        aes = algorithms.gcm()
        # Get authentication tag
        header = getHeader()
        # Encrypt plaintext
        ciphertext, tag, nonce = aes.encryptString(plaintext, header, key)
        # Output Result
        print("COMPONENTS OF MESSAGE")
        print("Associated Authenticated Data: " + str(header))
        print("Encrypted message: " + str(ciphertext))
        print("Authentication Tag: " + str(tag))
        print("Nonce" + str(nonce))
        print("Salt: " + str(salt))
        print("WARNING: If any components are lost you will be unable to decrypt your message.")
        # Message to transmit / share
        time.sleep(1)
        final_message = header, ciphertext, tag, nonce, salt
        print("Message: " + str(final_message))
    else:
        print("Error Retriveing Mode.")
        print("Returning To Menu.")
        menu()
    # -----------
    time.sleep(1)
    Continue()

def DecryptMessage():
    if aes_mode == "CBC":
        # Create an aes object
        aes = algorithms.cbc()
        # Get encrypted text to decrypt
        secretmessage = input("Enter string to decrypt: ")
        # Get password and salt
        password = getPassword()
        # Get salt
        salt = input("Enter Salt: ")
        salt = salt.replace(" ", "")
        while salt == "":
            print("Please enter something.")
            salt = input("Enter Salt: ")
            salt = salt.replace(" ", "")
        # Derive key from password and require 1gb of ram to do so
        key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
        # Decrypt and print result
        decrypted, status = aes.decryptString(secretmessage, key)
        if status == True:
            print(decrypted)
        elif status == False:
            time.sleep(2)
            print("Restarting Function.")
            clearScreen()
            DecryptMessage()
        # -----------
        time.sleep(1)
        Continue()
    elif aes_mode == "GCM":
        # Create an aes object
        aes = algorithms.gcm()
        choice = input("Do you have a transmitted message [Y/N]: ")
        choice = choice.replace(" ", "")
        while choice == "":
            print("Please enter something.")
            choice = input("Do you have a transmitted message [Y/N]: ")
            choice = choice.replace(" ", "")
        # Choice 1
        if choice == "1":
            # Get ciphertext to decrypt
            ciphertext = input("Enter string to decrypt: ")
            # Get Header
            header = input("Enter Header: ")
            header = header.replace(" ", "")
            while nonce == "":
                print("Please enter something.")
                header = input("Enter Header: ")
                header = header.replace(" ", "")
            # Get password
            password = getPassword()
            # Get salt
            salt = input("Enter Salt: ")
            salt = salt.replace(" ", "")
            while salt == "":
                print("Please enter something.")
                salt = input("Enter Salt: ")
                salt = salt.replace(" ", "")
            # Derive key from password and require 1gb of ram to do so
            key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
            # Get Nonce
            nonce = input("Enter Nonce: ")
            nonce = nonce.replace(" ", "")
            while nonce == "":
                print("Please enter something.")
                nonce = input("Enter Nonce: ")
                nonce = nonce.replace(" ", "")
            # Get Auth_tag
            tag = input("Enter Tag: ")
            tag = tag.replace(" ", "")
            while tag == "":
                print("Please enter something.")
                tag = input("Enter Tag: ")
                tag = tag.replace(" ", "")
            # Decrypt and Print Result
            decrypted, status = aes.decryptString(ciphertext, header, key, nonce, tag)
            if status == True:
                print("MAC validated.")
                print("Authenticated Associated Data: " + str(header))
                print("Decrypted Message: " + str(decrypted))
            elif status == False:
                time.sleep(2)
                print("Restarting Function.")
                clearScreen()
                DecryptMessage()
            # -----------
            time.sleep(1)
            Continue()
        # Choice 2
        elif choice == "2":
            # Get Received Message
            received_msg = input("Enter Received Message: ")
            received_msg = received_msg.replace(" ", "")
            # Error Checking
            while received_msg == "":
                print("Please enter something.")
                received_msg = input("Enter Received Message: ")
                received_msg = received_msg.replace(" ", "")
            # Parsing the data
            received_header, received_ciphertext, received_tag, received_nonce, received_salt = received_msg
            # Get Decryption Passphrase
            password = getpass.getpass("Enter Decryption Passphrase: ")
            confirmPassword = getpass.getpass("Confirm Decryption Passphrase: ")
            # Error Checking
            while password != confirmPassword:
                print("Passphrases do not match. Please try again.")
                password = getpass.getpass("Enter Decryption Passphrase: ")
                confirmPassword = getpass.getpass("Confirm Decryption Passphrase: ")
            # Derive key from password and require 1gb of ram to do so
            key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
            # Decrypt and Print Result
            decrypted, status = aes.decryptString(received_ciphertext, received_header, key, received_nonce, received_tag)
            if status == True:
                print("MAC validated.")
                print("Authenticated Associated Data: " + str(received_header))
                print("Decrypted Message: " + str(decrypted))
            elif status == False:
                time.sleep(2)
                print("Restarting Function.")
                clearScreen()
                DecryptMessage()
        # -----------
        time.sleep(1)
        Continue()

def EncryptFile():
    if aes_mode == "CBC":
        # Create an aes object
        aes = algorithms.cbc()
        # Get plaintext file to encrypt
        plaintext_file = input("Enter file to encrypt (with path and extention): ")
        # Get password
        password = getPassword()
        # Generate salt
        salt = get_random_bytes(32)
        # Derive key from password and require 1gb of ram to do so
        key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
        # Get output file
        outfile = plaintext_file + ".enc"
        # Encrypt and print result
        ciphertext = algorithms.encryptFile(plaintext_file, key, outfile)
        print("Encrypted message: " + ciphertext)
        print("Salt: " + salt)
        print("WARNING: If your salt is lost you will be unable to decrypt your message.")
    elif aes_mode == "GCM":
        # Create an aes object
        aes = algorithms.gcm()
    # -----------
    time.sleep(1)
    Continue()

def DecryptFile():
    if aes_mode == "CBC":
        # Create an aes object
        aes = algorithms.gcm()
        # Get encrypted file to decrypt
        encrypted_file = input("Enter file to decrypt (with path and extention): ")
        # Get output output directory and file
        outfile = input("Enter output file (with path and extention): ")
        # Get password
        password = getPassword()
        # Get salt
        salt = input("Enter Salt: ")
        salt = salt.replace(" ", "")
        while salt == "":
            print("Please enter something.")
            salt = input("Enter Salt: ")
            salt = salt.replace(" ", "")
        # Derive key from password and require 1gb of ram to do so
        key = scrypt(password, salt, 32, N=1048576, r=8, p=1)
        # Get output file
        outfile = encrypted_file + ".dec"
        # Decrypt and print result
        decrypt = aes.decryptFile(encrypted_file, key, outfile)
        if decrypt == True:
            print("File Successfully Encrypted.")
            print("Encrypted File: " + outfile)
        else:
            print("Error during decryption.")
            DecryptFile()
    elif aes_mode == "GCM":
        # Create an aes object
        aes = algorithms.gcm()
    # -----------
    time.sleep(1)
    Continue()

#---------------------------------------------------------------------------

def getPassword():
    # Get password
    password = getpass.getpass("Enter Encryption Passphrase: ")
    confirmPassword = getpass.getpass("Confirm Encryption Passphrase: ")
    # Check if password is valid
    validPassword = checkPassword(password)
    # Check if passwords match
    while password != confirmPassword or validPassword != True:
        # Inform the user if their password do not match
        if password != confirmPassword:
            print("Passphrases do not match. Please try again.")
        # Inform the user if their password do not meet criteria
        if validPassword != True:
            print("Passphrase does not meet criteria. Please try again.")
        # Get the password again
        password = getpass.getpass("Enter Encryption Passphrase: ")
        confirmPassword = getpass.getpass("Confirm Encryption Passphrase: ")
        # Update vaildPassword
        validPassword = checkPassword(password)
    return password

def checkPassword(password):
    flag = 0
    while True:
        # Checks if password is less than 8
        if (len(password) < 8):
            flag = 1
            break
        # Checks if password contains lower case letters
        elif not re.search("[a-z]", password):
            flag = 2
            break
        # Checks if password contains upper case letters
        elif not re.search("[A-Z]", password):
            flag = 3
            break
        # Checks if password contains numbers
        elif not re.search("[0-9]", password):
            flag = 4
            break
        # Checks if password contains special characters
        elif not re.search("[_@$]", password):
            flag = 5
            break
        # Checks if password contains white spaces
        elif re.search("\s", password):
            flag = 6
            break
        # Else it meets criteria
        else:
            flag = 0
            break

    if flag == 1:
        print("Password Must Be 8 Characters")
        return(False)
    if flag == 2:
        print("Password Must Contain Lower Case ASCII Characters")
        return(False)
    if flag == 3:
        print("Password Must Contain Upper Case ASCII Characters")
        return(False)
    if flag == 4:
        print("Password Must Contain Numbers")
        return(False)
    if flag == 5:
        print("Password Must Contain Special Characters")
        return(False)
    if flag == 6:
        print("Password Must Not Contain Spaces")
        return(False)
    else:
        return(True)

def getHeader():
    # Get Header
    header = input("Enter Associated Authenticated Data: ")
    header = auth_tag.replace(" ", "")
    while header == "":
        print("Please enter something. This won't be encrypted but it will be authenticated.")
        header = input("Enter Associated Authenticated Data: ")
        header = header.replace(" ", "")
    return header

#---------------------------------------------------------------------------

def Continue():
    clearScreen()
    menu()
