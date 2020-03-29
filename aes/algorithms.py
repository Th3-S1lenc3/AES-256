# Programmed by TH3_S1LENC3
# Contains all encryption algorithms

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

#---------------------------------------------------------------------------

class cbc():
    def encryptString(plaintext, key):
        # Convert plaintext and key to bytes
        plaintext = bytes(plaintext, 'utf-8')
        key = bytes(key, 'utf-8')
        # Create a AES cipher object
        cipher = AES.new(key, AES.MODE_CBC)
        # Pad the input data and encrypts
        ct_bytes = cipher.encrypt(pad(secretmessage, AES.block_size))
        # Return EncryptedText & IV
        IV = b64encode(cipher.iv).decode('utf-8')
        ciphertext = b64encode(ct_bytes).decode('utf-8')
        ciphertext = IV + ciphertext
        return ciphertext

    def decryptString(ciphertext, key):
        # Convert encrypted message and key to bytes
        ciphertext = bytes(ciphertext, 'utf-8')
        key = bytes(key, 'utf-8')
        # Get IV
        iv = ciphertext[:16]
        # Create a AES cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            # Unpad the encrypted message and decrypt
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            # Return DecryptedText
            return decrypted, True
        except ValueError:
            print("ValueError")
            decrypted = ""
            return decrypted, False
        except KeyError:
            print("Invalid Decryption Passphrase.")
            decrypted = ""
            return decrypted, False

    #---------------------------------------------------------------------------

    def encryptFile(plaintext_file, key, outfile):
        # Open input and output files
        input_file = open(plaintext_file, 'rb')
        output_file = open(outfile, 'wb')
        # Set chunk_size
        chunk_size = 65536
        # Create the cipher object and encrypt the data
        cipher = AES.new(key, AES.MODE_CBC)
        output_file.write(b64encode(iv))
        # Keep reading the file into the chunk, encrypting then writing to the new file
        chunk = input_file.read(chunk_size)
        while len(chunk) > 0:
            chunk = pad(chunk)
            ciphered_bytes = cipher.encrypt(chunk)
            output_file.write(b64encode(ciphered_bytes))
            chunk = input_file.read(chunk_size)
        return True

    def decryptFile(encrypted_file, key, outfile):
        # Open input and output files
        input_file = open(encrypted_file, 'rb')
        output_file = open(outfile, 'wb')
        # Set chunk_size
        chunk_size = 65536
        with open(encrypted_file, 'rb')as input_file:
            iv = input_file.read(16)
        # Create a AES cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            chunk = input_file.read(chunk_size)
            while len(chunk) > 0:
                decrypted_bytes = unpad(cipher.decrypt(chunk))
                output_file.write(decrypted_bytes)
                chunk = input_file.read(chunk_size)
            return True
        except ValueError:
            print("ValueError")
            decrypted = ""
            return False
        except KeyError:
            print("Invalid Decryption Passphrase.")
            decrypted = ""
            return False


#---------------------------------------------------------------------------

class gcm():

    def encryptString(plaintext, header, key):
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        nonce = cipher.nonce
        return ciphertext, tag, nonce

    def decryptString(ciphertext, header, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        cipher.update(header)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted, True
        except ValueError as mac_mismatch:
            print("MAC validation failed during decryption. No authentication garuntees on this ciphertext")
            print("Unauthenticated Associated Data: " + str(header))
            decrypted = ""
            return decrypted, False
        except KeyError:
            print("Incorrect Decryption Passphrase.")
            decrypted = ""
            return decrypted, False

    #---------------------------------------------------------------------------

    def encryptFile(plaintext_file, key, outfile):
        # Open input and output files
        input_file = open(plaintext_file, 'rb')
        output_file = open(outfile, 'wb')
        # Set chunk_size
        chunk_size = 65536
        # Create the cipher object and encrypt the data
        cipher = AES.new(key, AES.MODE_GCM)
        output_file.write(b64encode(iv))
        # Keep reading the file into the chunk, encrypting then writing to the new file
        chunk = input_file.read(chunk_size)
        while len(chunk) > 0:
            ciphered_bytes = cipher.encrypt(chunk)
            output_file.write(b64encode(ciphered_bytes))
            chunk = input_file.read(chunk_size)
        cipher.digest()
        return True

    def decryptFile(encrypted_file, key, outfile):
        # Open input and output files
        input_file = open(encrypted_file, 'rb')
        output_file = open(outfile, 'wb')
        # Set chunk_size
        chunk_size = 65536
        # Create a AES cipher object
        cipher = AES.new(key, AES.MODE_GCM, iv)
        try:
            chunk = input_file.read(chunk_size)
            while len(chunk) > 0:
                decrypted_bytes = unpad(cipher.decrypt(chunk))
                output_file.write(decrypted_bytes)
                chunk = input_file.read(chunk_size)
            return True
        except ValueError as mac_mismatch:
            print("MAC validation failed during decryption. No authentication garuntees on this ciphertext")
            print("Unauthenticated Associated Data: " + str(header))
            decrypted = ""
            return decrypted, False
        except KeyError:
            print("Incorrect Decryption Passphrase.")
            decrypted = ""
            return decrypted, False
