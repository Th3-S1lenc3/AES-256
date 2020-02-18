# Setup Script for AES 256 encryption/decryption script
# Programmed by TH3_S1LENC3

from Crypto.Random import get_random_bytes

# Generate a salt
salt = get_random_bytes(32)
# Open salt File
salt_file = open("salt.txt", "w")
# Write salt to file
salt_file.write(str(salt))
# Close file
salt_file.close()
