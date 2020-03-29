# AES 256 encryption/decryption using pycryptodome library
# Programmed by TH3_S1LENC3
import os
from aes.mode import get_mode

# Setup working directory
os.chdir("aes")

# Setup AES mode
aes_mode = get_mode()

# Setup clearScreen function
def clearScreen():
    os.system('cls' if os.name == 'nt' else 'clear')

from aes import cli
