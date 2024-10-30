import unittest
from aes import AES
from colorama import Fore, Style, init


# Initialize colorama for color support on Windows
init(autoreset=True)


def hex_string_to_hex_4x4_matrix(string):
    matrix = [["", "", "", ""], ["", "", "", ""], ["", "", "", ""], ["", "", "", ""]]
    elements = string.split()

    for i in range(4):
        for j in range(4):
            matrix[j][i] = "0x" + elements[4 * i + j]
    
    return matrix


def hex_4x4_matrix_to_hex_string(matrix):
    hex_string = ""
    for i in range(4):
        for j in range(4):
            hex_string += matrix[j][i] + " "
    return hex_string


class TestAES(unittest.TestCase):
    def setUp(self):
        # Define the key and plaintext used in the example
        self.key = "0f 15 71 c9 47 d9 e8 59 0c b7 ad d6 af 7f 67 98"
        self.plaintext = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
        
        # Expected ciphertext from the example
        self.expected_ciphertext = "ff 0b 84 4a 08 53 bf 7c 69 34 ab 43 64 14 8f b9"

    def test_aes_encryption(self):
        # Convert key and plaintext to 4x4 matrices
        key_matrix = hex_string_to_hex_4x4_matrix(self.key)
        plaintext_matrix = hex_string_to_hex_4x4_matrix(self.plaintext)
        
        # Initialize AES with the key
        aes = AES(key_matrix)
        
        # Encrypt the plaintext and get ciphertext
        ciphertext, _ = aes.encrypt(plaintext_matrix)
        ciphertext_str = hex_4x4_matrix_to_hex_string(aes.formatty(ciphertext))
        
        # Assert that the resulting ciphertext matches the expected ciphertext
        try:
            self.assertEqual(ciphertext_str.strip(), self.expected_ciphertext.strip())
            print(Fore.GREEN + "Test Passed: AES encryption produced expected ciphertext.")
        except AssertionError:
            print(Fore.RED + "Test Failed: AES encryption did not produce expected ciphertext.")
            raise  # Re-raise the assertion error to ensure the test fails


if __name__ == "__main__":
    print(Fore.CYAN + "Running AES Encryption Test:" + Style.RESET_ALL)
    unittest.main()