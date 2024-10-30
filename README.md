# AES Encryption

This project demonstrates the implementation and use of AES-128 encryption. It includes three files:

- `aes.py`: Implements AES-128 encryption and decryption algorithms.
- `main.py`: A script to use AES with a user-provided key and plaintext input.
- `test.py`: Runs an example test case to validate AES encryption.

## Files Overview

### aes.py
This file contains the AES-128 encryption and decryption implementation, handling 128-bit keys to secure plaintext data.

### main.py
This script allows users to input a key and plaintext to perform AES encryption and decryption using the `aes.py` module.

### test.py
This script tests the AES implementation with an example case to verify encryption and decryption correctness.

## Usage

1. **Encrypt Data**: Run `main.py` and provide a 128-bit key and plaintext to encrypt.
    ```bash
    python3 main.py
    ```
2. **Test Case**: Run `test.py` to check the encryption and decryption with a sample input.
    ```bash
    python3 test.py
    ```

## Example
```bash
# Running main.py
Enter key (16 bytes): example_key_128b
Enter plaintext: Hello, AES!
```
The output will display the encrypted ciphertext and the decrypted result to confirm accuracy.

## Requirements
- Python 3.x
- colorama
