# AES - 128bit
class AES:
    def __init__(self, key):
        """
        Initialises the AES object with a given key.
        
        Args:
            key (list or string): The key to use for encryption. If a string, it should be a space-separated list of hexadecimal values.
        
        Raises:
            ValueError: If the key is not 16 bytes (128 bits) long.
        """
        if isinstance(key, list) and all(isinstance(row, list) for row in key):
            key = [int(value, 16) for row in key for value in row]
        
        # Check if the key is 16 bytes long
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128.")
        
        self.initialise_tables()
        self.key = key
        self.round_keys = self.key_expansion(self.key)
    
    
    # Initialise tables
    def initialise_tables(self):
        """
        Initialise the AES S-box and inverse S-box
        """
        # AES S-box
        self.s_box = [
            #  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,   # 0
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,   # 1
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,   # 2
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,   # 3
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,   # 4
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,   # 5
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,   # 6
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,   # 7
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,   # 8
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,   # 9
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,   # A
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,   # B
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,   # C
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,   # D
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,   # E
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,   # F
        ]
        
        # AES S-box Inverse
        self.inv_s_box = [
            #  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,   # 0
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,   # 1
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,   # 2
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,   # 3
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,   # 4
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,   # 5
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,   # 6
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,   # 7
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,   # 8
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,   # 9
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,   # A
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,   # B
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,   # C
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,   # D
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,   # E
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,   # F
        ]
        
        # mix-matrix table
        self.mix_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02],
        ]
        
        # mix-matrix inverse table
        self.inv_mix_matrix = [
            [0x0e, 0x0b, 0x0d, 0x09],
            [0x09, 0x0e, 0x0b, 0x0d],
            [0x0d, 0x09, 0x0e, 0x0b],
            [0x0b, 0x0d, 0x09, 0x0e],
        ]
        
        # Rcon: round constants
        self.rcon = [
            0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
        ]
    
    
    # Function: Hex to Binary - helper function -> key expansion
    def hex2binary(self, hex):
        """
        Converts a hexadecimal string to its binary representation.
        
        Args:
            hex (str): The hexadecimal string to be converted.
        
        Returns:
            str: The binary representation of the input hexadecimal string.
        
        This function takes a hexadecimal string as input, converts it to an integer using base 16, and then converts that integer to a binary string. The binary string is prefixed with '0b' to indicate it's a binary number. This function is used in various cryptographic operations, including key expansion and encryption/decryption processes.
        """
        return bin(int(str(hex), 16))


    # Function: Hex XOR - helper function -> key expansion
    def hexor(self, hex1, hex2):
        """
        Performs a bitwise XOR operation on two hexadecimal strings.
        
        Args:
            hex1 (str): The first hexadecimal string.
            hex2 (str): The second hexadecimal string.
        
        Returns:
            str: The result of the XOR operation as a hexadecimal string.
        
        This function takes two hexadecimal strings as input, converts them to binary, performs a bitwise XOR operation,
        and returns the result as a hexadecimal string. The XOR operation is a fundamental operation in cryptography,
        used in various encryption algorithms, including AES. This function is used in the key expansion process to
        generate subsequent round keys.
        """
        # Convert to binary
        bin1 = self.hex2binary(hex1)
        bin2 = self.hex2binary(hex2)
        
        #calculate
        xord = int(bin1, 2) ^ int(bin2, 2)
        
        #cut prefix
        hexed = hex(xord)[2:]
        
        #leading 0s get cut above, if not length 8 add a leading 0
        if len(hexed) != 8:
            hexed = '0' + hexed
            
        return hexed


    # Function: Rot Word - helper function -> key expansion
    def rot_word(self, word):
        """
        Rotates the input word by one byte to the left.
        
        Args:
            word (str): The 4-byte word to be rotated.
        
        Returns:
            str: The rotated word.
        
        This function takes a 4-byte word as input and rotates it by one byte to the left. The rotation is a circular shift,
        meaning that the first byte becomes the last byte after rotation. This operation is used in the key expansion process
        of the AES algorithm to generate subsequent round keys.
        """
        return word[1:] + word[:1]


    # Function: Sub Word - helper function -> key expansion
    def sub_word(self, word):
        """
        Substitutes each byte of the input word using the S-box substitution table.
        
        Args:
            word (str): The 4-byte word to be substituted.
        
        Returns:
            str: The substituted word.
        
        This function iterates through each byte of the input word, substitutes it using the S-box substitution table,
        and returns the substituted word. The S-box substitution is based on the AES S-box, which is a non-linear substitution
        table used in the SubBytes step of the AES encryption algorithm. The function handles both hexadecimal and decimal
        values in the input word, ensuring that the correct substitution is made based on the S-box table.
        """
        sWord = ()
	
        #loop throug the current word
        for i in range(4):
            #check first char, if its a letter(a-f) get corresponding decimal
            #otherwise just take the value and add 1
            if word[i][0].isdigit() == False:
                row = ord(word[i][0]) - 86
            else:
                row = int(word[i][0])+1

            #repeat above for the seoncd char
            if word[i][1].isdigit() == False:
                col = ord(word[i][1]) - 86
            else:
                col = int(word[i][1])+1
            
            #get the index base on row and col (16x16 grid)
            sBoxIndex = (row*16) - (17-col)
            
            #get the value from sbox without prefix
            piece = hex(self.s_box[sBoxIndex])[2:]
            
            #check length to ensure leading 0s are not forgotton
            if len(piece) != 2:
                piece = '0' + piece
            
            #form tuple
            sWord = (*sWord, piece)
            
        #return string
        return ''.join(sWord)
    

    # Function: Key Expansion / Key Schedule
    def key_expansion(self, key_decimal):
        """
        Expands the initial key into a key schedule for all rounds of encryption.
        
        Args:
            key (list): The initial 16-byte (128-bit) key as a list of integers.
        
        Returns:
            list: The expanded key schedule as a list of integers.
        
        The key expansion process generates a total of 11 round keys (including the initial key)
        for the 10 rounds of AES-128, each consisting of 16 bytes (128 bits).
        
        The process involves:
        1. Using the initial key as the first round key.
        2. Generating subsequent round keys using the previous round key.
        3. Applying operations like SubWord (S-box substitution), RotWord (circular left shift),
           and XOR with round constant (Rcon) for every fourth word.
        
        This expanded key schedule is then used in the AddRoundKey step of each round
        during encryption and decryption.
        """
        key = []
        
        for i in range(0, 4):
            key.append([
                key_decimal[i + 0], 
                key_decimal[i + 4],
                key_decimal[i + 8],
                key_decimal[i + 12]
            ])
        
        key = [hex(value)[2:].zfill(2) for row in key for value in row]
        
        #prep w list to hold 44 tuples
        w = [()]*44
        
        #fill out first 4 words based on the key
        for i in range(4):
            w[i] = (key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
            
        #fill out the rest based on previews words, rotword, subword and rcon values
        for i in range(4, 44):
            #get required previous keywords
            temp = w[i-1]
            word = w[i-4]

            #if multiple of 4 use rot, sub, rcon etc
            if i % 4 == 0:
                x = self.rot_word(temp)
                y = self.sub_word(x)
                rcon = self.rcon[int(i/4)]

                temp = self.hexor(y, hex(rcon)[2:]) 
                
            #creating strings of hex rather than tuple
            word = ''.join(word)
            temp = ''.join(temp)
            
            #xor the two hex values
            xord = self.hexor(word, temp)
            w[i] = (xord[:2], xord[2:4], xord[4:6], xord[6:8])
            
        round_keys = []

        for i in range(0, 11):
            round_keys.append([
                " ".join(w[4*i + 0]).split(),
                " ".join(w[4*i + 1]).split(),
                " ".join(w[4*i + 2]).split(),
                " ".join(w[4*i + 3]).split()
            ])
        
        # Switch i,j to j,i and vice versa in all 4x4 matrix in round keys
        for i in range(11):
            for j in range(4):
                for k in range(j+1, 4):
                    round_keys[i][j][k], round_keys[i][k][j] = round_keys[i][k][j], round_keys[i][j][k]
                 
        # Convert round keys from hex to int base 16
        round_keys_int = []
        for round_key in round_keys:
            round_key_int = []
            for row in round_key:
                row_int = [int(value, 16) for value in row]
                round_key_int.append(row_int)
            round_keys_int.append(round_key_int)
            
        return round_keys_int
    
    
    # Function: Add Round Key
    def add_round_key(self, state, round_key):
        """
        Adds the round key to the state.
        
        Args:
            state (list): The current state of the AES algorithm as a 4x4 state of hex values.
            round_key (list): The round key to be added to the state as a list of integers.
        
        Returns:
            list: The updated state after adding the round key.
        
        The AddRoundKey step involves XORing each byte of the state with the corresponding byte 
        of the round key. This operation provides confusion in the cipher by combining the state 
        with the round key in a non-linear way.
        """
        if len(state) != 4 or len(round_key) != 4:
            raise ValueError("Both state and round key must be 4x4 matrices.")
        
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
                
        return state


    # Function: Subsitute Bytes
    def sub_bytes(self, state):
        """
        Applies the S-box to each byte in the state.
        
        Args:
            state (list): The current state of the AES algorithm as a list of integers.
        
        Returns:
            list: The updated state after applying the S-box to each byte.
        
        The SubBytes step is a non-linear substitution that operates independently on each byte 
        of the state using a substitution table (S-box). This operation provides confusion in the 
        cipher by obscuring the relationship between the key and the ciphertext.

        The process involves:
        1. Treating each byte of the state as two hexadecimal digits.
        2. Using these digits as row and column indices to look up a replacement byte in the S-box.
        3. Replacing the original byte with the value found in the S-box.

        This transformation helps to ensure non-linearity in the cipher, making it resistant to 
        differential and linear cryptanalysis.
        """
        for i in range(4):
            for j in range(4):
                # Get the byte value from the state
                byte_value = state[i][j]
                # Ensure the byte value is within the valid range for S-box
                if byte_value < 0 or byte_value > 255:
                    raise ValueError("Byte values must be in the range 0-255.")
                # Substitute using the S-box
                state[i][j] = self.s_box[byte_value]  # Accessing s_box directly with byte_value
                
        return state
    
    
    # Function: Inverse Subsitute Bytes
    def inv_sub_bytes(self, state):
        """
        Applies the inverse S-box to each byte in the state.
        
        Args:
            state (list): The current state of the AES algorithm as a list of integers.
        
        Returns:
            list: The updated state after applying the inverse S-box to each byte.
        
        The InvSubBytes step is a non-linear substitution that operates independently on each byte 
        of the state using the inverse substitution table (inverse S-box). This operation provides 
        diffusion in the cipher by obscuring the relationship between the key and the plaintext.

        The process involves:
        1. Treating each byte of the state as two hexadecimal digits.
        2. Using these digits as row and column indices to look up a replacement byte in the inverse S-box.
        3. Replacing the original byte with the value found in the inverse S-box.

        This transformation helps to ensure non-linearity in the cipher, making it resistant to 
        differential and linear cryptanalysis.
        """
        for i in range(4):
            for j in range(4):
                byte_value = state[i][j]
                if byte_value < 0 or byte_value > 255:
                    raise ValueError("Byte values must be in the range 0-255.")
                # Substitute using the inverse S-box
                state[i][j] = self.inv_s_box[byte_value]  # Accessing inv_s_box with byte_value
                
        return state


    # Function: Shift Rows
    def shift_rows(self, state):
        """
        Shifts the rows of the state.
        Args:
            state (list): The current state of the AES algorithm as a 4x4 state of bytes.
        
        Returns:
            list: The updated state after shifting the rows.
        
        The ShiftRows step operates on the rows of the state:
        1. The first row is not shifted.
        2. The second row is shifted 1 byte to the left.
        3. The third row is shifted 2 bytes to the left.
        4. The fourth row is shifted 3 bytes to the left.

        This operation provides diffusion in the cipher by spreading the influence of each 
        byte over multiple rounds of processing. It ensures that the bytes from each column 
        are spread out to different columns in subsequent rounds, enhancing the overall 
        security of the encryption process.
        """
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
        
        return state
    
    
    # Function: Inverse Shift Rows
    def inv_shift_rows(self, state):
        """
        Inverts the ShiftRows operation.
        
        Args:
            state (list): The current state of the AES algorithm as a 4x4 state of bytes.
        
        Returns:
            list: The updated state after inverting the ShiftRows operation.
        
        The Inverse ShiftRows step operates on the rows of the state in reverse order of the ShiftRows operation:
        1. The first row is not shifted.
        2. The second row is shifted 3 bytes to the right.
        3. The third row is shifted 2 bytes to the right.
        4. The fourth row is shifted 1 byte to the right.

        This operation is the inverse of the ShiftRows operation, ensuring that the bytes from each column are restored to their original positions in the state, effectively undoing the diffusion provided by the ShiftRows operation.
        """
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
        
        return state
    
    # Function: Galois Multiplications
    def galois_multiply(self, a, b):
        """
        Performs Galois Field (2^8) multiplication.
        
        Args:
            a (int): The first byte to be multiplied.
            b (int): The second byte to be multiplied.
        
        Returns:
            int: The result of the Galois Field multiplication.
        
        The Galois Field (2^8) multiplication is performed using bitwise operations.
        """
        result = 0
        
        for _ in range(8):
            if b & 1:
                result ^= a
        
            high_bit_set = a & 0x80
            a <<= 1
        
            if high_bit_set:
                a ^= 0x1B  # Polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
        
            b >>= 1
        
        return result & 0xFF
    
    
    # Function: Mix Columns
    def mix_columns(self, state):
        """
        Mixes the columns of the state.
        
        Args:
            state (list): The current state of the AES algorithm as a 4x4 state of bytes.
        
        Returns:
            list: The updated state after mixing the columns.
        
        The MixColumns step operates on the columns of the state:
        1. Each column is treated as a polynomial over GF(2^8) and multiplied with a fixed polynomial.
        2. This multiplication is performed using arithmetic in GF(2^8), which involves the use of 
           irreducible polynomials (e.g., x^8 + x^4 + x^3 + x + 1).
        3. The result is a new column that is a linear combination of the original column.

        This operation ensures that each bit of the state's data is affected by multiple 
        bits of the key schedule, which helps to distribute the influence of the key schedule 
        more evenly across the state. This increased diffusion makes the cipher more resistant 
        to differential and linear cryptanalysis.
        """
        # Create a new state for the mixed columns
        mixed_state = [[0] * 4 for _ in range(4)]

        for c in range(4):  # Process each column individually
            for i in range(4):
                mixed_state[i][c] = (
                    self.galois_multiply(self.mix_matrix[i][0], state[0][c]) ^
                    self.galois_multiply(self.mix_matrix[i][1], state[1][c]) ^
                    self.galois_multiply(self.mix_matrix[i][2], state[2][c]) ^
                    self.galois_multiply(self.mix_matrix[i][3], state[3][c])
                )

        return mixed_state
    
    
    # Function: Inverse Mix Columns
    def inv_mix_columns(self, state):
        """
        Inverse Mixes the columns of the state.
        
        Args:
            state (list): The current state of the AES algorithm as a 4x4 state of bytes.
        
        Returns:
            list: The updated state after mixing the columns.
        
        The Inverse MixColumns step operates on the columns of the state:
        1. Each column is treated as a polynomial over GF(2^8) and multiplied with a fixed polynomial.
        2. This multiplication is performed using arithmetic in GF(2^8), which involves the use of 
           irreducible polynomials (e.g., x^8 + x^4 + x^3 + x + 1).
        3. The result is a new column that is a linear combination of the original column.

        This operation ensures that each bit of the state's data is affected by multiple 
        bits of the key schedule, which helps to distribute the influence of the key schedule 
        more evenly across the state. This increased diffusion makes the cipher more resistant 
        to differential and linear cryptanalysis.
        """
        inv_mixed_state = [[0] * 4 for _ in range(4)]

        for c in range(4):
            for i in range(4):
                inv_mixed_state[i][c] = (
                    self.galois_multiply(self.inv_mix_matrix[i][0], state[0][c]) ^
                    self.galois_multiply(self.inv_mix_matrix[i][1], state[1][c]) ^
                    self.galois_multiply(self.inv_mix_matrix[i][2], state[2][c]) ^
                    self.galois_multiply(self.inv_mix_matrix[i][3], state[3][c])
                )

        return inv_mixed_state
        
    
    # Function: Beautify store state
    def formatty(self, matrix):
        return [[format(value, '02x') for value in row] for row in matrix]

    
    # Function: AES-128bit encryption
    def encrypt(self, plaintext):
        """
        Encrypts the plaintext using the AES algorithm.
        
        Args:
            plaintext (list): The plaintext to be encrypted as a list of integers.
        
        Returns:
            list: The encrypted ciphertext as a list of integers.
            dict: A dictionary containing the state at various stages of each round:
                  - 'Start of Round': The state at the beginning of each round
                  - 'After SubBytes': The state after applying the SubBytes transformation
                  - 'After ShiftRows': The state after applying the ShiftRows transformation
                  - 'After MixColumns': The state after applying the MixColumns transformation
                  - 'Round Key': The round key used for each round
        Raises:
            ValueError: If the plaintext is not a 4x4 matrix of hex strings.
            
        The encryption process follows these steps:
        1. Key Expansion: The original key is expanded into a key schedule.
        2. Initial Round: AddRoundKey
        3. Main Rounds (9 for AES-128):
           a. SubBytes: Substitute each byte using the S-box
           b. ShiftRows: Cyclically shift the rows of the state
           c. MixColumns: Mix the data within each column of the state
           d. AddRoundKey: XOR the state with the round key
        4. Final Round:
           a. SubBytes
           b. ShiftRows
           c. AddRoundKey

        This process ensures that the ciphertext has high diffusion and confusion,
        making it resistant to various cryptanalytic attacks.
        """
        if isinstance(plaintext, list) and all(isinstance(row, list) and len(row) == 4 for row in plaintext):
            state = [[int(value, 16) for value in row] for row in plaintext]  # Convert hex strings to integers
        else:
            raise ValueError("Plaintext must be a 4x4 matrix of hex strings.")

        round_key = [list(self.key[i:i+4]) for i in range(0, len(self.key), 4)]
        
        # Ensure round_key is a 2D list
        if len(round_key) != 4 or any(len(row) != 4 for row in round_key):
            raise ValueError("Round key must be a 4x4 matrix.")

        empty_state = [
            ["", "", "", ""],
            ["", "", "", ""],
            ["", "", "", ""],
            ["", "", "", ""]
        ]
        state_data = {
            "Start of Round" : [self.formatty(state)],
            "After SubBytes" : [empty_state],
            "After ShiftRows" : [empty_state],
            "After MixColumns" : [empty_state],
            "Round Key" : [self.formatty(round_key)]
        }
        state = self.add_round_key(state, round_key)

        # 10 rounds
        for round in range(1, 11):
            # Start of the Round-i
            state_data["Start of Round"].append(self.formatty(state))
            
            # Sub Bytes
            state = self.sub_bytes(state)
            state_data["After SubBytes"].append(self.formatty(state))
                        
            # Shift Rows
            state = self.shift_rows(state)
            state_data["After ShiftRows"].append(self.formatty(state))
                        
            # Mix Columns
            if round != 10:
                state = self.mix_columns(state)
                state_data["After MixColumns"].append(self.formatty(state))
            else:
                state_data["After MixColumns"].append(empty_state)
                        
            # Round Key
            state_data["Round Key"].append(self.formatty(self.round_keys[round]))
            
            # Final State of Round
            state = self.add_round_key(state, self.round_keys[round])
        
        # Final State
        state_data["Start of Round"].append(self.formatty(state))
        state_data["After SubBytes"].append(empty_state)
        state_data["After ShiftRows"].append(empty_state)
        state_data["After MixColumns"].append(empty_state)
        state_data["Round Key"].append(empty_state)

        return state, state_data
    
    
    # Function: AES-128bit decryption
    def decrypt(self, ciphertext):
        """
        Decrypts a given ciphertext using AES-128 decryption.
        
        Args:
            ciphertext (list): The ciphertext to decrypt, formatted as a 4x4 matrix of hex strings.
        
        Returns:
            state (list): The final decrypted state as a 4x4 matrix.
            state_data (dict): A dictionary containing intermediate states after each decryption round for debugging purposes.
        
        Raises:
            ValueError: If the ciphertext is not provided as a 4x4 matrix of hex strings.
            
        Key Expansion: The original key is expanded into a key schedule used across decryption rounds.
        
        Initial Round: 
            - AddRoundKey: XORs the ciphertext state with the final round key.
        
        Main Rounds (9 rounds for AES-128 decryption):
            1. InvShiftRows: Inversely shifts rows to revert the original positions.
            2. InvSubBytes: Applies the inverse S-box to each byte.
            3. AddRoundKey: XORs the state with the round key for the current round.
            4. InvMixColumns: Reverses the column mixing operation, applied only in rounds 1-9.
        
        Final Round:
            1. InvShiftRows
            2. InvSubBytes
            3. AddRoundKey
        """
        if isinstance(ciphertext, list) and all(isinstance(row, list) and len(row) == 4 for row in ciphertext):
            # Convert hex strings to integers
            state = [[int(value, 16) if isinstance(value, str) else value for value in row] for row in ciphertext]
        else:
            raise ValueError("Ciphertext must be a 4x4 matrix of hex strings.")

        # Initial round key addition
        round_key = self.round_keys[-16:]
        state = self.add_round_key(state, round_key)
        
        # Initialize state data for debugging
        empty_state = [["", "", "", ""], ["", "", "", ""], ["", "", "", ""], ["", "", "", ""]]
        state_data = {
            "Start of Round": [self.formatty(state)],
            "After InvSubBytes": [empty_state],
            "After InvShiftRows": [empty_state],
            "After InvMixColumns": [empty_state],
            "Round Key": [self.formatty(round_key)]
        }

        # 9 main rounds
        for round in range(9, 0, -1):
            print(f"Start of Round {round}: {self.formatty(state)}")
            state = self.inv_shift_rows(state)
            state_data["After InvShiftRows"].append(self.formatty(state))
            
            state = self.inv_sub_bytes(state)
            state_data["After InvSubBytes"].append(self.formatty(state))

            round_key = self.round_keys[round * 16: (round + 1) * 16]
            state = self.add_round_key(state, round_key)
            state_data["Round Key"].append(self.formatty(round_key))

            if round > 1:
                state = self.inv_mix_columns(state)
                state_data["After InvMixColumns"].append(self.formatty(state))

        # Final round
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_keys[:16])

        # Record final state
        state_data["Start of Round"].append(self.formatty(state))
        state_data["After InvSubBytes"].append(empty_state)
        state_data["After InvShiftRows"].append(empty_state)
        state_data["After InvMixColumns"].append(empty_state)
        state_data["Round Key"].append(empty_state)

        return state, state_data