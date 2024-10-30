from aes import AES


def hex_string_to_hex_4x4_matrix(string):
    matrix = [ ["", "", "", ""], ["", "", "", ""], ["", "", "", ""], ["", "", "", ""] ]
    elements = string.split()

    for i in range(0, 4):
        for j in range(0, 4):
            matrix[j][i] = "0x" + elements[4*i + j]
            
    return matrix


def hex_4x4_matrix_to_hex_string(matrix):
    hex_string = ""
    
    for i in range (0, 4):
        for j in range(0, 4):
            hex_string += matrix[j][i] + " "
    
    return hex_string


def print_state(state, itr):
    keys = list(state.keys())
    print("+ " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + ")
    print(f"| {keys[0]:^20} | {keys[1]:^20} | {keys[2]:^20} | {keys[3]:^20} | {keys[4]:^20} |")
    print("+ " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + ")

    for i in range(itr + 1):
        for j in range(4):
            values = []
            
            for key in keys:
                values.append(' '.join(map(str, state[key][i][j])))
            
            print(f"| {values[0]:^20} | {values[1]:^20} | {values[2]:^20} | {values[3]:^20} | {values[4]:^20} |")
        
        print("+ " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + " + "-" * 20 + " + ")
 

def main():
    key = input("Key: ")
    # key = "0f 15 71 c9 47 d9 e8 59 0c b7 ad d6 af 7f 67 98"
    plaintext = input("Plain text: ")
    # plaintext = "01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10"
    
    # Convert to 4x4 matrix
    key = hex_string_to_hex_4x4_matrix(key)
    plaintext= hex_string_to_hex_4x4_matrix(plaintext)
            
    # Initialise AES
    aes = AES(key)
       
    # Encryption
    ciphertext, round_states = aes.encrypt(plaintext)
    ciphertext = hex_4x4_matrix_to_hex_string(aes.formatty(ciphertext))
    print(f"Ciphertext: {ciphertext}")
    
    # Print Round Data
    rounds = int(input("Enter number of rounds to see: "))
    print_state(round_states, rounds)

if __name__ == "__main__":
    main()