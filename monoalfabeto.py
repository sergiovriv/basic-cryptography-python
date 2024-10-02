import argparse
def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = "".join(dict.fromkeys(key.upper().replace("J", "I") + alphabet))
    matrix = [key[i:i+5] for i in range(0, 25, 5)]
    return matrix

def find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return -1, -1

def playfair_encrypt(plaintext, key):
    matrix = create_playfair_matrix(key)
    plaintext = plaintext.upper().replace("J", "I")
    ciphertext = ""
    
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i+2]
        if len(pair) == 1:
            pair += "X"
        elif pair[0] == pair[1]:
            pair = pair[0] + "X"
        
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            ciphertext += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
        elif col1 == col2:
            ciphertext += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    plaintext = ""
    
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        
        if row1 == row2:
            plaintext += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
        elif col1 == col2:
            plaintext += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    
    return plaintext

def print_help():
    help_message = """
    Playfair Cipher Program
    ------------------------
    
    This program allows you to encrypt and decrypt messages using the Playfair cipher.
    
    Commands:
      - Enter 'e' to encrypt a message.
      - Enter 'd' to decrypt a message.
      - Enter 'q' to quit the program.
    
    Encryption Process:
      1. Input your plaintext (uppercase letters only, no spaces).
      2. The program will encrypt your message using the specified key.
      3. If there are duplicate letters in a pair, an 'X' will be added.
      4. The output will be your encrypted text.

    Decryption Process:
      1. Input your ciphertext (uppercase letters only).
      2. The program will decrypt your message using the same key used for encryption.
      3. The output will be your decrypted text.

    Note: The key should consist of uppercase letters and will be used to create a Playfair matrix.
    
    Example Key: "MONARCHY"
    
    Enjoy using the Playfair cipher!
    """
    print(help_message)
def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(description='Playfair Cipher Encryption/Decryption')
    
    parser.add_argument('-help', action='help', help='Show this help message and exit')
    parser.add_argument('--encrypt', '-e', metavar='PLAINTEXT', type=str,
                        help='Encrypt the given plaintext (uppercase, no spaces)')
    parser.add_argument('--decrypt', '-d', metavar='CIPHERTEXT', type=str,
                        help='Decrypt the given ciphertext (uppercase)')
    parser.add_argument('--key', type=str, default='MONAR',
                        help='Set the encryption/decryption key (default: MONAR)')
    
    return parser
def main():
    
    # Create the argument parser
    parser = create_parser()
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Use the provided key or fallback to default
    key = args.key

    # Check if any flags were provided
    if args.encrypt:
        plaintext = args.encrypt
        ciphertext = playfair_encrypt(plaintext, key)
        print("Encrypted text:", ciphertext)
    elif args.decrypt:
        ciphertext = args.decrypt
        plaintext = playfair_decrypt(ciphertext, key)
        print("Decrypted text:", plaintext)
    else:
        # No flags provided, prompt the user for input
        choice = input("Enter 'e' for encryption or 'd' for decryption (q to quit) or 'help' for help: ")

        if choice == 'q':
            print("Bye")
        elif choice == 'help':
            print_help()
        elif choice == 'e':
            plaintext = input("Enter the plaintext (uppercase, no spaces): ")
            ciphertext = playfair_encrypt(plaintext, key)
            print("Encrypted text:", ciphertext)
        elif choice == 'd':
            ciphertext = input("Enter the ciphertext (uppercase): ")
            plaintext = playfair_decrypt(ciphertext, key)
            print("Decrypted text:", plaintext)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
