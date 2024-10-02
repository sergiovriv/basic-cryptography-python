import argparse

def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(description='Vigenère Cipher Encryption/Decryption')
    
    parser.add_argument('-help', action='help', help='Show this help message and exit')
    parser.add_argument('--encrypt', '-e', metavar='PLAINTEXT', type=str,
                        help='Encrypt the given plaintext (uppercase, no spaces)')
    parser.add_argument('--decrypt', '-d', metavar='CIPHERTEXT', type=str,
                        help='Decrypt the given ciphertext (uppercase)')
    parser.add_argument('--key', type=str, default='MONAR',
                        help='Set the encryption/decryption key (default: MONAR)')
    
    return parser

def vigenere_encrypt(plaintext, key):
    """Encrypt the plaintext using the Vigenère cipher."""
    ciphertext = []
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        if char.isalpha():  # Ensure we only encrypt alphabetic characters
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted_char)
        else:
            ciphertext.append(char)  # Non-alphabetic characters are added unchanged
    
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, key):
    """Decrypt the ciphertext using the Vigenère cipher."""
    plaintext = []
    key_length = len(key)
    
    for i, char in enumerate(ciphertext):
        if char.isalpha():  # Ensure we only decrypt alphabetic characters
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            plaintext.append(decrypted_char)
        else:
            plaintext.append(char)  # Non-alphabetic characters are added unchanged
    
    return ''.join(plaintext)

def main():
    # Create the argument parser
    parser = create_parser()
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Use the provided key or fallback to default
    key = args.key.upper()

    # Check if any flags were provided
    if args.encrypt:
        plaintext = args.encrypt.upper()
        ciphertext = vigenere_encrypt(plaintext, key)
        print("Encrypted text:", ciphertext)
    elif args.decrypt:
        ciphertext = args.decrypt.upper()
        plaintext = vigenere_decrypt(ciphertext, key)
        print("Decrypted text:", plaintext)
    else:
        # No flags provided, prompt the user for input
        choice = input("Enter 'e' for encryption or 'd' for decryption (q to quit) or 'help' for help: ")

        if choice == 'q':
            print("Bye")
        elif choice == 'help':
            print(parser.format_help())
        elif choice == 'e':
            plaintext = input("Enter the plaintext (uppercase, no spaces): ").upper()
            ciphertext = vigenere_encrypt(plaintext, key)
            print("Encrypted text:", ciphertext)
        elif choice == 'd':
            ciphertext = input("Enter the ciphertext (uppercase): ").upper()
            plaintext = vigenere_decrypt(ciphertext, key)
            print("Decrypted text:", plaintext)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

