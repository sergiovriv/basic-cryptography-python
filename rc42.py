#!/usr/bin/env python3

import argparse
import sys

# RC4 implementation (unchanged)
state = [None] * 256
p = q = None

def setKey(key):
    global p, q, state
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        if len(key) > 0:
            j = (j + state[i] + key[i % len(key)]) % 256
        else:
            j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]

def byteGenerator():
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    return state[(state[p] + state[q]) % 256]

def encrypt(inputString):
    return [ord(p) ^ byteGenerator() for p in inputString]

def decrypt(inputByteList):
    return "".join([chr(c ^ byteGenerator()) for c in inputByteList])

# New main function with CLI options
def main():
    parser = argparse.ArgumentParser(description="RC4 encryption/decryption tool")
    parser.add_argument("-k", "--key", required=True, help="Encryption/decryption key")
    parser.add_argument("-f", "--file", help="Input file (if not specified, read from stdin)")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt mode (default is encrypt)")
    args = parser.parse_args()

    # Set the key
    setKey([ord(c) for c in args.key])

    # Read input
    if args.file:
        with open(args.file, 'r') as f:
            input_data = f.read()
    else:
        input_data = sys.stdin.read()

    # Process data
    if args.decrypt:
        # Assuming input is hex-encoded for decryption
        input_bytes = bytes.fromhex(input_data.strip())
        result = decrypt(input_bytes)
        print(result)
    else:
        result = encrypt(input_data)
        print(''.join(f'{b:02x}' for b in result))

if __name__ == '__main__':
    main()
#!/usr/bin/env python3

import sys

# RC4 implementation
state = [None] * 256
p = q = None

def setKey(key):
    global p, q, state
    state = [n for n in range(256)]
    print("Valor inicial de S:", state)
    p = q = j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]
    print("Valor de S después de la fase inicial:", state)

def byteGenerator():
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    print("S después de generar keystream:", state)
    return state[(state[p] + state[q]) % 256]

def encrypt(char):
    keystream = byteGenerator()
    encrypted = ord(char) ^ keystream
    print(f"Carácter: {char}")
    print(f"ASCII: {ord(char)}, Binario: {bin(ord(char))[2:].zfill(8)}")
    print(f"Keystream: Decimal: {keystream}, Binario: {bin(keystream)[2:].zfill(8)}")
    print(f"Cifrado: Binario: {bin(encrypted)[2:].zfill(8)}, Hexadecimal: {encrypted:02x}")
    return encrypted

def decrypt(hex_string):
    bytes_to_decrypt = bytes.fromhex(hex_string)
    decrypted = ""
    for byte in bytes_to_decrypt:
        decrypted += chr(byte ^ byteGenerator())
    return decrypted

def create_parser():
    parser = argparse.ArgumentParser(description="RC4 encryption/decryption tool")
    parser.add_argument("-k", "--key", required=True, help="Encryption/decryption key in hexadecimal")
    parser.add_argument("-E", help="Encrypt text provided as argument")
    parser.add_argument("-D", help="Decrypt text provided as argument (in hexadecimal)")
    parser.add_argument("-e", help="Encrypt text from file")
    parser.add_argument("-d", help="Decrypt text from file (in hexadecimal)")
    return parser

def read_file(filename):
    with open(filename, 'r') as file:
        return file.read().strip()

def write_output(text, mode):
    filename = f"output_{mode}.txt"
    with open(filename, 'w') as file:
        file.write(text)
    print(f"Output written to {filename}")

def print_help():
    print("Usage:")
    print("  -k KEY    Specify the encryption/decryption key in hexadecimal")
    print("  -E TEXT   Encrypt the provided text")
    print("  -D TEXT   Decrypt the provided text (in hexadecimal)")
    print("  -e FILE   Encrypt text from the specified file")
    print("  -d FILE   Decrypt text from the specified file (in hexadecimal)")
    print("  Or run without arguments for interactive mode")

def main():
    parser = create_parser()
    args = parser.parse_args()
    key = bytes.fromhex(args.key)
    setKey(key)

    if args.E:
        plaintext = args.E
        ciphertext = ''.join(f'{b:02x}' for b in encrypt(plaintext))
        print("Encrypted text:", ciphertext)
        write_output(ciphertext, "enc")
    elif args.D:
        ciphertext = args.D
        plaintext = decrypt(ciphertext)
        print("Decrypted text:", plaintext)
        write_output(plaintext, "dec")
    elif args.e:
        plaintext = read_file(args.e)
        ciphertext = ''.join(f'{b:02x}' for b in encrypt(plaintext))
        print("Encrypted text:", ciphertext)
        write_output(ciphertext, "enc")
    elif args.d:
        ciphertext = read_file(args.d)
        plaintext = decrypt(ciphertext)
        print("Decrypted text:", plaintext)
        write_output(plaintext, "dec")
    else:
        while True:
            choice = input("Enter 'e' for encryption or 'd' for decryption (q to quit) or 'help' for help: ")

            if choice == 'q':
                print("Bye")
                break
            elif choice == 'help':
                print_help()
            elif choice == 'e':
                print("Enter the plaintext (press Enter twice to finish):")
                plaintext = sys.stdin.read().strip()
                ciphertext = ''.join(f'{b:02x}' for b in encrypt(plaintext))
                print("Encrypted text:", ciphertext)
                write_output(ciphertext, "enc")
            elif choice == 'd':
                ciphertext = input("Enter the ciphertext (in hexadecimal): ")
                plaintext = decrypt(ciphertext)
                print("Decrypted text:", plaintext)
                write_output(plaintext, "dec")
            else:
                print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
