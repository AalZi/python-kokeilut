import json
import re
import random
import string
import os  # Import at the start for broader access

# Caesar cipher functions remain unchanged
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            shifted = (ord(char) - ascii_offset + shift) % 26 + ascii_offset
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# Lists to store encrypted passwords, shifts, websites, and usernames
encrypted_passwords = []
encryption_shifts = []  # Store each password's shift for decryption
websites = []
usernames = []

def generate_password(length):
    """
    Generates a random strong password of the specified length.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A random strong password.
    """
    if length < 8:
        raise ValueError("Password length should be at least 8 characters.")

    # Ensure at least one of each type for strong password criteria
    characters = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]

    # Fill the rest of the password length with random choices
    characters += [random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length - 4)]
    random.shuffle(characters)

    return ''.join(characters)


def is_strong_password(password):
    """
    Checks if a password meets certain criteria for strength.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if the password is strong, False otherwise.
    """
    # Check length
    if len(password) < 8:
        return False
    
    # Check complexity
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"\W", password):
        return False
    
    # Check uniqueness
    #if len(set(password)) < len(password):
        #return False

    return True

def add_password():
    while True:
        website = input("Enter the website: ")
        username = input("Enter the username: ")
        password = input("Enter the password (or 'generate' to create a random one): ")
        if password == "generate":
            password = generate_password(random.randint(8, 20))
        
        if not is_strong_password(password):
            print("Password is not strong enough. Please try again.")
            continue
        
        shift = random.randint(3, 5)  # Random shift for encryption
        encrypted_passwords.append(caesar_encrypt(password, shift))
        encryption_shifts.append(shift)  # Store the shift
        websites.append(website)
        usernames.append(username)
        break

def get_password():
    while True:
        website = input("Enter the website: ")
        username = input("Enter the username: ")

        try:
            index = websites.index(website)
            if usernames[index] == username:
                encrypted_password = encrypted_passwords[index]
                shift = encryption_shifts[index]
                print(f"Password for {username} on {website}: {caesar_decrypt(encrypted_password, shift)}")
                break
            else:
                print("Username not found for this website.")
        except ValueError:
            print("Website not found. Please try again.")

def save_passwords():
    while True:
        filename = input("Enter the filename: ")
        
        if os.path.exists(filename):
            print("File already exists. Please try again.")
            continue

        with open(filename, 'w') as f:
            json.dump({
                'websites': websites,
                'usernames': usernames,
                'encrypted_passwords': encrypted_passwords,
                'encryption_shifts': encryption_shifts
            }, f)
        break

def load_passwords():
    global websites, usernames, encrypted_passwords, encryption_shifts
    while True:
        filename = input("Enter the filename: ")

        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                websites = data['websites']
                usernames = data['usernames']
                encrypted_passwords = data['encrypted_passwords']
                encryption_shifts = data['encryption_shifts']
            print("Passwords loaded successfully!")
            break
        except (FileNotFoundError, KeyError):
            print("File not found or data format error. Please try again.")
            continue

def main():
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()