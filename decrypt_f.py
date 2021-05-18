from cryptography.fernet import Fernet

key = input("Enter your key:")
cipher = Fernet(key)

with open('encrypted_data.txt', 'rb') as df:
    encrypted_data = df.read()

decrypted_file = cipher.decrypt(encrypted_data)

with open('data.txt', 'wb') as df:
    df.write(decrypted_file)

