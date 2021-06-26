from cryptography.hazmat.primitives.kdf import pbkdf2
from passlib.context import CryptContext

context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    pbkdf2_sha256__default_rounds=50000
)

# hashed_password = context.hash("password")
# print(hashed_password)
# print(context.verify("password", hashed_password))


def create_pass(my_pass):
    hashed_password = context.hash(my_pass)
    with open("hashed_pass.txt", 'w') as f:
        f.write(hashed_password)


def check_pass(my_pass):
    with open("hashed_pass.txt", 'r') as f:
        file = f.read()
    return context.verify(my_pass, file)
