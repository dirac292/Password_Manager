import base64
import random
import os
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog
import pyperclip
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



# ---------------------------- PASSWORD AND KEY GENERATOR ------------------------------- #

def gen_key(master_pass):

    password = master_pass.encode()

    mysalt = b'b9\xcc\x8d_B\xdd\xe9@.\xcf\xb1;\xac\x8f\xac'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=mysalt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def gen_pass():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
               'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
               'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']


    pass_let=[random.choice(letters) for _ in range(random.randint(8, 10))]
    pass_sym=[random.choice(symbols) for _ in range(random.randint(2, 4))]
    pass_num=[random.choice(numbers) for _ in range(random.randint(2, 4))]

    pass_list=pass_let+pass_sym+pass_num

    random.shuffle(pass_list)

    password = "".join(pass_list)

    password_entry.insert(0,password)
    pyperclip.copy(password)



# ---------------------------- SAVE PASSWORD ------------------------------- #
def encryp(key):

    cipher = Fernet(key)

    with open("data.txt", 'rb') as f:
        e_file = f.read()
    encrypted_file = cipher.encrypt(e_file)
    with open("encrypted_data.txt", 'wb') as ef:
        ef.write(encrypted_file)

    os.remove("data.txt")

def decryp(key):

    cipher = Fernet(key)

    with open('encrypted_data.txt', 'rb') as df:
        encrypted_data = df.read()

    decrypted_file = cipher.decrypt(encrypted_data)

    with open('data.txt', 'wb') as df:
        df.write(decrypted_file)

def view_txt():
    master_pass = simpledialog.askstring(title='Test', prompt='Enter the master password?',show="*")
    if master_pass == "password":
        key = gen_key(master_pass)
        decryp(key)
        messagebox.showinfo(title="Prompt", message="Close the Program to view the File.Please Delete the file after use.")
    else:
        messagebox.showinfo(title="Oops", message="Check password again")

def save_pass():

    website=website_entry.get()
    email=email_entry.get()
    password=password_entry.get()

    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(title="Oops", message="Please don't leave any fields empty!")
    else:
        is_ok=messagebox.askokcancel(title="website",message=f"These are the details entered:\n Email: {email}"
                               f"\nPassword:{password} \nIs it ok to save?")

        if is_ok:
            master_pass = simpledialog.askstring(title='Test', prompt='Enter the master password?',show="*")
            #Sample Password For now
            if master_pass=="password":
                key=gen_key(master_pass)
                decryp(key)
                with open("data.txt","a") as data_file:
                    data_file.write(f"{website} | {email} | {password}\n")
                    website_entry.delete(0,END)
                    password_entry.delete(0,END)
                encryp(key)
            else:
                messagebox.showinfo(title="Oops", message="Check password again")







# ---------------------------- UI SETUP ------------------------------- #

window = Tk()
window.title("Password Manager")
window.config(padx=50,pady=50)

canvas=Canvas(width=200,height=200)
pass_img=PhotoImage(file="download.png")
canvas.create_image(100,100,image=pass_img)
canvas.grid(row=0,column=1)

website_label=Label(text="Website:")
website_label.grid(row=1,column=0)
email_label=Label(text="Email/Username:")
email_label.grid(row=2,column=0)
pass_label=Label(text="Password:")
pass_label.grid(row=3,column=0)


#Entries

website_entry= Entry(width=35)
website_entry.grid(row=1,column=1,columnspan=2)
website_entry.focus()
email_entry= Entry(width=35)
email_entry.grid(row=2,column=1,columnspan=2)
email_entry.insert(0,"abc@gmail.com")
password_entry= Entry(width=21)
password_entry.grid(row=3,column=1)

gen_pass=Button(text="Generate Password",command=gen_pass)
gen_pass.grid(row=3,column=2)
add_button=Button(text="Add",width=35,command=save_pass)
add_button.grid(row=4,column=1,columnspan=2)

view_pass=Button(text="View Passwords in a Text File",command=view_txt)
view_pass.grid(row=5,column=1)



window.mainloop()