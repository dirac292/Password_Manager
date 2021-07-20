import json
import re
import base64
import random
import os
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
from ttkthemes import ThemedTk
import pyperclip
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os.path
import time
from threading import Event
import hash
import pass_check
import csv
# import matplotlib
# matplotlib.use('Agg')


# ---------------------------- PASSWORD AND KEY GENERATOR ------------------------------- #

# if os.environ.get('DISPLAY', '') == '':
#     print('no display found. Using :0.0')
#     os.environ.__setitem__('DISPLAY', ':0.0')

autocompleteList = []
with open('user.csv', 'r') as f:
    file = csv.DictReader(f)
    autocompleteList = []
    for col in file:
        autocompleteList.append(col['Username'])


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

    pass_let = [random.choice(letters) for _ in range(random.randint(8, 10))]
    pass_sym = [random.choice(symbols) for _ in range(random.randint(2, 4))]
    pass_num = [random.choice(numbers) for _ in range(random.randint(2, 4))]

    pass_list = pass_let+pass_sym+pass_num

    random.shuffle(pass_list)

    password = "".join(pass_list)

    password_entry.insert(0, password)
    pyperclip.copy(password)


def reset_pass():
    if os.path.isfile("encrypted_data.txt"):
        os.remove("encrypted_data.txt")
        if os.path.isfile('data.json'):
            os.remove("data.json")
        messagebox.showinfo(
            title="Prompt", message="All Password directories cleared.")
    else:
        messagebox.showinfo(
            title="Prompt", message="Directories already empty.")

        # ---------------------------- SAVE PASSWORD ------------------------------- #


def del_f():
    if messagebox.askokcancel("Prompt", "Are you sure you want to delte the file?"):
        if os.path.isfile('data.json'):
            os.remove("data.json")
            messagebox.showinfo(
                title="Prompt", message="File Successfuly Removed.")
        else:
            messagebox.showinfo(
                title="Prompt", message="File is not on the system.")


def new_del():
    if os.path.isfile('data.json'):
        os.remove("data.json")


def encryp(key):

    cipher = Fernet(key)

    with open("data.json", 'rb') as f:
        e_file = f.read()
    encrypted_file = cipher.encrypt(e_file)
    with open("encrypted_data.txt", 'wb') as ef:
        ef.write(encrypted_file)
        print("written")

    os.remove("data.json")


def decryp(key):

    cipher = Fernet(key)

    with open('encrypted_data.txt', 'rb') as df:
        encrypted_data = df.read()

    decrypted_file = cipher.decrypt(encrypted_data)

    with open('data.json', 'wb') as df:
        df.write(decrypted_file)


# def view_txt():
#     # some code to time

#     if os.path.isfile("encrypted_data.txt"):
#         master_pass = simpledialog.askstring(
#             title='Test', prompt='Enter the master password?', show="*")
#         if hash.check_pass(master_pass):
#             key = gen_key(master_pass)

#             decryp(key)
#             messagebox.showinfo(
#                 title="Prompt", message="File will be delted in a minute automatically.")
#             os.system("start " + "data.json")

#         else:
#             messagebox.showinfo(title="Oops", message="Check password again")
#     else:
#         messagebox.showinfo(
#             title="Prompt", message="Password Directory Empty.")

#     window.after(60000, new_del)
    # time.sleep(25)
    # new_del()


# ---------------------------- AUTO COMPLETE FEATURE ------------------------------- #
# Class Autocomplete Code Credits: uroshekic  https: // gist.github.com/uroshekic/11078820 #


class AutocompleteEntry(ttk.Entry):
    def __init__(self, autocompleteList, *args, **kwargs):
        # Listbox length
        if 'listboxLength' in kwargs:
            self.listboxLength = kwargs['listboxLength']
            del kwargs['listboxLength']
        else:
            self.listboxLength = 8

        # Custom matches function
        if 'matchesFunction' in kwargs:
            self.matchesFunction = kwargs['matchesFunction']
            del kwargs['matchesFunction']
        else:
            def matches(fieldValue, acListEntry):
                pattern = re.compile(
                    '.*' + re.escape(fieldValue) + '.*', re.IGNORECASE)
                return re.match(pattern, acListEntry)

            self.matchesFunction = matches

        ttk.Entry.__init__(self, *args, **kwargs)
        self.focus()

        self.autocompleteList = autocompleteList

        self.var = self["textvariable"]
        if self.var == '':
            self.var = self["textvariable"] = StringVar()

        self.var.trace('w', self.changed)
        self.bind("<Right>", self.selection)
        self.bind("<Up>", self.moveUp)
        self.bind("<Down>", self.moveDown)

        self.listboxUp = False

    def changed(self, name, index, mode):
        if self.var.get() == '':
            if self.listboxUp:
                self.listbox.destroy()
                self.listboxUp = False
        else:
            words = self.comparison()
            if words:
                if not self.listboxUp:
                    self.listbox = Listbox(
                        width=self["width"], height=self.listboxLength)
                    self.listbox.bind("<Button-1>", self.selection)
                    self.listbox.bind("<Right>", self.selection)
                    self.listbox.place(
                        x=self.winfo_x(), y=self.winfo_y() + self.winfo_height())
                    self.listboxUp = True

                self.listbox.delete(0, END)
                for w in words:
                    self.listbox.insert(END, w)
            else:
                if self.listboxUp:
                    self.listbox.destroy()
                    self.listboxUp = False

    def selection(self, event):
        if self.listboxUp:
            self.var.set(self.listbox.get(ACTIVE))
            self.listbox.destroy()
            self.listboxUp = False
            self.icursor(END)

    def moveUp(self, event):
        if self.listboxUp:
            if self.listbox.curselection() == ():
                index = '0'
            else:
                index = self.listbox.curselection()[0]

            if index != '0':
                self.listbox.selection_clear(first=index)
                index = str(int(index) - 1)

                self.listbox.see(index)  # Scroll!
                self.listbox.selection_set(first=index)
                self.listbox.activate(index)

    def moveDown(self, event):
        if self.listboxUp:
            if self.listbox.curselection() == ():
                index = '0'
            else:
                index = self.listbox.curselection()[0]

            if index != END:
                self.listbox.selection_clear(first=index)
                index = str(int(index) + 1)

                self.listbox.see(index)  # Scroll!
                self.listbox.selection_set(first=index)
                self.listbox.activate(index)

    def comparison(self):
        return [w for w in self.autocompleteList if self.matchesFunction(self.var.get(), w)]


# autocompleteList = ['Gmail', 'YouTube', 'Facebook',
#                     'Zoom', 'Reddit', 'Netflix', 'Microsoft', 'Amazon', 'Instagram', 'Google', 'Twitch', 'Twitter', 'Apple Inc', 'Adobe', 'Linkedin',
#                     'Hotstar', 'Quora', 'Dropbox']


def matches(fieldValue, acListEntry):
    pattern = re.compile(re.escape(fieldValue) + '.*', re.IGNORECASE)
    return re.match(pattern, acListEntry)


def is_present(arr, entry):
    for i in arr:
        if i == entry:
            return True
    return False


def save_pass():
    global autocompleteList
    website = website_entry.get()
    row = [f'{website}']

    if(not (is_present(autocompleteList, website))):
        autocompleteList.append(website)
        with open('user.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(row)

    email = email_entry.get()
    password = password_entry.get()
    count = pass_check.pwned_api_check(password)
    question = 0
    if count:
        question = messagebox.askquestion(
            title="Warning", message=f"This password was found {count} times.Do you wish to proceed ?")

    new_data = {
        website: {
            "username": email,
            "password": password,
        }
    }

    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(
            title="Oops", message="Please don't leave any fields empty!")
    elif question == 'yes' or count == 0:
        is_ok = messagebox.askokcancel(title=f"{website}", message=f"These are the details entered:\n Email: {email}"
                                       f"\n Password: {password} \n Is it ok to save?")

        if is_ok:
            master_pass = simpledialog.askstring(
                title='Test', prompt='Enter the master password?', show="*")
            # Sample Password For now
            if hash.check_pass(master_pass):
                key = gen_key(master_pass)
                if os.path.isfile('encrypted_data.txt'):
                    decryp(key)
                if (not os.path.isfile('data.json')):
                    with open("data.json", "w") as data_file:
                        json.dump(new_data, data_file, indent=4)
                        website_entry.delete(0, END)
                        password_entry.delete(0, END)
                    encryp(key)
                else:
                    with open("data.json", 'r') as data_file:
                        data = json.load(data_file)
                    data.update(new_data)

                    with open("data.json", "w") as data_file:
                        json.dump(data, data_file, indent=4)
                        website_entry.delete(0, END)
                        password_entry.delete(0, END)
                    encryp(key)
            else:
                messagebox.showinfo(
                    title="Oops", message="Check password again")


def on_closing():

    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        window.destroy()
        new_del()


def create_login(create_pass):
    # os.remove('encrypted_data.txt')
    hash.create_pass(create_pass)
    messagebox.showinfo(
        title="Prompt", message="Password Sucessfuly Created")


def searchpass():
    website = website_entry.get()
    print(website)
    if(website == ""):
        messagebox.showinfo(title="Prompt",
                            message="Please Don't leave the website entry empty.")
    else:

        if os.path.isfile("encrypted_data.txt"):
            master_pass = simpledialog.askstring(
                title='Prompt', prompt='Enter the master password?', show="*")
            if hash.check_pass(master_pass):
                key = gen_key(master_pass)

                decryp(key)
                with open("data.json") as data_file:
                    data = json.load(data_file)
                    if website in data:
                        email = data[website]["username"]
                        password = data[website]["password"]
                        pyperclip.copy(password)
                        messagebox.showinfo(title=website,
                                            message=f"Username: {email}\nPassword: {password}\nCopied to Clipboard")
                    else:
                        messagebox.showinfo(
                            title="Error Occured", message=f"No Username or Password Found for the {website}.")

            else:
                messagebox.showinfo(
                    title="Oops", message="Check password again")
        else:
            messagebox.showinfo(
                title="Prompt", message="Password Directory Empty.")

    window.after(60000, new_del)


start = time.time()
incorrect_tries = 0
window = ThemedTk(theme="arc")
style = ttk.Style(window)
style.theme_use("xpnative")
# window.get_themes()
# window.set_theme("clearlooks")
window.title("Password Manager")
window.iconbitmap(r'padlock.ico')
window.state("zoomed")
window.geometry("1000x1000")
back_image = PhotoImage(file="new.png")

if(not os.path.isfile("hashed_pass.txt")):
    master_pass = simpledialog.askstring(
        title='Register', prompt='Create Master Password', show="*")
    create_login(master_pass)

master_pass = simpledialog.askstring(
    title='Test', prompt='Enter the master password?', show="*", parent=window)

if(master_pass == None):
    messagebox.showinfo(
        title="Prompt", message="Error Occured")
    window.destroy()
    exit()
    # ---------------------------- UI SETUP ------------------------------- #


while(incorrect_tries <= 2):

    if hash.check_pass(master_pass):

        canvas = Canvas(window, width=1000, height=1000)
        canvas.pack(fill="both", expand=True)

        canvas.create_image(0, 0, image=back_image, anchor="nw")
        canvas.create_text(500, 150, text="ManagePass",
                           font=("Helvetica", 45), fill="white")

        canvas.create_text(500, 250, text="Website: ",
                           font=("Helvetica"), fill="white")
        canvas.create_text(500, 280, text="Username:",
                           font=("Helvetica"), fill="white")
        canvas.create_text(500, 310, text="Password:",
                           font=("Helvetica"), fill="white")

        # # Entries
        website_entry = AutocompleteEntry(
            autocompleteList, window, listboxLength=6, width=35, matchesFunction=matches)

        website_entry_window = canvas.create_window(
            550, 240, anchor="nw", window=website_entry)

        email_entry = ttk.Entry(window, width=35)
        email_entry_window = canvas.create_window(
            550, 270, anchor="nw", window=email_entry)

        password_entry = ttk.Entry(window, width=21, show="*")
        password_entry_window = canvas.create_window(
            550, 300, anchor="nw", window=password_entry)

        search_pass = ttk.Button(window, text="Search", command=searchpass)
        search_pass_window = canvas.create_window(
            780, 240, anchor="nw", window=search_pass)

        gen_pass = ttk.Button(
            window, text="Generate Password", command=gen_pass)
        gen_pass_window = canvas.create_window(
            700, 300, anchor="nw", window=gen_pass)

        add_button = ttk. Button(
            window, text="Add", width=35, command=save_pass)
        add_button_window = canvas.create_window(
            550, 330, anchor="nw", window=add_button)

        clear_button = ttk.Button(window, text="Reset",
                                  width=35, command=reset_pass)
        clear_button_window = canvas.create_window(
            550, 360, anchor="nw", window=clear_button)

        # view_pass = ttk.Button(
        #     window, text="View Password", width=35, command=view_txt)
        # view_pass_window = canvas.create_window(
        #     550, 360, anchor="nw", window=view_pass)

        # del_file = ttk.Button(window, text="Delete File",
        #                       width=35, command=del_f)
        # del_file_window = canvas.create_window(
        #     550, 420, anchor="nw", window=del_file)

        window.protocol("WM_DELETE_WINDOW", on_closing)
        window.mainloop()
        break

    else:
        incorrect_tries += 1
        master_pass = simpledialog.askstring(
            title='Prompt', prompt='Password Incorrect.Enter the master password again?', show="*")

if (incorrect_tries > 2):
    messagebox.showinfo(
        title="Warning", message="Incorrect Password entered 3 times")
    window.destroy()
