import customtkinter as ctk
from customtkinter import E, END, N, S, W
import base64
from hashlib import md5
from os.path import dirname, realpath
from json import dump, load, dumps, loads
from genericpath import exists
from PIL import ImageTk, Image 

import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

dir_path = dirname(realpath(__file__))
People = dict(load(open(dir_path + "\\People.json")))

class Login(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.loggedIn = False

        self.UserID = ""
        self.Password = ""
        
        self.title("Login Form")
        self.geometry('{}x{}+{}+{}'.format(250, 200, 750, 250))
        self.resizable(width=False, height=False)

        self.bind('<Return>', self.validate_login)
        self.create_widgets()

    def create_widgets(self):
        self.username_label =  ctk.CTkLabel(self, text="Username:")
        self.username_label.pack()

        self.username_entry =  ctk.CTkEntry(self)
        self.username_entry.pack()

        self.password_label =  ctk.CTkLabel(self, text="Password:")
        self.password_label.pack()

        self.password_entry =  ctk.CTkEntry(self, show="*")
        self.password_entry.pack()

        self.login_button =  ctk.CTkButton(self, text="Login", command=self.validate_login)
        self.login_button.pack(fill="x", pady = 1)

        self.create_button =  ctk.CTkButton(self, text="Create User", command=self.create_user)
        self.create_button.pack(fill="x", pady = 1)

        self.quit_button =  ctk.CTkButton(self, text="Quit", command=self.destroy)
        self.quit_button.pack(fill="x", pady = 1)

        self.bind('<Escape>', lambda event: (self.destroy()))

    def check_user_password(self, userid : str, password : str):
        username_md5 = self.md5_hex(userid)
        password_md5 = self.md5_hex(password)

        return ((userid if password_md5 == People.get(username_md5, "") else False) if People.get(username_md5) else False)

    def create_user(self):
        root =  ctk.CTk()

        root.title("Creation Form")
        root.geometry('{}x{}+{}+{}'.format(250, 155, 750, 550))
        root.resizable(width=False, height=False)

        username_label =  ctk.CTkLabel(root, text="Username:")
        username_label.pack()

        self.create_username_entry =  ctk.CTkEntry(root)
        self.create_username_entry.pack()

        password_label = ctk.CTkLabel(root, text="Password:")
        password_label.pack()

        self.create_password_entry =  ctk.CTkEntry(root, show="*")
        self.create_password_entry.pack()

        login_button =  ctk.CTkButton(root, text="Create User", command=lambda: (self.create_user_logic(root)))
        login_button.pack()

        root.bind('<Return>', lambda event: (self.create_user_logic(root)))
        root.bind('<Escape>', lambda event: (root.destroy()))
        root.mainloop()

    def md5_hex(self, text : str):
        return md5(text.encode()).hexdigest()

    def create_user_logic(self, root : ctk.CTk):
        username = self.create_username_entry.get()
        username_md5 = self.md5_hex(username)

        password = self.create_password_entry.get()
        password_md5 = self.md5_hex(password)

        if not username_md5 in People:
            People[username_md5] = password_md5
            with open(dir_path + "\\People.json", "w") as file:
                dump(People, file)
        else:
            messagebox.showerror("Creation Failed", "Username Already Exists.")
        root.destroy()

    def validate_login(self, event = None):
        userid = self.username_entry.get()
        password = self.password_entry.get()

        Validation = self.check_user_password(userid, password)
        if Validation:
            self.loggedIn = True
            self.Password = password
            self.UserID = userid
            self.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

class Application(ctk.CTk):
    def __init__(self, userid : str, password : str):
        super().__init__()
        self.Password = password
        self.UserID = userid

        self.title("Application")
        self.geometry('{}x{}+{}+{}'.format(800, 400, 500, 220))
        self.resizable(width=False, height=False)

        self.notesFrame = ctk.CTkScrollableFrame(self, width=150)
        self.notesFrame.pack(fill="y", side="left")

        self.messageBox =  ctk.CTkTextbox(self, width=800, height=400)
        self.messageBox.pack(fill="both")

        self.new_note_button = ctk.CTkButton(self.notesFrame, text="New Note", command=lambda: self.new_note(simpledialog.askstring("New Note", "What do you wanna name the note?")))
        self.new_note_button.pack(pady=5)

        self.rem_note_button = ctk.CTkButton(self.notesFrame, text="Remove Note", command=lambda: self.rem_note_button(messagebox.askokcancel("Remove Note?", f"Do you wanna delete {self.currentNote}")))
        self.rem_note_button.pack(pady=5)

        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind('<Escape>', lambda event: (self.close()))

        self.Note_Buttons = {}

    def close(self):
        self.encrypt()
        self.destroy()

    def generate_fernet_key(self):
        password_bytes = self.Password.encode()

        salt = password_bytes
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())

        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))

        return Fernet(key)

    def encrypt(self):
        self.Notes[self.currentNote] = self.messageBox.get("1.0", tk.END)
        with open(self.file_path, "wb") as file:
            file.write(self.fernet.encrypt(dumps(self.Notes).encode()))

    def decrypt(self) -> dict:
        with open(self.file_path, "rb") as file:
            Decrypted_Notes = self.fernet.decrypt(file.read()).decode()
            NewNotes = loads(Decrypted_Notes)
            return NewNotes

    def load(self):
        self.fernet = self.generate_fernet_key()
        self.file_path = dir_path + "\\Notes\\" + self.UserID + ".txt"
        
        if not exists(self.file_path):
            open(self.file_path, "w")
        if open(self.file_path, "r").read():
            self.Notes = self.decrypt()
            if self.Notes:
                self.currentNote = list(self.Notes.keys())[0]
                self.messageBox.insert("1.0", self.Notes[self.currentNote])

                for i in list(self.Notes.keys()):
                    self.create_note_button(i)
        self.mainloop()
    
    def open_note(self, name):
        self.Notes[self.currentNote] = self.messageBox.get("1.0", tk.END)

        self.currentNote = name
        self.messageBox.delete("1.0", tk.END)
        self.messageBox.insert("1.0", self.Notes[self.currentNote])
    
    def delete_note(self, confirm):
        if confirm:
            del self.Notes[self.currentNote]
            del self.Note_Buttons[self.currentNote]
            self.currentNote = list(self.Notes.keys())[0]
    
    def new_note(self, name):
        if name:
            self.Notes[name] = ""
            self.open_note(name)
            self.create_note_button(name)
    
    def create_note_button(self, name):
        newButton = ctk.CTkButton(self.notesFrame, text=name, command=lambda: self.open_note(name))
        newButton.pack(pady=5)
        self.Note_Buttons[name] = newButton

if not __name__ == "__main__":
    print("Starting..")
    login = Login()
    login.mainloop()
    if login.loggedIn:
        print("Logged In!")
        App = Application(login.UserID, login.Password)
        login.Password = ""
        App.load()
