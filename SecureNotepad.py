import base64
import tkinter as tk
from tkinter import messagebox
from hashlib import md5
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os.path import dirname, realpath
from json import dump, load
from genericpath import exists

dir_path = dirname(realpath(__file__))
People = dict(load(open(dir_path + "\\People.json")))

class Login(tk.Tk):
    def __init__(self):
        super().__init__()
        self.loggedIn = False

        self.UserID = ""
        self.Password = ""
        
        self.title("Login Form")
        self.geometry('{}x{}'.format(250, 155))
        self.resizable(width=False, height=False)

        self.create_widgets()

    def create_widgets(self):
        self.username_label = tk.Label(self, text="Username:")
        self.username_label.pack()

        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self, text="Login", command=self.validate_login)
        self.login_button.pack()

        self.create_button = tk.Button(self, text="Create User", command=self.create_user)
        self.create_button.pack()

        self.quit_button = tk.Button(self, text="Quit", command=self.destroy)
        self.quit_button.pack()

    def check_user_password(self, userid, password):
        md5User, md5Pswd = md5(userid.encode()).hexdigest(), md5(password.encode()).hexdigest()
        return ((userid if md5Pswd == People.get(md5User, "") else False) if People.get(md5User) else False)

    def create_user(self):
        root = tk.Tk()

        root.title("Creation Form")
        root.geometry('{}x{}'.format(250, 150))
        root.resizable(width=False, height=False)

        username_label = tk.Label(root, text="Username:")
        username_label.pack()

        self.create_username_entry = tk.Entry(root)
        self.create_username_entry.pack()

        password_label = tk.Label(root, text="Password:")
        password_label.pack()

        self.create_password_entry = tk.Entry(root, show="*")
        self.create_password_entry.pack()

        login_button = tk.Button(root, text="Create User", command=lambda: (self.create_user_logic(root)))
        login_button.pack()

        root.mainloop()

    def create_user_logic(self, root):
        if md5(self.create_username_entry.get().encode()).hexdigest() not in People:
            People[md5(self.create_username_entry.get().encode()).hexdigest()] = md5(self.create_password_entry.get().encode()).hexdigest()
            with open(dir_path + "\\People.json", "w") as file:
                dump(People, file)
        else:
            messagebox.showerror("Creation Failed", "Username Already Exists.")
        root.destroy()

    def validate_login(self):
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

class Application(tk.Tk):
    def __init__(self, userid, password):
        super().__init__()
        self.Password = password
        self.UserID = userid

        self.title("Application")
        self.geometry('{}x{}'.format(800, 400))
        self.resizable(width=False, height=False)

        self.messageBox = tk.Text(self, width=100, height=23)
        self.messageBox.pack()

        self.protocol("WM_DELETE_WINDOW", self.close)

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
        with open(self.file_path, "wb") as file:
            file.write(self.fernet.encrypt(self.messageBox.get("1.0", tk.END).encode()))

    def decrypt(self):
        with open(self.file_path, "rb") as file:
            read = file.read()
            return self.fernet.decrypt(read)

    def load(self):
        self.fernet = self.generate_fernet_key()
        self.file_path = dir_path + "\\Notes\\" + self.UserID + ".txt"
        
        if not exists(self.file_path):
            open(self.file_path, "w")
        if open(self.file_path, "r").read():
            decrypted_message = self.decrypt()
            if decrypted_message:
                self.messageBox.insert("1.0", decrypted_message)
        self.mainloop()

if __name__ == "__main__":
    print("Starting..")
    login = Login()
    login.mainloop()
    if login.loggedIn:
        print("Logged In!")
        App = Application(login.UserID, login.Password)
        login.Password = ""
        App.load()