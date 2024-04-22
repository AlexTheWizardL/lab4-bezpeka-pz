import os
import platform
import getpass
import hashlib
import winreg
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from tkinter import Tk, filedialog


def get_installation_folder():
    root = Tk()
    root.withdraw() 
    folder_path = filedialog.askdirectory(title="Виберіть папку для установки програми")
    if folder_path:
        return folder_path
    else:
        print("Папку не було вибрано.")
        exit()


def create_executable_file(installation_folder):
    pass

def collect_computer_info():
    computer_info = {
        'username': getpass.getuser(),
        'computer_name': platform.node(),
        'windows_directory': os.environ.get('windir'),
        'system_directory': os.environ.get('SYSTEMROOT'),
    }
    return computer_info

def calculate_hash(data):
    hash_object = hashlib.sha256()
    hash_object.update(str(data).encode())
    return hash_object.hexdigest()

def sign_data(data, private_key):
    key = RSA.import_key(open(private_key).read())
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def write_signature_to_registry(signature):
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Stepanenko")
        winreg.SetValueEx(key, "Signature", 0, winreg.REG_BINARY, signature)
        winreg.CloseKey(key)
        print("Підпис успішно записано в реєстр Windows.")
    except Exception as e:
        print("Помилка при записі підпису в реєстр Windows:", e)

def main():
    installation_folder = get_installation_folder()
    create_executable_file(installation_folder)
    computer_info = collect_computer_info()
    hash_data = calculate_hash(computer_info)
    private_key = 'private_key.pem'
    signature = sign_data(hash_data.encode(), private_key)
    write_signature_to_registry(signature)

if __name__ == "__main__":
    main()
