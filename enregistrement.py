import colorama
import cowsay
import getpass
import re
import hashlib
colorama.init()
cowsay.cow("Enregistrement ")
print(colorama.Fore.BLUE)
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b'

def email_exists(email):
    with open("users.txt", "r") as file:
        lines = file.readlines()
        for line in lines:
            stored_email, _ = line.strip().split(":")
            if stored_email == email:
                return True
        return False
def hash_password(password):
    
    return hashlib.sha256(password.encode()).hexdigest()
def Enregistrer_client():
    while True:
        email = input("Entrez le email : ")
        if re.fullmatch(regex, email):
            if email_exists(email):
                print("Email déjà enregistré. Veuillez choisir un autre email.")
            else :
                break
        else:
            print('Email invalide')

    expression_reguliere = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.*.).{8,}$"
    while True:
        password = getpass.getpass("Entrez le password  : ")
        if re.match(expression_reguliere, password):
            break
        else:
            print("Le mot de passe doit contenir au moins une lettre majuscule, une minuscule, un chiffre et un caractère spécial")

    hashed_password = hash_password(password)

    with open("users.txt", "a") as file:
        file.write(f"{email}:{hashed_password}\n")
    print("Registration successful!")
    import Authentification
    Authentification.login()

Enregistrer_client()
         