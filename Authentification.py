import colorama
import art
import getpass
import hashlib
colorama.init(autoreset=True)
print(art.text2art("Authentification"))

print(colorama.Fore.BLUE)
regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b'
def hash_password(password):
    # Hasher le mot de passe avec SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def login():
        email = input("Donnez votre email : ")
        password = getpass.getpass()
        with open("users.txt", 'r') as f:  
          users = f.readlines()
          for user in users:
                user_email, user_hashed_password = user.strip().split(":")
                if email == user_email and hash_password(password) == user_hashed_password:
                     print("Authentification réussie !")
                     import Menuprincipal
                     Menuprincipal.Menu()
                     
                else:
                   print("Email ou mot de passe incorrect.")
login()
    
       
             
              
                    
            
                 
    

