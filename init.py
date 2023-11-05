import colorama
import art
import cowsay
colorama.init(autoreset=True)
print(art.text2art("App Sing in up,Chifrement RSA"))
print(colorama.Fore.BLUE)
cowsay.cow("WELCOM")

def menup():
    print("1: Enregistre vous")
    print("2: Login")
    print("3: Quiter app")
while True:
    menup()
    choix=input("tapper votre choix : ")
    match choix:
        case '1':
         import enregistrement
         import Authentification
         enregistrement.Enregistrer_client()
        case '2':
         import Authentification
         Authentification.login()
        case '3':
          exit
        case default:
          print("choix invalide. Veuiller sélectionner un option valide ")
          
    