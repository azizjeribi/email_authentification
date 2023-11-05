import hashlib
import bcrypt
import rsa
def hash_password(password):
    
    return hashlib.sha256(password.encode()).hexdigest()
def hash_sha256(word):
    hashed_word = hashlib.sha256(word.encode()).hexdigest()
    print(f"Le mot haché par sha256 est : {hashed_word}")

def hash_with_salt(word):
    salt = bcrypt.gensalt()
    hashed_word = bcrypt.hashpw(word.encode(), salt)
    print(f"Le mot haché avec salt est : {hashed_word}")

def dictionary_attack(hashed_password,dictionary):
     with open('dictionary.txt', 'r') as file:
        word = file.readlines()
        hashed_word = hash_password(word)
        if hashed_word == hashed_password:
            return word
        else :
            print("le hach de mote ne existe pas")              
             
    

def generate_key_pair():
    publicKey, privateKey = rsa.newkeys(512)
    with open("public_key.pem", "wb") as pub_key_file:
        pub_key_file.write(publicKey.save_pkcs1())
    with open("private_key.pem", "wb") as priv_key_file:
        priv_key_file.write(privateKey.save_pkcs1())
    print("Les paires de clés ont été générées et enregistrées dans public_key.pem et private_key.pem.")

def encrypt_message(message):
    with open("public_key.pem", "rb") as pub_key_file:
        publicKey = rsa.PublicKey.load_pkcs1(pub_key_file.read())
    encrypted_message = rsa.encrypt(message.encode(), publicKey)
    return encrypted_message

def decrypt_message(encrypted_message):
    with open("private_key.pem", "rb") as priv_key_file:
        privateKey = rsa.PrivateKey.load_pkcs1(priv_key_file.read())
    decrypted_message = rsa.decrypt(encrypted_message, privateKey).decode()
    print(f"Le message déchiffré est : {decrypted_message}")

def sign_message(message):
    with open("private_key.pem", "rb") as priv_key_file:
        privateKey = rsa.PrivateKey.load_pkcs1(priv_key_file.read())
    signature = rsa.sign(message.encode(), privateKey, 'SHA-1')
    return signature

def verify_signature(message, signature):
    with open("public_key.pem", "rb") as pub_key_file:
        publicKey = rsa.PublicKey.load_pkcs1(pub_key_file.read())
    try:
        rsa.verify(message.encode(), signature, publicKey)
        print("La signature est valide.")
    except:
        print("La signature n'est pas valide.")
def Menu():
    while True:
     print("Menu Principal:")
     print("A- Donnez un mot à hacher")
     print("    a- Hacher le mot par sha256")
     print("    b- Hacher le mot en générant un salt (bcrypt)")
     print("    c- Attaquer par dictionnaire le mot inséré")
     print("    d- Revenir au menu principal")
     print("B- Chiffrement (RSA)")
     print("    a- Générer les paires de clés dans un fichier")
     print("    b- Chiffrer un message de votre choix par RSA")
     print("    c- Déchiffrer le message (b)")
     print("    d- Signer un message de votre choix par RSA")
     print("    e- Vérifier la signature du message (d)")
     print("    f- Revenir au menu principal")
     print("C- Certificat (RSA)")
     print("    a- Générer les paires de clés dans un fichier")
     print("    b- Générer un certificat autosigné par RSA")
     print("    c- Chiffrer un message de votre choix par ce certificat")
     print("    d- Revenir au menu principal")

     choix = input("Choisissez une option : ")

     if choix.upper() == "A":
        mot = input("Entrez le mot à hacher : ")
        choix_a = input("Choisissez une option (a, b, c, d) : ")

        if choix_a.lower() == "a":
            hash_sha256(mot)
        elif choix_a.lower() == "b":
            hash_with_salt(mot)
        elif choix_a.lower() == "c":
            dictionary_attack(mot)
        elif choix_a.lower() == "d":
            continue

     elif choix.upper() == "B":
        choix_b = input("Choisissez une option (a, b, c, d, e, f) : ")

        if choix_b.lower() == "a":
            generate_key_pair()
        elif choix_b.lower() == "b":
            messageb = input("Entrez le message à chiffrer : ")
            encrypted_message = encrypt_message(messageb, )
            print(f"Le message chiffré est : {encrypted_message}")
        elif choix_b.lower() == "c":
            decrypt_message(messageb)
        elif choix_b.lower() == "d":
            messaged = input("Entrez le message à signer : ")
            signatured = sign_message(messaged)
            print(f"La signature du message est : {signatured}")
        elif choix_b.lower() == "e":
            verify_signature(messaged, signatured)
        elif choix_b.lower() == "f":
            continue

     elif choix.upper() == "C":
        choix_c = input("Choisissez une option (a, b, c, d) : ")

        if choix_c.lower() == "a":
            generate_key_pair()
        elif choix_c.lower() == "b":
            # Code pour générer un certificat autosigné par RSA
            pass
        elif choix_c.lower() == "c":
            # Code pour chiffrer un message avec le certificat
            pass
        elif choix_c.lower() == "d":
            continue
     else:
        print("Option invalide. Veuillez réessayer.")

Menu()