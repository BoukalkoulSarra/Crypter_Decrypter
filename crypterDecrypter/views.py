import string
from django.shortcuts import render
from django.http import HttpResponse
import base64
import random
# Create your views here.

def index(request):
    outils = [
        {'title': 'César', 'desc': "Substitution avec décalage fixe.", 'url': 'chiffrement/'},
        {'title': 'Atbush', 'desc': "Substitution miroir : A ↔ Z.", 'url': 'atbush/'},
        {'title': 'Polybe', 'desc': "Grille 5x5, coordonnées des lettres.", 'url': 'Carré_Polybe/'},
        {'title': 'Vigenère', 'desc': "Polyalphabétique avec une clé.", 'url': 'ChiffVigenere/'},
        {'title': 'Vernam', 'desc': "XOR avec clé unique (OTP).", 'url': 'vernamChiffrer/'},
        {'title': 'Auto-clé', 'desc': "La clé inclut le message.", 'url': 'crypterautokey/'},
        {'title': 'Alberti', 'desc': "Disque chiffrant à double alphabet.", 'url': 'encrypt_alberti/'},
        {'title': 'Trithemius', 'desc': "Décalage progressif.", 'url': 'encrypt_trithemius/'},
        {'title': 'Substitution', 'desc': "Remplacement par alphabet secret.", 'url': 'encrypt_substitution/'},
        {'title': 'Albam', 'desc': "Substitution A↔N, B↔O,(décalage 13 pos).", 'url': 'encrypt_albam/'},
        {'title': 'Beaufort', 'desc': "Variante du Vigenère inversé.", 'url': 'encrypt_beaufort/'},
        {'title': 'Porta', 'desc': "Chiffrement par paire de lettres.", 'url': 'encrypt_porta/'},
        {'title': 'Atbah', 'desc': "Substitution miroir : A ↔ M et N ↔ z .", 'url': 'encrypt_Atbah/'},
    ]
    return render(request, 'chiffrement/index.html', {'outils': outils})

def chiffCeser(request):
    motChiffre = ""
    Key = None
    motClair = ""
    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')

        if motClair:  # Ensure it's not empty
            Key = random.randint(1, 25)  # Generate a random shift key
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            motCh = []

            for m in motClair:
                if m.upper() in alphabet:
                    nouvelle_position = (alphabet.index(m.upper()) + Key) % 26
                    motCh.append(alphabet[nouvelle_position] if m.isupper() else alphabet[nouvelle_position].lower())
                else:
                    motCh.append(m)

            motChiffre = "".join(motCh)  # Convert list to string

    return render(request, 'chiffrement/cesar.html', {'motChiffre': motChiffre, 'Key': Key, 'motClair': motClair,})

def dechiffCeser(request):
    texteClair = []
    mot_Chiffre = ""

    if request.method == 'POST':
        mot_Chiffre = request.POST.get('mot_Chiffre', '')
        print("mot_Chiffre:", mot_Chiffre)  # Debugging line

        if mot_Chiffre:
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

            for key in range(1, 26):
                motDechiffre = []

                for m in mot_Chiffre:
                    if m.upper() in alphabet:
                        new_pos = (alphabet.index(m.upper()) - key) % 26
                        lettre = alphabet[new_pos]
                        motDechiffre.append(lettre if m.isupper() else lettre.lower())
                    else:
                        motDechiffre.append(m)

                texteClair.append((key, "".join(motDechiffre)))

            print("texteClair:", texteClair)  # Debugging line

    return render(request, 'chiffrement/cesar.html', {
        'texteClair': texteClair,
        'mot_Chiffre': mot_Chiffre,
    })


def atbush_encrypt_view(request):
    if request.method == 'POST':
        motClair = request.POST.get('motClair')  # Get the input text from the form
        result = ""
        conversions = []  # To store (original, converted) pairs

        for char in motClair:
            if char.isalpha():
                if char.isupper():
                    converted = chr(65 + (25 - (ord(char) - 65)))
                else:
                    converted = chr(97 + (25 - (ord(char) - 97)))
                result += converted
                conversions.append((char, converted))
            else:
                result += char
                conversions.append((char, char))  # unchanged

        return render(request, 'chiffrement/crypterDecAtbush.html', {
            'motClair': motClair,
            'chiffre': result,
            'conversions': conversions  # pass list of tuples to template
        })

    # Handle GET request if necessary
    return render(request, 'chiffrement/crypterDecAtbush.html')
def atbush_decrypt_view(request):
    if request.method == 'POST':
        motChiffre = request.POST.get('motChiffre')  # This could be the encrypted text
        resu = ""
        conversions = []  # To store (original, converted) pairs

        for char in motChiffre:
            if char.isalpha():
                if char.isupper():
                    converted = chr(65 + (25 - (ord(char) - 65)))
                else:
                    converted = chr(97 + (25 - (ord(char) - 97)))
                resu += converted
                conversions.append((char, converted))
            else:
                resu += char
                conversions.append((char, char))  # unchanged

        return render(request, 'chiffrement/crypterDecAtbush.html', {
            'motChiffre': motChiffre,
            'chiffr': resu,
            'conversion': conversions  # pass list of tuples to template
        })

    return render(request, 'chiffrement/crypterDecAtbush.html')


def crypter_carre_polybe(request):
    motClair = ""
    motChiffre = ""
    key = []

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '').upper().replace('J', 'I').replace(" ", "")

    matriceC = [['' for _ in range(5)] for _ in range(5)]
    encrypted_matrix = [['' for _ in range(5)] for _ in range(5)]
    used_letters = set()

    # Générer une clé aléatoire
    key_length = random.randint(2, 10)
    while len(key) < key_length:
        random_char = chr(random.randint(65, 90))  # A-Z
        if random_char != 'J' and random_char not in used_letters:
            key.append(random_char)
            used_letters.add(random_char)

    # Remplir la matrice de Polybe avec la clé
    index = 0
    letter = 'A'
    for i in range(5):
        for j in range(5):
            if index < len(key):
                matriceC[i][j] = key[index]
                index += 1
            else:
                while letter == 'J' or letter in used_letters:
                    letter = chr(ord(letter) + 1)
                matriceC[i][j] = letter
                used_letters.add(letter)
                letter = chr(ord(letter) + 1)

    # Créer la matrice des coordonnées
    for i in range(5):
        for j in range(5):
            encrypted_matrix[i][j] = str(i + 1) + str(j + 1)

    # Chiffrer le message clair
    for char in motClair:
        found = False
        for i in range(5):
            for j in range(5):
                if matriceC[i][j] == char:
                    motChiffre += encrypted_matrix[i][j]
                    found = True
                    break
            if found:
                break

    return render(request, 'chiffrement/carre_polybe.html', {
        'motClair': motClair,
        'motChiffre': motChiffre,
        'cle': ''.join(key),
        'matriceC': matriceC,
    })






def dechiffrer_carre_polybe(request):
    texteChiffre = ""
    texteDechiffre = ""
    key_str = ""

    if request.method == 'POST':
        texteChiffre = request.POST.get('texteChiffre', '').strip()
        key_str = request.POST.get('key', '').upper().replace('J', 'I').replace(" ", "")

    key = []
    used_letters = set()

    # Convert the key string into a list without duplicates and without 'J'
    for char in key_str:
        if char not in used_letters and char != 'J':
            key.append(char)
            used_letters.add(char)

    # Create the Polybius square
    matrice = [['' for _ in range(5)] for _ in range(5)]
    index = 0
    letter = 'A'
    for i in range(5):
        for j in range(5):
            if index < len(key):
                matrice[i][j] = key[index]
                index += 1
            else:
                while letter in used_letters or letter == 'J':
                    letter = chr(ord(letter) + 1)
                matrice[i][j] = letter
                used_letters.add(letter)
                letter = chr(ord(letter) + 1)

    # Decrypt the message
    for i in range(0, len(texteChiffre), 2):
        try:
            ligne = int(texteChiffre[i]) - 1
            colonne = int(texteChiffre[i + 1]) - 1
            if 0 <= ligne < 5 and 0 <= colonne < 5:
                texteDechiffre += matrice[ligne][colonne]
        except (ValueError, IndexError):
            texteDechiffre += '?'  # Invalid character pair

    # DEBUG
    print(f"Clé utilisée : {''.join(key)}")
    print("\nCarré de Polybe :")
    for row in matrice:
        print(' '.join(row))
    print("\nTexte déchiffré :", texteDechiffre)

    return render(request, 'chiffrement/carre_polybe.html', {
        'texteChiffre': texteChiffre,
        'texteDechiffre': texteDechiffre,
        'key': key_str,
        'matrice': matrice,
    })





def encrypt_vigenere(request):
    motClair = ""
    motChiffre = ""
    key = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')
        key = request.POST.get('key', '')

        message = motClair.upper().replace(" ", "")
        key = key.upper().replace(" ", "")

        # Générer une clé étendue si nécessaire
        key_extended = list(key)
        if len(message) != len(key):
            for i in range(len(message) - len(key)):
                key_extended.append(key_extended[i % len(key)])

        # Chiffrement
        encrypted_text = []
        for i in range(len(message)):
            if message[i].isalpha():
                m = ord(message[i]) - 65
                k = ord(key_extended[i]) - 65
                encrypted_char = chr((m + k) % 26 + 65)
                encrypted_text.append(encrypted_char)
            else:
                encrypted_text.append(message[i])  # caractères non alphabétiques

        motChiffre = "".join(encrypted_text)

    return render(request, 'chiffrement/Vigenere.html', {
        'motClair': motClair,
        'key': key,
        'motChiffre': motChiffre,
    })





def decrypt_vigenere(request):
    textChiffre = ""
    textClair = ""
    cle = ""

    if request.method == 'POST':
        textChiffre = request.POST.get('textChiffre', '')
        cle = request.POST.get('cle', '')

        message = textChiffre.upper().replace(" ", "")
        cle = cle.upper().replace(" ", "")

        # Étendre la clé à la longueur du message
        key_extended = list(cle)
        if len(message) != len(cle):
            for i in range(len(message) - len(cle)):
                key_extended.append(key_extended[i % len(cle)])

        # Déchiffrement
        decrypted_text = []
        for i in range(len(message)):
            if message[i].isalpha():
                c = ord(message[i]) - 65
                k = ord(key_extended[i]) - 65
                decrypted_char = chr((c - k + 26) % 26 + 65)
                decrypted_text.append(decrypted_char)
            else:
                decrypted_text.append(message[i])  # caractères non alphabétiques

        textClair = "".join(decrypted_text)

    return render(request, 'chiffrement/Vigenere.html', {
        'textChiffre': textChiffre,
        'cle': cle,
        'textClair': textClair,
    })




def vernam_encrypt(request):
    message = ""
    key = ""
    encrypted_message = ""
    message_bin = ""
    key_bin = ""
    result = ""

    if request.method == 'POST':
        message = request.POST.get('message', '')
        key = request.POST.get('key', '')

        if len(message) != len(key):
            result = "Erreur : la clé doit avoir la même longueur que le message."
        else:
            message_bin = ''.join(format(ord(c), '08b') for c in message)
            key_bin = ''.join(format(ord(c), '08b') for c in key)

            encrypted_bin = ''.join(
                str(int(message_bin[i]) ^ int(key_bin[i])) for i in range(len(message_bin))
            )

            encrypted_bytes = bytes(
                int(encrypted_bin[i:i+8], 2) for i in range(0, len(encrypted_bin), 8)
            )

            encrypted_message = base64.b64encode(encrypted_bytes).decode('utf-8')

    return render(request, 'chiffrement/vernam.html', {
        'message': message,
        'message_bin': message_bin,
        'key': key,
        'key_bin': key_bin,
        'encrypted_message': encrypted_message,
        'result': result
    })


def vernam_decrypt(request):
    encrypted_message = ""
    key = ""
    decrypted_message = ""
    encrypted_bin = ""
    key_bin = ""
    result = ""

    if request.method == 'POST':
        encrypted_message = request.POST.get('encrypted_message', '')
        key = request.POST.get('key', '')

        # Base64 decoding with error handling
        try:
            encrypted_bytes = base64.b64decode(encrypted_message)
        except Exception:
            result = "Erreur : le message chiffré n'est pas un format base64 valide."
            return render(request, 'chiffrement/vernam.html', {
                'encrypted_message': encrypted_message,
                'key': key,
                'decrypted_message': decrypted_message,
                'result': result
            })

        # Convert encrypted bytes to binary string
        encrypted_bin = ''.join(format(b, '08b') for b in encrypted_bytes)

        # Check if the key length in bits matches the encrypted message
        if len(key) * 8 != len(encrypted_bin):
            # Adjust the key to match the message length (truncate it)
            key_bin = ''.join(format(ord(c), '08b') for c in key)
            key_bin = key_bin[:len(encrypted_bin)]  # Truncate the key to match the message length
            result = "La clé a été tronquée pour correspondre au message chiffré."
        else:
            key_bin = ''.join(format(ord(c), '08b') for c in key)

        # XOR between encrypted binary message and the key binary
        decrypted_bin = ''.join(
            str(int(encrypted_bin[i]) ^ int(key_bin[i])) for i in range(len(encrypted_bin))
        )

        # Convert decrypted binary back to string
        try:
            decrypted_message = ''.join(
                chr(int(decrypted_bin[i:i+8], 2)) for i in range(0, len(decrypted_bin), 8)
            )
        except ValueError:
            result = "Erreur : décryptage échoué, format binaire incorrect."
            decrypted_message = ""

    return render(request, 'chiffrement/vernam.html', {
        'encrypted_message': encrypted_message,
        'key': key,
        'key_bin': key_bin,
        'decrypted_message': decrypted_message,
        'result': result
    })





def crypty_autokey(request):
    motClair = ""
    key = ""
    motChiffre = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')
        key = request.POST.get('key', '')

        # Nettoyer le texte
        plaintext = motClair.upper().replace(" ", "")
        key = key.upper()

        # Générer la clé auto-complétée
        key_extended = list(key)
        if len(key_extended) < len(plaintext):
            key_extended.extend(list(plaintext[:len(plaintext) - len(key_extended)]))
        key_extended = ''.join(key_extended)

        # Chiffrement
        cipher_text = ""
        for p, k in zip(plaintext, key_extended):
            cipher_char = chr(((ord(p) + ord(k)) % 26) + ord('A'))
            cipher_text += cipher_char

        motChiffre = cipher_text

    return render(request, 'chiffrement/AutoKey.html', {
        'motClair': motClair,
        'key': key,
        'motChiffre': motChiffre
    })




def decrypter_autokey(request):
    textDecrypter = ""
    cle = ""
    textClair = ""

    if request.method == 'POST':
        textDecrypter = request.POST.get('textDecrypter', '')
        cle = request.POST.get('key', '')

        # Nettoyer le texte
        ciphertext = textDecrypter.upper().replace(" ", "")
        key = list(cle.upper())

        plaintext = ""
        for c in ciphertext:
            p = chr(((ord(c) - ord(key[0])) % 26) + ord('A'))
            plaintext += p
            key.append(p)  # auto-key : ajoute la lettre décryptée
            key.pop(0)     # enlève la 1ère lettre de la clé

        textClair = plaintext

    return render(request, 'chiffrement/AutoKey.html', {
        'textDecrypter': textDecrypter,
        'cle': cle,
        'textClair': textClair
    })





def encrypt_alberti(request):
    motClair = ""
    motChiffre = ""
    shift = 0  # décalage initial

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')
        try:
            shift = int(request.POST.get('shift', '0'))
        except ValueError:
            shift = 0

        outer_ring = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        inner_ring = list("abcdefghijklmnopqrstuvwxyz")
        message = motClair.upper()

        # Appliquer le décalage
        shifted_inner = inner_ring[shift:] + inner_ring[:shift]

        encrypted_text = []
        for char in message:
            if char.isalpha():
                index = outer_ring.index(char)
                encrypted_text.append(shifted_inner[index])
            else:
                encrypted_text.append(char)

        motChiffre = "".join(encrypted_text)

    return render(request, 'chiffrement/Alberti.html', {
        'motClair': motClair,
        'shift': shift,
        'motChiffre': motChiffre,
    })



def decrypt_alberti(request):
    textDecrypter = ""
    textClair = ""
    shifte = 0

    if request.method == 'POST':
        textDecrypter = request.POST.get('textDecrypter', '')
        try:
            shifte = int(request.POST.get('shifte', '0'))
        except ValueError:
            shifte = 0

        outer_ring = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        inner_ring = list("abcdefghijklmnopqrstuvwxyz")
        shifted_inner = inner_ring[shifte:] + inner_ring[:shifte]
        message = textDecrypter.lower()

        decrypted_text = []
        for char in message:
            if char.isalpha():
                index = shifted_inner.index(char)
                decrypted_text.append(outer_ring[index])
            else:
                decrypted_text.append(char)

        textClair = "".join(decrypted_text)

    return render(request, 'chiffrement/Alberti.html', {
        'textDecrypter': textDecrypter,
        'shifte': shifte,
        'textClair': textClair,
    })





def encrypt_trithemius(request):
    motClair = ""
    motChiffre = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')
        message = motClair.upper().replace(" ", "")

        encrypted_text = []
        for i, char in enumerate(message):
            if char.isalpha():
                m = ord(char) - 65
                k = i % 26  # clé = position (0 pour A, 1 pour B, etc.)
                encrypted_char = chr((m + k) % 26 + 65)
                encrypted_text.append(encrypted_char)
            else:
                encrypted_text.append(char)

        motChiffre = "".join(encrypted_text)

    return render(request, 'chiffrement/Trithemius.html', {
        'motClair': motClair,
        'motChiffre': motChiffre,
    })




def decrypt_trithemius(request):
    textDecrypter = ""
    textClair = ""

    if request.method == 'POST':
        textDecrypter = request.POST.get('textDecrypter', '')
        message = textDecrypter.upper().replace(" ", "")

        decrypted_text = []
        for i, char in enumerate(message):
            if char.isalpha():
                c = ord(char) - 65
                k = i % 26
                decrypted_char = chr((c - k + 26) % 26 + 65)
                decrypted_text.append(decrypted_char)
            else:
                decrypted_text.append(char)

        textClair = "".join(decrypted_text)

    return render(request, 'chiffrement/Trithemius.html', {
        'textDecrypter': textDecrypter,
        'textClair': textClair,
    })






def generate_random_key():
    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    shuffled = alphabet[:]
    random.shuffle(shuffled)
    return ''.join(shuffled)

def encrypt_substitution(request):
    motClair = ""
    motChiffre = ""
    key = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '').upper()
        key = request.POST.get('key', '').upper()

        if not key or len(key) != 26 or not key.isalpha():
            key = generate_random_key()

        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        substitution_dict = {alphabet[i]: key[i] for i in range(26)}

        encrypted_text = []
        for char in motClair:
            if char.isalpha():
                encrypted_text.append(substitution_dict[char])
            else:
                encrypted_text.append(char)

        motChiffre = ''.join(encrypted_text)

    return render(request, 'chiffrement/Substitution.html', {
        'motClair': motClair,
        'key': key,
        'motChiffre': motChiffre,
    })


def decrypt_substitution(request):
    textDecrypter = ""
    textClair = ""
    cle = ""

    if request.method == 'POST':
        textDecrypter= request.POST.get('textDecrypter', '').upper()
        key = request.POST.get('cle', '').upper()

        if not key or len(key) != 26 or not key.isalpha():
            return render(request, 'chiffrement/Substitution.html', {
                'textClair': '',
                'textDecrypter': textDecrypter,
                'cle': '',
                'error': 'Clé invalide. La clé doit contenir 26 lettres.'
            })

        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        reverse_dict = {key[i]: alphabet[i] for i in range(26)}

        decrypted_text = []
        for char in textDecrypter:
            if char.isalpha():
                decrypted_text.append(reverse_dict[char])
            else:
                decrypted_text.append(char)

        textClair = ''.join(decrypted_text)

    return render(request, 'chiffrement/Substitution.html', {
        'textDecrypter': textDecrypter,
        'cle': cle,
        'textClair': textClair,
    })



def encrypt_albam(request):
    motClair = ""
    motChiffre = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '').upper()

        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        half = len(alphabet) // 2
        first_half = alphabet[:half]    # A-M
        second_half = alphabet[half:]   # N-Z

        albam_dict = {first_half[i]: second_half[i] for i in range(half)}
        albam_dict.update({second_half[i]: first_half[i] for i in range(half)})

        result = []
        for char in motClair:
            if char in albam_dict:
                result.append(albam_dict[char])
            else:
                result.append(char)

        motChiffre = ''.join(result)

    return render(request, 'chiffrement/Albam.html', {
        'motClair': motClair,
        'motChiffre': motChiffre,
    })



def decrypt_albam(request):
    textDecrypter = ""
    textClair = ""

    if request.method == 'POST':
        textDecrypter = request.POST.get('textDecrypter', '').upper()

        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        half = len(alphabet) // 2
        first_half = alphabet[:half]
        second_half = alphabet[half:]

        albam_dict = {first_half[i]: second_half[i] for i in range(half)}
        albam_dict.update({second_half[i]: first_half[i] for i in range(half)})

        result = []
        for char in textDecrypter:
            if char in albam_dict:
                result.append(albam_dict[char])
            else:
                result.append(char)

        textClair = ''.join(result)

    return render(request, 'chiffrement/Albam.html', {
        'textDecrypter': textDecrypter,
        'textClair': textClair,
    })






def encrypt_beaufort(request):
    motClair = ""
    motChiffre = ""
    key = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')
        key = request.POST.get('key', '')

        message = motClair.upper().replace(" ", "")
        key = key.upper().replace(" ", "")

        # Étendre la clé à la longueur du message
        key_extended = list(key)
        if len(message) != len(key):
            for i in range(len(message) - len(key)):
                key_extended.append(key_extended[i % len(key)])

        # Chiffrement Beaufort
        encrypted_text = []
        for i in range(len(message)):
            if message[i].isalpha():
                m = ord(message[i]) - 65
                k = ord(key_extended[i]) - 65
                c = (k - m + 26) % 26
                encrypted_char = chr(c + 65)
                encrypted_text.append(encrypted_char)
            else:
                encrypted_text.append(message[i])

        motChiffre = ''.join(encrypted_text)

    return render(request, 'chiffrement/Beaufort.html', {
        'motClair': motClair,
        'key': key,
        'motChiffre': motChiffre,
    })




def decrypt_beaufort(request):
    textDecrypter = ""
    textClair = ""
    cle = ""

    if request.method == 'POST':
        textDecrypter = request.POST.get('textDecrypter', '')
        cle = request.POST.get('cle', '')

        message = textDecrypter.upper().replace(" ", "")
        cle = cle.upper().replace(" ", "")

        # Étendre la clé
        key_extended = list(cle)
        if len(message) != len(cle):
            for i in range(len(message) - len(cle)):
                key_extended.append(key_extended[i % len(cle)])

        # Déchiffrement (identique au chiffrement Beaufort)
        decrypted_text = []
        for i in range(len(message)):
            if message[i].isalpha():
                c = ord(message[i]) - 65
                k = ord(key_extended[i]) - 65
                m = (k - c + 26) % 26
                decrypted_char = chr(m + 65)
                decrypted_text.append(decrypted_char)
            else:
                decrypted_text.append(message[i])

        textClair = ''.join(decrypted_text)

    return render(request, 'chiffrement/Beaufort.html', {
        'textDecrypter': textDecrypter,
        'cle': cle,
        'textClair': textClair,
    })



def encrypt_porta(request):
    motClair = ""
    motChiffre = ""
    key = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')
        key = request.POST.get('key', '')

        message = motClair.upper().replace(" ", "")
        key = key.upper().replace(" ", "")

        # Étendre la clé
        key_extended = list(key)
        if len(message) != len(key):
            for i in range(len(message) - len(key)):
                key_extended.append(key_extended[i % len(key)])

        # Table Porta
        porta_table = {
            'A': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
            'B': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
            'C': 'OPQRSTUVWXYZNMABCDEFGHIJKL',
            'D': 'OPQRSTUVWXYZNMABCDEFGHIJKL',
            'E': 'PQRSTUVWXYZNOLMABCDEFGHIJK',
            'F': 'PQRSTUVWXYZNOLMABCDEFGHIJK',
            'G': 'QRSTUVWXYZNOPMLABCDEFGHIJK',
            'H': 'QRSTUVWXYZNOPMLABCDEFGHIJK',
            'I': 'RSTUVWXYZNOPQMLABCDEFGHIJK',
            'J': 'RSTUVWXYZNOPQMLABCDEFGHIJK',
            'K': 'STUVWXYZNOPQRMLABCDEFGHIJK',
            'L': 'STUVWXYZNOPQRMLABCDEFGHIJK',
            'M': 'TUVWXYZNOPQRSMLABCDEFGHIJK',
            'N': 'TUVWXYZNOPQRSMLABCDEFGHIJK',
            'O': 'UVWXYZNOPQRSTMLABCDEFGHIJK',
            'P': 'UVWXYZNOPQRSTMLABCDEFGHIJK',
            'Q': 'VWXYZNOPQRSTUMLABCDEFGHIJK',
            'R': 'VWXYZNOPQRSTUMLABCDEFGHIJK',
            'S': 'WXYZNOPQRSTUVMLABCDEFGHIJK',
            'T': 'WXYZNOPQRSTUVMLABCDEFGHIJK',
            'U': 'XYZNOPQRSTUVWMLABCDEFGHIJK',
            'V': 'XYZNOPQRSTUVWMLABCDEFGHIJK',
            'W': 'YZNOPQRSTUVWXMLABCDEFGHIJK',
            'X': 'YZNOPQRSTUVWXMLABCDEFGHIJK',
            'Y': 'ZNOPQRSTUVWXYMLABCDEFGHIJK',
            'Z': 'ZNOPQRSTUVWXYMLABCDEFGHIJK',
        }

        result = []
        for i in range(len(message)):
            char = message[i]
            k = key_extended[i]

            if char.isalpha():
                index = ord(char) - 65
                mapped_char = porta_table[k][index]
                result.append(mapped_char)
            else:
                result.append(char)

        motChiffre = ''.join(result)

    return render(request, 'chiffrement/Porta.html', {
        'motClair': motClair,
        'key': key,
        'motChiffre': motChiffre,
    })



def decrypt_porta(request):
    textDecrypter = ""
    textClair = ""
    cle = ""

    if request.method == 'POST':
        textDecrypter = request.POST.get('textDecrypter', '')
        cle = request.POST.get('cle', '')

        message = textDecrypter.upper().replace(" ", "")
        cle = cle.upper().replace(" ", "")

        # Étendre la clé
        key_extended = list(cle)
        if len(message) != len(cle):
            for i in range(len(message) - len(cle)):
                key_extended.append(key_extended[i % len(cle)])

        # Table Porta
        porta_table = {
            'A': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
            'B': 'NOPQRSTUVWXYZABCDEFGHIJKLM',
            'C': 'OPQRSTUVWXYZNMABCDEFGHIJKL',
            'D': 'OPQRSTUVWXYZNMABCDEFGHIJKL',
            'E': 'PQRSTUVWXYZNOLMABCDEFGHIJK',
            'F': 'PQRSTUVWXYZNOLMABCDEFGHIJK',
            'G': 'QRSTUVWXYZNOPMLABCDEFGHIJK',
            'H': 'QRSTUVWXYZNOPMLABCDEFGHIJK',
            'I': 'RSTUVWXYZNOPQMLABCDEFGHIJK',
            'J': 'RSTUVWXYZNOPQMLABCDEFGHIJK',
            'K': 'STUVWXYZNOPQRMLABCDEFGHIJK',
            'L': 'STUVWXYZNOPQRMLABCDEFGHIJK',
            'M': 'TUVWXYZNOPQRSMLABCDEFGHIJK',
            'N': 'TUVWXYZNOPQRSMLABCDEFGHIJK',
            'O': 'UVWXYZNOPQRSTMLABCDEFGHIJK',
            'P': 'UVWXYZNOPQRSTMLABCDEFGHIJK',
            'Q': 'VWXYZNOPQRSTUMLABCDEFGHIJK',
            'R': 'VWXYZNOPQRSTUMLABCDEFGHIJK',
            'S': 'WXYZNOPQRSTUVMLABCDEFGHIJK',
            'T': 'WXYZNOPQRSTUVMLABCDEFGHIJK',
            'U': 'XYZNOPQRSTUVWMLABCDEFGHIJK',
            'V': 'XYZNOPQRSTUVWMLABCDEFGHIJK',
            'W': 'YZNOPQRSTUVWXMLABCDEFGHIJK',
            'X': 'YZNOPQRSTUVWXMLABCDEFGHIJK',
            'Y': 'ZNOPQRSTUVWXYMLABCDEFGHIJK',
            'Z': 'ZNOPQRSTUVWXYMLABCDEFGHIJK',
        }

        result = []
        for i in range(len(message)):
            char = message[i]
            k = key_extended[i]

            if char.isalpha():
                row = porta_table[k]
                index = row.find(char)
                decrypted_char = chr(index + 65)
                result.append(decrypted_char)
            else:
                result.append(char)

        textClair = ''.join(result)

    return render(request, 'chiffrement/Porta.html', {
        'textDecrypter': textDecrypter,
        'cle': cle,
        'textClair': textClair,
    })




# Function for the custom reflection cipher
def reflect_cipher(text):
    result = ""
    for char in text.upper():
        if 'A' <= char <= 'M':
            result += chr(ord('M') - (ord(char) - ord('A')))
        elif 'N' <= char <= 'Z':
            result += chr(ord('Z') - (ord(char) - ord('N')))
        else:
            result += char  # preserve non-letter characters
    return result

# Encrypt view
def encrypt_Atbah(request):
    motClair = ""
    motChiffre = ""

    if request.method == 'POST':
        motClair = request.POST.get('motClair', '')

        # Encrypt the message using the reflection cipher
        motChiffre = reflect_cipher(motClair)

    return render(request, 'chiffrement/Atbah.html', {
        'motClair': motClair,
        'motChiffre': motChiffre,
    })

# Decrypt view (same as encryption because of the symmetric nature of the cipher)
def decrypt_Atbah(request):
    textClair = ""
    textChiffre = ""

    if request.method == 'POST':
        textChiffre = request.POST.get('textChiffre', '')

        # Decrypt the message (same function as encryption)
        textClair = reflect_cipher(textChiffre)

    return render(request, 'chiffrement/Atbah.html', {
        'textChiffre': textChiffre,
        'textClair': textClair,
    })
