# Import du module socket
import socket   

# Création de la socket
mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connexion au serveur
mysock.connect(('data.pr4e.org', 80))  # Le client se connecte au serveur data.pr4e.org sur le port 80

#Construction de la requête HTTP
cmd = 'GET http://data.pr4e.org/romeo.txt HTTP/1.0\r\n\r\n'.encode()
# GET ... HTTP/1.0 est une requête pour obtenir une ressource.
# Deux retours à la ligne (\n\n) pour indiquer la fin de l'en-tête.
# .encode() transforme la chaîne en bytes, nécessaire pour l'envoi via socket.

mysock.send(cmd) # Envoi de la requête

#Réception de la réponse (boucle)   |  bloc qui lit 512 octets à la fois de la réponse du serveur.
while True:
    data = mysock.recv(512)
    if (len(data) < 1):       # s'il n’y a plus de données → on sort de la boucle.
        break
    print(data.decode(),end='')  # transforme les bytes reçus en chaîne de caractères lisible.

# Fermeture de la connexion
mysock.close()