# Dofus Network Sniffer

Ce projet est une application Python qui utilise Scapy pour sniffer les paquets TCP sur le port 5555 et les traiter en tant que messages du réseau Dofus.


## Prérequis

- Python 3.8 ou supérieur
- pip


## Installation

1. Clonez ce dépôt sur votre machine locale.
2. Installez les dépendances nécessaires en utilisant pip :

```bash
pip install -r requirements.txt
```


## Utilisation

Exécutez le fichier `main.py` pour démarrer l'application :

```bash
python main.py
```


## Fonctionnalités

- **Sniffer de paquets TCP** : L'application écoute les paquets TCP sur le port 5555 (port utilisé par le serveur Dofus).
- **Traitement des paquets TCP** : Les paquets TCP sont parsés de sorte à en extraire chaque message concernant Dofus.
- **Gestion des messages du réseau Dofus** : Les messages du réseau Dofus sont extraits, identifiés (grâce au protocole stocké dans le fichier dofus.protocol) et affichés dans leur forme brute (hexadécimale).

## Fonctionnement du protocole Dofus (2.0+)

---

#### Rappel technique:
- 1 octet = 1 byte = 8 bits

---

Le protocole Dofus utilise un format de message personnalisé pour communiquer entre le client et le serveur. Chaque message est composé de 4 parties :<br>

- **ID du message** : Un entier non signé encodé sur les 14 premiers bits correspondant à l'ID du message Dofus.
- **Nombre d'octets utilisés pour la taille des données** : Un entier non signé de 2 octets représentant l'identifiant du message.
- **ID de séquence** : Un entier non signé de 4 octets représentant l'ID de séquence du message. Cet ID est incrémenté à chaque message envoyé mais n'est présent que dans les messages envoyés par le client pour le serveur. Si le message est envoyé par le serveur pour le client, cet ID est absent du message.
- **Taille des données** : Correspond simplement au nombre d'octets sur lesquels sont encodés les données du message. Cette valeur est encodée sur le nombre d'octets défini précédemment.
- **Données** : Les données du message peuvent être de n'importe quel type (entier, chaîne de caractères, tableau, etc.) et sont encodées sur le nombre d'octets définis juste avant.

### Exemple:

#### Client -> Serveur
Considérons le message suivant :

```
55 61 00 00 51 76 01 01
```
**ID du message** : Extraction des 14 premiers bits, présents donc sur les deux octets suivant: `55 61` (ID = 5464)<br>
**Nombre d'octets utilisés pour la taille des données** : Extraction des 2 bits suivant l'ID du message (soit les deux derniers bits des deux premiers octets) : `55 61`<br> (Nombre d'octets = 1)<br>
**ID de séquence** : Comme il s'agit d'un message client -> serveur, les 4 octets suivants : `00 00 51 76` sont occupé par l'ID de séquence (ID = 20 854)<br>
**Taille des données** : Nous savons que la taille des données est encodée sur 1 seul octet grâce aux valeurs précedemment trouvée. La taille des données correspond donc à l'octet suivant `01` (Taille des données = 1)<br>
**Données** : Les données du message sont correspondent donc uniquement à l'octet suivant `01`<br>

Dans ce cas précis, le message est un message de type `BasicPingMessage` (ID = 5464) envoyé par le client au serveur. Ce message ne contient pas de données, il s'agit simplement d'un ping envoyé par le client pour vérifier la connexion avec le serveur.
Ce type de message ne contient qu'un booléen, c'est pourquoi la taille des données est de 1 octet et le contenu des données équivaut à 1 (true).

---

#### Serveur -> Client
Considérons le message suivant :

```
2b 71 18 00 06 01 1a 01 28 01 37 01 53 01 6f 01 8b 00 06 42 42 37 15 80 92 00 00
```
**ID du message** : Extraction des 14 premiers bits, présents donc sur les deux premiers octets : `2b 71` (ID = 2780)<br>
**Nombre d'octets utilisés pour la taille des données** : Extraction des 2 bits suivant l'ID du message (soit les deux derniers bits des deux premiers octets) : `2b 71`<br> (Nombre d'octets = 1)<br>
**ID de séquence** : Comme il s'agit d'un message serveur -> client, l'ID de séquence est absent du message.<br>
**Taille des données** : Nous savons que la taille des données est encodée sur 1 seul octet grâce aux valeurs précedemment trouvée. La taille des données correspond donc à l'octet suivant `18` (Taille des données = 24)<br>
**Données** : Les données du message correspondent donc aux 24 octets suivants `00 06 01 1a 01 28 01 37 01 53 01 6f 01 8b 00 06 42 42 37 15 80 92 00 00` (Données = 24)<br>

Dans ce cas précis, le message est un message de type `GameMapMovementMessage` (ID = 2780) envoyé par le serveur au client.
Nous pouvons le savoir, comme pour tous les messages dont l'ID est connu, en allant rechercher cet identifiant dans les fichiers décompilé du jeu pour voir à quelle classe correspond ce message.
C'est également de cette facon que les données peuvent être décodées pour être lisible par un humain.


## Difficulté imposée par le protocole TCP

Dofus utilise le protocole TCP pour communiquer entre le client et le serveur.<br>
Le protocole TCP est un protocole de communication fiable qui garantit la livraison des données dans l'ordre et sans perte.<br>

Cependant, cela signifie que les données sont envoyées en blocs de taille variable et que les messages peuvent être fragmentés en plusieurs paquets TCP.<br>
Cela rend le processus de décodage des messages Dofus plus complexe, car il est nécessaire de reconstituer les messages à partir des paquets TCP fragmentés.<br>

Il est important de comprendre que les messages Dofus peuvent être fragmentés en plusieurs paquets TCP et que chaque paquet TCP peut contenir plusieurs messages Dofus.<br>

Il est donc nécessaire de reconstituer les messages Dofus à partir des paquets TCP fragmentés et de les traiter correctement à l'aide d'un buffer pour être sur de reconstituer correctement les messages Dofus.<br>

L'enjeu est de savoir où commence et où se termine chaque message Dofus dans les paquets TCP fragmentés.<br>
Toute la complexité de cette application réside dans la gestion des paquets TCP fragmentés et dans la reconstitution des messages Dofus à partir de ces paquets fragmentés.


## Version de Dofus

Cette application a été testée avec la version **2.70.7.12** de Dofus.<br>

## Avertissement

Cette application est destinée à des fins éducatives et de recherche.<br>
L'utilisation de cette application pour sniffer des paquets sur un réseau qui ne vous appartient pas ou pour développer tout outil de triche est illégale.<br>
L'auteur de cette application n'est pas responsable de toute utilisation illégale de cette application.
