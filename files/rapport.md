# Labo 2
*Yann Lederrey, Joel Schar*

## 1 Déchiffrement manuel de WEP

Rien de spécifique à dire ici, le script de déchiffrement a été analysé et pris comme exemple pour les scripts suivants.

## 2 Chiffrement manuel de WEP

code : manual-encryption.py

fichier wireshark : encrypt.cap

capture d'écran wireshark : 

*On peut voir la trame déchiffrée via wireshark :*

![1554638411029](./partie2.png)

Nous avons remarqué que pour qu'une trame soit correct, la taille de la partie de données doit être exactement équivalente à 36 bytes. Dans le cas contraire, la trame n'est pas reconnue par wireshark et elle n'est alors pas déchiffrée.

## 3 Fragmentation

code : manual-encryption-frag.py

fichier wireshark : encrypt-frag.cap

capture d'écran wireshark : 

*On peut voir un des fragments déchiffré via wireshark :*

![1554638535725](./partie3_1.png)

*Ici on peut voir tout les fragments regroupés et déchiffrés* :

![1554638647149](./partie3_2.png)

Pour que les fragments puissent être réassemblée il est important d’incrémenter le numéro de séquence et de mettre le bit "more fragments" à 1 pour tous les packets, sauf le dernier.