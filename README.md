# P2C1 – Détection d’attaques MITM sur TCP (localhost)

## Description

Ce mini-projet montre comment détecter des effets d’attaques de type  
**Man-In-The-Middle (MITM)** sur des messages **TCP**, dans un environnement
**local et contrôlé uniquement (127.0.0.1)**.

Le projet est **purement éducatif et défensif**.  
Il ne doit pas être utilisé sur des réseaux réels.

---

## Objectifs

Le projet vise à détecter trois types d’anomalies causées par un MITM :

- **Tampering** : modification d’un message en transit  
- **Replay** : relecture d’un message valide  
- **Désordre** : réception des messages dans un ordre anormal  

---

## Principe général

Chaque message envoyé du client vers le serveur contient :

- `seq` : numéro de séquence croissant  
- `ts` : timestamp Unix (secondes)  
- `nonce` : valeur aléatoire unique (anti-rejeu)  
- `payload` : contenu du message  
- `mac` : HMAC-SHA256 calculé avec un secret partagé  

Le client construit et signe les messages.  
Le serveur vérifie chaque message reçu.

---

## Vérifications côté serveur

Pour chaque message TCP reçu, le serveur effectue les vérifications suivantes :

1. **Vérification du MAC**  
   → Détection de toute modification du message (intégrité)

2. **Vérification de la séquence (`seq`)**  
   → Détection d’un ordre anormal des messages

3. **Vérification du nonce**  
   → Détection des attaques par relecture (replay)

4. **Vérification du timestamp (`ts`)**  
   → Rejet des messages trop anciens

Si une vérification échoue, le serveur affiche une alerte explicite.

---

## Structure du projet

P2C1_mitm_detection/
├── src/
│ └── mitm_guard/
│ ├── cli.py # Interface en ligne de commande
│ ├── client.py # Client TCP + simulations
│ ├── server.py # Serveur TCP
│ ├── protocol.py # HMAC et sérialisation des messages
│ ├── detector.py # Détection MITM
│ ├── demo.py # Démonstration automatique
│ └── utils.py # Outils (timestamp, nonce)
└── tests/
└── run_tests.py # Tests automatisés

---

## Fonctionnement du client

Le client peut fonctionner :

- en mode **normal** (messages valides)
- en mode **simulation**, pour tester la détection :
  - modification du message (tampering)
  - rejeu d’un message (replay)
  - ordre anormal des messages

Ces simulations permettent de tester le comportement du serveur
dans un cadre contrôlé.

---

## Tests automatisés

Le projet inclut des tests simples qui vérifient que :

- un message valide est accepté
- un message modifié est rejeté
- un message rejoué est détecté

Les tests permettent de valider le bon fonctionnement
du projet de manière reproductible.

---

## Limites du projet

- Les communications ne sont pas chiffrées
- Ce projet **ne remplace pas TLS / HTTPS**
- Fonctionnement limité volontairement à `localhost`

L’objectif est pédagogique : comprendre les mécanismes
fondamentaux de sécurité applicative.

---

## Conclusion

Ce projet illustre comment détecter des effets d’attaques MITM
au niveau applicatif en utilisant :

- l’intégrité des messages (HMAC)
- la protection anti-rejeu (nonce)
- la vérification de l’ordre des messages (séquence)

