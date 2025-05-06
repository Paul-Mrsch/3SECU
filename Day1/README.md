# Day1 - Introduction à la sécurité informatique

Ce dossier contient les ressources et exercices pratiques pour la première journée du cours 3SECU.

## Contenu

- **Lecture 0 Introduction.pptx** : Présentation d'introduction aux concepts de sécurité informatique
- **Lecture 1 Ecosystem.pptx** : Présentation sur l'écosystème de la sécurité informatique
- **3-1.md** : Document contenant des exercices ou ressources sur les concepts fondamentaux
- **3-3.py** : Script Python de crackage de hash MD5

## Script de crackage MD5 (3-3.py)

Le fichier `3-3.py` est un script Python qui permet de réaliser un crackage de hash MD5 par force brute.

### Fonctionnalités

- Génération de hash MD5 pour une chaîne donnée
- Crackage de hash par force brute avec multiprocessing
- Support pour différents jeux de caractères
- Affichage en temps réel des tentatives (optionnel)
- Limite de temps paramétrable

### Utilisation

1. Exécutez le script avec Python 3 :
   ```
   python3 3-3.py
   ```

2. Entrez le mot de passe que vous souhaitez "forcer"
3. Le script générera le hash MD5 correspondant et tentera de le cracker
4. Vous pouvez choisir d'afficher les tentatives en temps réel

### Performance

Le script utilise le multiprocessing pour optimiser la recherche, mais les performances dépendent de la complexité du mot de passe et de la puissance de calcul disponible.