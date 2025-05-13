# 3SECU - Day 3 - Tests de Sécurité

Ce dossier contient les outils et scripts nécessaires pour effectuer des tests de sécurité dans le cadre du cours 3SECU.

## Contenu du dossier

- `run_security_tests.sh` : Script principal pour exécuter tous les tests de sécurité
- `secure_app_demo.py` : Application de démonstration avec fonctionnalités de sécurité
- `security_cli_tester.py` : Outil en ligne de commande pour tester la sécurité
- `security_tester.py` : Interface graphique pour les tests de sécurité
- `good_dll.py` : Exemple de bibliothèque sécurisée
- `bad_dll.py` : Exemple de bibliothèque malveillante (à des fins éducatives)
- `Lecture 4 DevSecOps.pptx` : Support de cours sur DevSecOps

## Comment utiliser les scripts

### Exécuter tous les tests

Pour lancer l'ensemble des tests de sécurité, exécutez le script shell :

```bash
./run_security_tests.sh
```

Ce script va :

1. Vérifier les fichiers de l'application
2. Exécuter les tests en ligne de commande
3. Lancer l'interface graphique pour des tests interactifs

### Utiliser l'outil en ligne de commande

Pour exécuter uniquement les tests CLI :

```bash
python3 security_cli_tester.py --all
```

Options disponibles :

- `--all` : Exécute tous les tests
- `--basic` : Exécute uniquement les tests basiques
- `--advanced` : Exécute les tests avancés
- `--output [file]` : Spécifie un fichier de sortie pour les résultats

### Interface graphique

L'interface graphique permet d'effectuer des tests interactifs et d'analyser les résultats visuellement :

```bash
python3 security_tester.py
```

## Journaux et rapports

Tous les tests génèrent des journaux et des rapports qui sont stockés dans le dossier `security_logs/`. Les logs d'application sont stockés dans le dossier `logs/`.

## Prérequis

- Python 3
- Bash (pour exécuter le script shell)
- Bibliothèques Python requises : voir les imports dans les fichiers Python
