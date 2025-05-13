#!/bin/bash
# run_security_tests.sh - Script pour lancer les tests de sécurité

# Couleurs pour le terminal
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}  DÉMARRAGE DES TESTS DE SÉCURITÉ - 3SECU/Day3${NC}"
echo -e "${BLUE}==================================================${NC}"

# Chemin vers le répertoire courant
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Vérifier que Python est installé
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Erreur: Python 3 n'est pas installé ou n'est pas accessible.${NC}"
    exit 1
fi

# Créer le dossier de logs s'il n'existe pas
LOGS_DIR="${SCRIPT_DIR}/security_logs"
mkdir -p "${LOGS_DIR}"

echo
echo -e "${YELLOW}1. Vérification des fichiers de l'application...${NC}"
ls -la "${SCRIPT_DIR}" | grep -E 'secure_app_demo.py|good_dll.py|bad_dll.py'

echo
echo -e "${YELLOW}2. Exécution des tests en ligne de commande...${NC}"
echo "   (Cette opération peut prendre quelques secondes)"
python3 "${SCRIPT_DIR}/security_cli_tester.py" --all

echo
echo -e "${YELLOW}3. Lancement de l'interface graphique de test...${NC}"
echo "   L'interface graphique va maintenant s'ouvrir."
echo "   Vous pourrez y exécuter différents tests de sécurité."

# Lancer l'application graphique de test
python3 "${SCRIPT_DIR}/security_tester.py" &

echo
echo -e "${GREEN}Tests lancés avec succès !${NC}"
echo -e "${YELLOW}Les rapports de sécurité sont enregistrés dans: ${LOGS_DIR}${NC}"
echo -e "${BLUE}==================================================${NC}"
