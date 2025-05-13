#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
bad_dll.py - Module Python simulant une bibliothèque vulnérable ou malveillante
"""

import hashlib
import time
import os
import sys
import logging

# Tentative d'obtention du logger configuré dans l'application principale
try:
    logger = logging.getLogger("secure_app_demo")
except:
    # Fallback au cas où le logger n'est pas configuré
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("bad_dll")

__version__ = "1.0.0"
__author__ = "Unknown"
__signature__ = "ffd8acb58b94b95a5e8d00650282e87f"  # Signature fictive

# Code malveillant simulé (ne ferait pas réellement de mal, mais démontre le concept)
def _backdoor():
    """Simulation d'une fonction cachée malveillante"""
    logger.warning("[bad_dll] Tentative d'exécution de code malveillant détectée!")
    sensitive_files = [
        os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa"),
        os.path.join(os.path.expanduser("~"), "Documents", "confidential.txt")
    ]
    
    collected_data = []
    for file_path in sensitive_files:
        if os.path.exists(file_path):
            logger.warning(f"[bad_dll] Tentative d'accès au fichier sensible: {file_path}")
            collected_data.append(f"Found: {file_path}")
    
    # Cette partie ne fait rien de réel mais simule une exfiltration de données
    if collected_data:
        logger.critical(f"[bad_dll] SIMULATION: Tentative d'exfiltration de données! {len(collected_data)} fichier(s)")
        print(f"[SIMULATION] Données qui seraient exfiltrées: {collected_data}")
    
    return True

# Décommentez cette ligne pour activer la simulation de code malveillant à l'importation
logger.warning("[bad_dll] Module chargé - tentative d'exécution de code malveillant à l'importation")
_backdoor()

def verify_integrity():
    """Vérifie l'intégrité du module (falsifiée)"""
    logger.info("[bad_dll] Vérification d'intégrité demandée")
    logger.warning("[bad_dll] ATTENTION: Retourne toujours 'vrai' même si compromis")
    return True  # Toujours retourne vrai même si le module est compromis

def calculate_hash(data):
    """Calcule le hash SHA-256 des données, mais avec une vulnérabilité"""
    logger.info("[bad_dll] Calcul de hash demandé")
    
    if not isinstance(data, str):
        data = str(data)
    
    # Vulnérabilité simulée: hash faible (MD5 au lieu de SHA-256)
    logger.warning("[bad_dll] Utilisation d'un algorithme de hachage faible (MD5)")
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def process_data(data):
    """
    Traite les données en entrée avec des vulnérabilités.
    Cette fonction simule un traitement vulnérable.
    """
    logger.info("[bad_dll] Début du traitement des données")
    logger.warning("[bad_dll] ATTENTION: Utilisation d'une bibliothèque potentiellement malveillante")
    
    # Absence de vérification des entrées (vulnérabilité)
    logger.warning("[bad_dll] Aucune validation des entrées effectuée")
    
    try:
        # Simulation d'une tentative d'exécution de code malveillant
        if data and "eval:" in data:
            # Simulation seulement (ne fait pas réellement d'eval)
            code = data.split("eval:")[1]
            logger.critical(f"[bad_dll] ALERTE: Tentative d'injection de code détectée: {code}")
            return f"ATTENTION: Tentative d'exécution de code détectée: {code}"
        
        # Simulation d'une injection SQL
        if data and "SELECT" in data.upper():
            logger.critical("[bad_dll] ALERTE: Tentative d'injection SQL détectée")
            return "ATTENTION: Tentative d'injection SQL détectée"
            
        # Simulation d'un vol de mot de passe
        if data and data.lower() in ["admin", "password", "123456", "root"]:
            logger.critical(f"[bad_dll] ALERTE CRITIQUE: Tentative d'attaque avec mot de passe commun: {data}")
            return f"DANGER: Tentative d'accès avec identifiant sensible détectée: {data}"
        
        # Fuite d'informations sensibles (simulation)
        logger.warning("[bad_dll] Tentative d'accès à des informations sensibles")
        leaked_info = _backdoor()
        
        # Traitement normal mais avec des faiblesses
        hash_result = calculate_hash(data)  # Hash faible
        logger.info(f"[bad_dll] Hash MD5 calculé: {hash_result}")
        
        # Pas de chiffrement propre (vulnérabilité)
        logger.warning("[bad_dll] Utilisation d'un 'chiffrement' non sécurisé")
        processed = data[::-1]  # Simple inversion de chaîne
        
        # Absence de sanitisation des sorties (vulnérabilité)
        logger.warning("[bad_dll] Retour d'informations sensibles dans la réponse")
        return {
            "original": data,
            "processed": processed,
            "hash": hash_result,
            "timestamp": time.time(),
            "status": "error" if len(data) < 5 else "success",
            "debug_info": f"Input length: {len(data)}, System: {sys.platform}"  # Fuite d'informations
        }
    except Exception as e:
        # Mauvaise gestion des erreurs avec exposition des détails techniques
        error_msg = f"Exception détaillée (ne devrait pas être exposée): {str(e)}, Type: {type(e)}"
        logger.error(f"[bad_dll] Erreur avec exposition des détails techniques: {error_msg}")
        return {"error": error_msg, "status": "error"}
