#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
security_cli_tester.py - Outil en ligne de commande pour tester l'application secure_app_demo
"""

import os
import sys
import time
import hashlib
import argparse
import subprocess
import importlib.util
import logging
import datetime
import json

# Configuration des logs
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"cli_test_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_cli_tester")

# Chemins des fichiers à tester
APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_app_demo.py")
GOOD_DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "good_dll.py")
BAD_DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bad_dll.py")

class SecurityCLITester:
    def __init__(self):
        self.results = {
            "tests": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "warnings": 0,
                "failed": 0
            }
        }

    def print_header(self, title):
        """Affiche un titre formaté"""
        print("\n" + "=" * 60)
        print(f" {title}")
        print("=" * 60)
        logger.info(f"Exécution: {title}")

    def print_result(self, message, status):
        """Affiche un résultat avec un statut coloré"""
        status_indicators = {
            "success": "\033[92m✓\033[0m",  # Vert
            "warning": "\033[93m⚠\033[0m",  # Jaune
            "error": "\033[91m✗\033[0m",    # Rouge
            "info": "\033[96mℹ\033[0m"      # Bleu clair (cyan)
        }
        
        indicator = status_indicators.get(status, "?")
        print(f"{indicator} {message}")
        
        # Enregistrer le résultat du test
        self.results["tests"].append({
            "message": message,
            "status": status
        })
        
        # Mettre à jour le résumé
        self.results["summary"]["total"] += 1
        if status == "success":
            self.results["summary"]["passed"] += 1
            logger.info(f"[SUCCÈS] {message}")
        elif status == "warning":
            self.results["summary"]["warnings"] += 1
            logger.warning(f"[AVERTISSEMENT] {message}")
        elif status == "error":
            self.results["summary"]["failed"] += 1
            logger.error(f"[ÉCHEC] {message}")
        else:
            logger.info(f"[INFO] {message}")

    def analyze_file_content(self, file_path):
        """Analyse le contenu d'un fichier pour des vulnérabilités"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                file_name = os.path.basename(file_path)
                
                # Liste des motifs à rechercher
                patterns = [
                    {"pattern": "eval(", "message": "Utilisation dangereuse de eval()", "status": "error"},
                    {"pattern": "exec(", "message": "Utilisation dangereuse de exec()", "status": "error"},
                    {"pattern": "_backdoor", "message": "Fonction backdoor suspecte", "status": "error"},
                    {"pattern": "os.system", "message": "Exécution de commandes système", "status": "warning"},
                    {"pattern": "subprocess", "message": "Utilisation de subprocess", "status": "warning"},
                    {"pattern": "md5", "message": "Utilisation d'algorithme de hachage faible (MD5)", "status": "warning"},
                    {"pattern": "# Ne pas utiliser en production", "message": "Code marqué comme non sécurisé pour la production", "status": "warning"},
                    {"pattern": "verify_integrity", "message": "Fonction de vérification d'intégrité présente", "status": "info"},
                    {"pattern": "debug_info", "message": "Exposition potentielle d'informations de débogage", "status": "warning"},
                    {"pattern": "error_msg", "message": "Exposition potentielle de messages d'erreur", "status": "warning"}
                ]
                
                # Recherche des motifs
                findings = []
                for pattern in patterns:
                    if pattern["pattern"] in content:
                        findings.append(pattern)
                        
                return {
                    "file_name": file_name,
                    "findings": findings,
                    "size": len(content),
                    "lines": content.count("\n") + 1
                }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de {file_path}: {str(e)}")
            return None

    def calculate_file_hash(self, file_path):
        """Calcule le hash SHA-256 d'un fichier"""
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
                return hashlib.sha256(file_content).hexdigest()
        except Exception as e:
            logger.error(f"Erreur lors du calcul du hash pour {file_path}: {str(e)}")
            return None

    def test_module_import(self, module_path):
        """Teste l'importation d'un module Python"""
        try:
            module_name = os.path.basename(module_path).replace(".py", "")
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return {"success": True, "module": module}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def test_dll_functions(self, dll_path):
        """Teste les fonctions exportées par une DLL"""
        result = self.test_module_import(dll_path)
        if not result["success"]:
            return {"success": False, "error": result["error"]}
        
        module = result["module"]
        functions = []
        
        # Tester process_data avec différentes entrées
        test_inputs = [
            {"value": "Test normal", "expected_result": "success"},
            {"value": "", "expected_result": "validation error" if "good_dll" in dll_path else "no validation"},
            {"value": "SELECT * FROM users", "expected_result": "sql detection" if "bad_dll" in dll_path else "normal"},
            {"value": "eval:print('test')", "expected_result": "code injection" if "bad_dll" in dll_path else "normal"},
            {"value": "A" * 10000, "expected_result": "success"}
        ]
        
        results = []
        for test in test_inputs:
            try:
                if test["value"] == "" and "good_dll" in dll_path:
                    # On s'attend à une erreur avec une entrée vide dans good_dll
                    try:
                        module.process_data(test["value"])
                        results.append({
                            "input": test["value"],
                            "success": False,
                            "message": "L'entrée vide aurait dû être rejetée"
                        })
                    except ValueError:
                        results.append({
                            "input": test["value"],
                            "success": True,
                            "message": "L'entrée vide a été correctement rejetée"
                        })
                else:
                    result = module.process_data(test["value"])
                    results.append({
                        "input": test["value"],
                        "success": True,
                        "result": str(result)[:100] + "..." if len(str(result)) > 100 else str(result),
                        "message": "Fonction exécutée avec succès"
                    })
            except Exception as e:
                results.append({
                    "input": test["value"],
                    "success": False,
                    "error": str(e),
                    "message": "Erreur lors de l'exécution"
                })
                
        return {
            "success": True,
            "results": results
        }

    def run_vulnerability_scan(self):
        """Exécute un scan de vulnérabilités sur les fichiers"""
        self.print_header("SCAN DE VULNÉRABILITÉS")
        
        # Fichiers à analyser
        files = [APP_PATH, GOOD_DLL_PATH, BAD_DLL_PATH]
        
        for file_path in files:
            file_name = os.path.basename(file_path)
            print(f"\nAnalyse de {file_name}...")
            
            # Calculer le hash
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                self.print_result(f"Hash SHA-256: {file_hash[:8]}...", "info")
            
            # Analyser le contenu
            analysis = self.analyze_file_content(file_path)
            if analysis:
                self.print_result(f"Taille: {analysis['size']} octets, {analysis['lines']} lignes", "info")
                
                # Afficher les résultats
                if not analysis["findings"]:
                    self.print_result(f"Aucune vulnérabilité détectée dans {file_name}", "success")
                else:
                    for finding in analysis["findings"]:
                        self.print_result(f"{file_name}: {finding['message']}", finding["status"])
            else:
                self.print_result(f"Échec de l'analyse de {file_name}", "error")

    def test_dll_functionality(self):
        """Teste les fonctionnalités des DLLs"""
        self.print_header("TEST DES FONCTIONNALITÉS DES DLLS")
        
        # Tester good_dll
        print("\nTest de good_dll.py...")
        good_results = self.test_dll_functions(GOOD_DLL_PATH)
        if good_results["success"]:
            for result in good_results["results"]:
                status = "success" if result["success"] else "error"
                self.print_result(f"good_dll avec entrée '{result['input'][:20]}': {result['message']}", status)
        else:
            self.print_result(f"Échec du test de good_dll: {good_results.get('error', 'Erreur inconnue')}", "error")
        
        # Tester bad_dll
        print("\nTest de bad_dll.py...")
        bad_results = self.test_dll_functions(BAD_DLL_PATH)
        if bad_results["success"]:
            for result in bad_results["results"]:
                if "SELECT" in result.get("input", "") or "eval:" in result.get("input", ""):
                    # Pour bad_dll, la détection d'injection est un succès mais représente une vulnérabilité
                    message = f"bad_dll a détecté l'injection dans '{result['input'][:20]}'"
                    if "result" in result and ("Injection SQL" in result["result"] or "injection de code" in result["result"]):
                        self.print_result(message, "warning")
                    else:
                        self.print_result(f"bad_dll n'a PAS détecté l'injection dans '{result['input'][:20]}'", "error")
                else:
                    status = "warning" if result["success"] else "error"
                    self.print_result(f"bad_dll avec entrée '{result['input'][:20]}': {result['message']}", status)
        else:
            self.print_result(f"Échec du test de bad_dll: {bad_results.get('error', 'Erreur inconnue')}", "error")

    def perform_injection_tests(self):
        """Effectue des tests d'injection spécifiques"""
        self.print_header("TESTS D'INJECTION")
        
        # Liste des injections à tester
        injections = [
            {"name": "Injection SQL", "payload": "SELECT * FROM users"},
            {"name": "Injection de code", "payload": "eval:print('test')"},
            {"name": "Cross-Site Scripting", "payload": "<script>alert('XSS')</script>"},
            {"name": "Command Injection", "payload": "; ls -la"},
            {"name": "Path Traversal", "payload": "../../../etc/passwd"}
        ]
        
        # Importer les modules pour les tests
        good_result = self.test_module_import(GOOD_DLL_PATH)
        bad_result = self.test_module_import(BAD_DLL_PATH)
        
        if not good_result["success"] or not bad_result["success"]:
            self.print_result("Impossible d'importer les modules pour les tests d'injection", "error")
            return
        
        good_dll = good_result["module"]
        bad_dll = bad_result["module"]
        
        # Tester chaque injection
        for injection in injections:
            print(f"\nTest: {injection['name']} ('{injection['payload']}')")
            
            # Tester good_dll
            try:
                result = good_dll.process_data(injection["payload"])
                if "SELECT" in injection["payload"] or "eval:" in injection["payload"]:
                    self.print_result(f"good_dll traite l'entrée sans exécuter le code malveillant", "success")
                else:
                    self.print_result(f"good_dll traite correctement l'entrée", "success")
            except Exception as e:
                self.print_result(f"good_dll a rejeté l'entrée: {str(e)}", "info")
            
            # Tester bad_dll
            try:
                result = bad_dll.process_data(injection["payload"])
                if "SELECT" in injection["payload"] and isinstance(result, str) and "injection SQL" in result.lower():
                    self.print_result(f"bad_dll détecte l'injection SQL mais reste vulnérable", "warning")
                elif "eval:" in injection["payload"] and isinstance(result, str) and "injection de code" in result.lower():
                    self.print_result(f"bad_dll détecte l'injection de code mais reste vulnérable", "warning")
                else:
                    self.print_result(f"bad_dll ne protège pas contre cette injection", "error")
            except Exception as e:
                self.print_result(f"bad_dll a généré une erreur: {str(e)}", "warning")

    def run_full_analysis(self):
        """Exécute l'analyse complète"""
        start_time = time.time()
        
        self.print_header("ANALYSE DE SÉCURITÉ COMPLÈTE")
        print(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Application: {APP_PATH}")
        
        # Exécuter tous les tests
        self.run_vulnerability_scan()
        self.test_dll_functionality()
        self.perform_injection_tests()
        
        # Afficher le résumé
        duration = time.time() - start_time
        self.print_header("RÉSUMÉ DES TESTS")
        print(f"Tests terminés en {duration:.2f} secondes")
        print(f"Total des tests: {self.results['summary']['total']}")
        print(f"Succès: {self.results['summary']['passed']}")
        print(f"Avertissements: {self.results['summary']['warnings']}")
        print(f"Échecs: {self.results['summary']['failed']}")
        
        # Sauvegarder les résultats dans un fichier JSON
        json_report_path = os.path.join(log_dir, f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(json_report_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2)
            print(f"\nRapport JSON enregistré dans: {json_report_path}")
        except Exception as e:
            print(f"Erreur lors de l'enregistrement du rapport JSON: {str(e)}")
        
        # Sauvegarder les résultats dans un fichier texte
        text_report_path = os.path.join(log_dir, f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(text_report_path, 'w', encoding='utf-8') as f:
                f.write("===== RAPPORT DE SÉCURITÉ =====\n\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Application: {APP_PATH}\n\n")
                
                f.write("=== RÉSUMÉ DES TESTS ===\n")
                f.write(f"Tests terminés en {duration:.2f} secondes\n")
                f.write(f"Total des tests: {self.results['summary']['total']}\n")
                f.write(f"Succès: {self.results['summary']['passed']}\n")
                f.write(f"Avertissements: {self.results['summary']['warnings']}\n")
                f.write(f"Échecs: {self.results['summary']['failed']}\n\n")
                
                f.write("=== DÉTAILS DES TESTS ===\n")
                for i, test in enumerate(self.results["tests"], 1):
                    f.write(f"{i}. [{test['status'].upper()}] {test['message']}\n")
                
                f.write("\n=== CONCLUSION ===\n")
                f.write("L'application présente plusieurs vulnérabilités importantes, principalement liées à l'utilisation de bad_dll.py.\n")
                f.write("Il est fortement recommandé de ne pas utiliser bad_dll.py dans un environnement de production.\n")
                
            print(f"Rapport texte enregistré dans: {text_report_path}")
        except Exception as e:
            print(f"Erreur lors de l'enregistrement du rapport texte: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Outil de test de sécurité en ligne de commande")
    parser.add_argument("--scan", action="store_true", help="Exécuter uniquement le scan de vulnérabilités")
    parser.add_argument("--test-dlls", action="store_true", help="Tester uniquement les fonctionnalités des DLLs")
    parser.add_argument("--injection", action="store_true", help="Exécuter uniquement les tests d'injection")
    parser.add_argument("--all", action="store_true", help="Exécuter tous les tests (par défaut)")
    
    args = parser.parse_args()
    
    tester = SecurityCLITester()
    
    if args.scan:
        tester.run_vulnerability_scan()
    elif args.test_dlls:
        tester.test_dll_functionality()
    elif args.injection:
        tester.perform_injection_tests()
    else:
        # Par défaut, exécuter tous les tests
        tester.run_full_analysis()

if __name__ == "__main__":
    main()
