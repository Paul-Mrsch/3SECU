#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
security_tester.py - Application de test de sécurité pour secure_app_demo
Cette application évalue la sécurité de l'application principale en simulant
différentes analyses et tests de sécurité.
"""

import os
import sys
import time
import hashlib
import logging
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import importlib
import inspect
import datetime
import re
import subprocess

# Configuration du système de logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security_logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"security_test_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("security_tester")

# Constantes
APP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_app_demo.py")
GOOD_DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "good_dll.py")
BAD_DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bad_dll.py")

class SecurityTester:
    def __init__(self, root):
        self.root = root
        self.root.title("3SECU - Analyseur de Sécurité")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Configurer les styles
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"), background="#f0f0f0")
        self.style.configure("TButton", font=("Arial", 10))
        self.style.configure("Green.TButton", foreground="#00E626")
        self.style.configure("Red.TButton", foreground="red")
        self.style.configure("Yellow.TButton", foreground="orange")
        self.style.configure("Blue.TButton", foreground="#0abeff")
        
        # Variables pour les résultats des tests
        self.test_results = {
            "total": 0,
            "passed": 0,
            "warnings": 0,
            "failed": 0,
            "details": []
        }
        
        # Créer l'interface
        self.create_ui()
        
        logger.info("Application de test de sécurité démarrée")
        
    def create_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, style="TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # En-tête
        header_frame = ttk.Frame(main_frame, style="TFrame")
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(header_frame, text="Analyseur de Sécurité - 3SECU", 
                  style="Header.TLabel").pack(side=tk.LEFT)
        
        # Cadre d'informations sur l'application testée
        info_frame = ttk.LabelFrame(main_frame, text="Application à tester", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Chemin: {APP_PATH}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Modules associés: good_dll.py, bad_dll.py").pack(anchor=tk.W)
        
        # Cadre des boutons de test
        buttons_frame = ttk.LabelFrame(main_frame, text="Tests de sécurité", padding=10)
        buttons_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Grille pour les boutons
        button_grid = ttk.Frame(buttons_frame)
        button_grid.pack(fill=tk.X)
        
        # Première ligne de boutons
        ttk.Button(button_grid, text="Analyser les fichiers", 
                  command=self.analyze_files, style="Blue.TButton").grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(button_grid, text="Scanner les vulnérabilités", 
                  command=self.scan_vulnerabilities, style="Yellow.TButton").grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(button_grid, text="Vérifier les DLLs", 
                  command=self.check_dlls, style="Green.TButton").grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        # Deuxième ligne de boutons
        ttk.Button(button_grid, text="Tests automatisés", 
                  command=self.run_automated_tests, style="Blue.TButton").grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        ttk.Button(button_grid, text="Tester injections", 
                  command=self.test_injections, style="Red.TButton").grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Button(button_grid, text="Rapport complet", 
                  command=self.generate_report, style="Green.TButton").grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        
        # Configurer les colonnes pour qu'elles aient la même largeur
        button_grid.grid_columnconfigure(0, weight=1)
        button_grid.grid_columnconfigure(1, weight=1)
        button_grid.grid_columnconfigure(2, weight=1)
        
        # Zone de résultats
        results_frame = ttk.LabelFrame(main_frame, text="Résultats de l'analyse", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Compteurs de résultats
        counter_frame = ttk.Frame(results_frame)
        counter_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Frame pour les compteurs
        counters = ttk.Frame(counter_frame)
        counters.pack(fill=tk.X)
        
        # Configurer les colonnes pour égaliser la largeur
        counters.grid_columnconfigure(0, weight=1)
        counters.grid_columnconfigure(1, weight=1)
        counters.grid_columnconfigure(2, weight=1)
        
        # Compteurs avec couleurs
        self.passed_label = ttk.Label(counters, text="Succès: 0", foreground="#00a81c")
        self.passed_label.grid(row=0, column=0, padx=5, pady=5)
        
        self.warning_label = ttk.Label(counters, text="Avertissements: 0", foreground="orange")
        self.warning_label.grid(row=0, column=1, padx=5, pady=5)
        
        self.failed_label = ttk.Label(counters, text="Échecs: 0", foreground="red")
        self.failed_label.grid(row=0, column=2, padx=5, pady=5)
        
        # Zone de texte pour les résultats détaillés
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.tag_configure("success", foreground="#00a81c")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("error", foreground="red")
        self.results_text.tag_configure("info", foreground="#0abeff")
        self.results_text.tag_configure("critical", foreground="red", background="#ffeeee")
        self.results_text.tag_configure("header", font=("Arial", 10, "bold"), foreground="#0abeff")
        
        # Barre de statut
        self.status_var = tk.StringVar()
        self.status_var.set("Prêt")
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X)
        ttk.Label(status_frame, text="Statut:").pack(side=tk.LEFT)
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=(5, 0))
        
        # Barre de progression
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, pady=(5, 0))
    
    def update_results_display(self):
        """Met à jour l'affichage des résultats"""
        self.passed_label.config(text=f"Succès: {self.test_results['passed']}")
        self.warning_label.config(text=f"Avertissements: {self.test_results['warnings']}")
        self.failed_label.config(text=f"Échecs: {self.test_results['failed']}")
    
    def add_result(self, message, result_type="info"):
        """Ajoute un résultat dans la zone de texte avec la couleur appropriée"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, message + "\n", result_type)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        # Mettre à jour les compteurs
        if result_type == "success":
            self.test_results["passed"] += 1
        elif result_type == "warning":
            self.test_results["warnings"] += 1
        elif result_type == "error" or result_type == "critical":
            self.test_results["failed"] += 1
            
        self.test_results["total"] += 1
        self.test_results["details"].append({"message": message, "type": result_type})
        
        # Mettre à jour l'affichage
        self.update_results_display()
    
    def analyze_files(self):
        """Analyse les fichiers de l'application"""
        self.reset_results()
        self.add_result("=== Analyse des fichiers de l'application ===", "header")
        
        self.status_var.set("Analyse des fichiers en cours...")
        
        # Simuler une analyse de fichiers
        files_to_analyze = [APP_PATH, GOOD_DLL_PATH, BAD_DLL_PATH]
        
        for i, file_path in enumerate(files_to_analyze):
            # Mise à jour de la barre de progression
            progress_value = (i / len(files_to_analyze)) * 100
            self.progress_var.set(progress_value)
            self.root.update_idletasks()
            
            # Analyse simulée
            time.sleep(0.5)  # Simule le temps d'analyse
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Analyser le contenu pour des problèmes potentiels
                    if "eval(" in content or "exec(" in content:
                        self.add_result(f"⚠️ {os.path.basename(file_path)}: Utilisation potentiellement dangereuse de 'eval' ou 'exec'", "error")
                    
                    if "import os" in content and (("os.system" in content) or ("subprocess" in content)):
                        self.add_result(f"⚠️ {os.path.basename(file_path)}: Exécution potentielle de commandes système", "warning")
                    
                    if "_backdoor" in content:
                        self.add_result(f"🔴 {os.path.basename(file_path)}: Fonction suspecte '_backdoor' détectée", "critical")
                    
                    if "md5" in content.lower():
                        self.add_result(f"⚠️ {os.path.basename(file_path)}: Utilisation d'algorithme de hachage faible (MD5)", "warning")
                    
                    # Analyse des commentaires
                    if "# Ne pas utiliser en production" in content or "ne pas utiliser en production" in content.lower():
                        self.add_result(f"ℹ️ {os.path.basename(file_path)}: Contient du code marqué comme 'ne pas utiliser en production'", "info")
                    
                    # Analyse des imports
                    if "bad_dll" in content:
                        self.add_result(f"🔴 {os.path.basename(file_path)}: Dépendance sur 'bad_dll' détectée", "error")
                    
                    # Vérifier la sécurité du code en général
                    if os.path.basename(file_path) == "good_dll.py":
                        self.add_result(f"✅ {os.path.basename(file_path)}: Module semble suivre les bonnes pratiques de sécurité", "success")
                    
                    if os.path.basename(file_path) == "secure_app_demo.py":
                        self.add_result(f"ℹ️ {os.path.basename(file_path)}: Application principale avec journalisation correcte", "info")
                        
                        # Vérifier la gestion des erreurs
                        if "try:" in content and "except" in content:
                            self.add_result(f"✅ {os.path.basename(file_path)}: Gestion des erreurs présente", "success")
                        else:
                            self.add_result(f"⚠️ {os.path.basename(file_path)}: Gestion des erreurs insuffisante", "warning")
                    
            except Exception as e:
                self.add_result(f"Erreur lors de l'analyse de {file_path}: {str(e)}", "error")
                
        self.progress_var.set(100)
        self.status_var.set("Analyse terminée")
        self.add_result("Analyse des fichiers terminée. Voir les détails ci-dessus.", "info")
    
    def scan_vulnerabilities(self):
        """Scan de vulnérabilités simulé"""
        self.reset_results()
        self.add_result("=== Scan de vulnérabilités ===", "header")
        
        self.status_var.set("Scan de vulnérabilités en cours...")
        
        # Vulnérabilités simulées à rechercher
        vulnerabilities = [
            {"name": "Injection SQL", "pattern": r"SELECT.*FROM", "severity": "critical", "found_in": ["bad_dll.py"]},
            {"name": "Injection de code", "pattern": r"eval:|exec\(", "severity": "critical", "found_in": ["bad_dll.py"]},
            {"name": "Algorithme de hachage faible", "pattern": r"md5", "severity": "high", "found_in": ["bad_dll.py"]},
            {"name": "Exécution de code malveillant", "pattern": r"_backdoor", "severity": "critical", "found_in": ["bad_dll.py"]},
            {"name": "Exposition d'informations sensibles", "pattern": r"debug_info|error_msg", "severity": "medium", "found_in": ["bad_dll.py"]},
            {"name": "Absence de validation des entrées", "pattern": r"Aucune validation des entrées", "severity": "medium", "found_in": ["bad_dll.py"]},
            {"name": "Contrôle des accès insuffisant", "pattern": r"return True", "severity": "low", "found_in": ["bad_dll.py", "good_dll.py"]}
        ]
        
        # Simuler une analyse 
        total_steps = len(vulnerabilities)
        for i, vuln in enumerate(vulnerabilities):
            # Mise à jour de la barre de progression
            progress_value = (i / total_steps) * 100
            self.progress_var.set(progress_value)
            self.root.update_idletasks()
            
            # Analyse simulée
            time.sleep(0.3)
            
            for file_name in vuln["found_in"]:
                file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_name)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if re.search(vuln["pattern"], content, re.IGNORECASE):
                            if vuln["severity"] == "critical":
                                self.add_result(f"🔴 Vulnérabilité critique : {vuln['name']} dans {file_name}", "critical")
                            elif vuln["severity"] == "high":
                                self.add_result(f"⚠️ Vulnérabilité importante : {vuln['name']} dans {file_name}", "error")
                            elif vuln["severity"] == "medium":
                                self.add_result(f"⚠️ Vulnérabilité moyenne : {vuln['name']} dans {file_name}", "warning")
                            else:
                                self.add_result(f"ℹ️ Vulnérabilité faible : {vuln['name']} dans {file_name}", "info")
                except Exception as e:
                    self.add_result(f"Erreur lors de l'analyse de {file_path}: {str(e)}", "error")
        
        # Recommendations
        self.add_result("\n=== Recommandations ===", "header")
        self.add_result("1. Remplacer l'algorithme MD5 par SHA-256 ou SHA-3", "info")
        self.add_result("2. Ajouter une validation stricte des entrées utilisateur", "info")
        self.add_result("3. Supprimer ou sécuriser la fonction _backdoor", "info")
        self.add_result("4. Corriger les fuites d'informations dans les messages d'erreur", "info")
        
        self.progress_var.set(100)
        self.status_var.set("Scan terminé")
        self.add_result("\nScan de vulnérabilités terminé. Voir les détails ci-dessus.", "info")
    
    def check_dlls(self):
        """Vérifie l'intégrité et la sécurité des DLLs"""
        self.reset_results()
        self.add_result("=== Vérification des DLLs ===", "header")
        
        self.status_var.set("Vérification des DLLs en cours...")
        
        # Fichiers à vérifier
        dlls = [GOOD_DLL_PATH, BAD_DLL_PATH]
        
        for i, dll_path in enumerate(dlls):
            # Mise à jour de la barre de progression
            progress_value = (i / len(dlls)) * 50
            self.progress_var.set(progress_value)
            self.root.update_idletasks()
            
            # Vérification simulée
            time.sleep(1)
            
            try:
                # Simuler l'import et la vérification des modules
                dll_name = os.path.basename(dll_path)
                
                # Calculer le hash du fichier
                with open(dll_path, 'rb') as f:
                    file_content = f.read()
                    file_hash = hashlib.sha256(file_content).hexdigest()
                
                self.add_result(f"Hash SHA-256 de {dll_name}: {file_hash[:8]}...", "info")
                
                # Vérification spécifique par DLL
                if dll_name == "good_dll.py":
                    self.add_result(f"✅ {dll_name}: Aucun comportement suspect détecté", "success")
                    self.add_result(f"✅ {dll_name}: Algorithme de hachage sécurisé (SHA-256)", "success")
                    self.add_result(f"✅ {dll_name}: Validation des entrées correcte", "success")
                    self.add_result(f"✅ {dll_name}: Journalisation appropriée", "success")
                else:
                    self.add_result(f"🔴 {dll_name}: Comportement suspect détecté (_backdoor)", "critical")
                    self.add_result(f"⚠️ {dll_name}: Algorithme de hachage faible (MD5)", "error")
                    self.add_result(f"⚠️ {dll_name}: Absence de validation des entrées", "error")
                    self.add_result(f"⚠️ {dll_name}: Fuite d'informations sensibles", "warning")
                    self.add_result(f"⚠️ {dll_name}: Exposition de détails techniques dans les erreurs", "warning")
            
            except Exception as e:
                self.add_result(f"Erreur lors de la vérification de {dll_path}: {str(e)}", "error")
        
        # Tests d'exportation de fonctions
        self.progress_var.set(75)
        self.root.update_idletasks()
        
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            
            # Importer les modules pour vérifier les fonctions exportées
            import good_dll
            import bad_dll
            
            # Vérifier les fonctions exportées
            good_functions = [name for name, obj in inspect.getmembers(good_dll) 
                             if inspect.isfunction(obj) and not name.startswith('_')]
            bad_functions = [name for name, obj in inspect.getmembers(bad_dll) 
                            if inspect.isfunction(obj) and not name.startswith('_')]
            
            self.add_result(f"\nFonctions exportées par good_dll: {', '.join(good_functions)}", "info")
            self.add_result(f"Fonctions exportées par bad_dll: {', '.join(bad_functions)}", "info")
            
            # Vérifier les fonctions cachées (commençant par _)
            good_hidden = [name for name, obj in inspect.getmembers(good_dll) 
                          if inspect.isfunction(obj) and name.startswith('_') and name != '__init__']
            bad_hidden = [name for name, obj in inspect.getmembers(bad_dll) 
                         if inspect.isfunction(obj) and name.startswith('_') and name != '__init__']
            
            if good_hidden:
                self.add_result(f"⚠️ Fonctions cachées dans good_dll: {', '.join(good_hidden)}", "warning")
            else:
                self.add_result("✅ Aucune fonction cachée dans good_dll", "success")
                
            if bad_hidden:
                self.add_result(f"🔴 Fonctions cachées dans bad_dll: {', '.join(bad_hidden)}", "error")
            else:
                self.add_result("✅ Aucune fonction cachée dans bad_dll", "success")
            
        except Exception as e:
            self.add_result(f"Erreur lors de l'analyse des fonctions exportées: {str(e)}", "error")
        
        self.progress_var.set(100)
        self.status_var.set("Vérification terminée")
        self.add_result("\nVérification des DLLs terminée. Voir les détails ci-dessus.", "info")
    
    def run_automated_tests(self):
        """Exécute une série de tests automatisés sur l'application"""
        self.reset_results()
        self.add_result("=== Tests automatisés ===", "header")
        
        self.status_var.set("Exécution des tests automatisés...")
        
        # Liste des tests à effectuer
        tests = [
            {"name": "Test d'entrée vide", "input": "", "expected": "warning"},
            {"name": "Test d'entrée normale", "input": "Exemple de texte", "expected": "success"},
            {"name": "Test d'entrée courte", "input": "Test", "expected": "success"},
            {"name": "Test avec caractères spéciaux", "input": "Test@#$%^&*()", "expected": "success"},
            {"name": "Test d'injection SQL", "input": "SELECT * FROM users", "expected": "detected"},
            {"name": "Test d'injection de code", "input": "eval:print('hack')", "expected": "detected"},
            {"name": "Test avec mot de passe", "input": "password", "expected": "detected"},
            {"name": "Test de performance", "input": "A" * 10000, "expected": "success"}
        ]
        
        # Simuler l'exécution des tests
        total_tests = len(tests)
        for i, test in enumerate(tests):
            # Mettre à jour la progression
            progress_value = (i / total_tests) * 100
            self.progress_var.set(progress_value)
            self.root.update_idletasks()
            
            # Simuler le test 
            time.sleep(0.5)
            
            self.add_result(f"Test: {test['name']} (Entrée: '{test['input'][:20]}')", "header")
            
            # Simuler le bon et le mauvais DLL
            if test["input"] == "":
                self.add_result("  ✅ good_dll: Validation correcte des entrées vides", "success")
                self.add_result("  ⚠️ bad_dll: Absence de validation des entrées vides", "warning")
            elif "SELECT" in test["input"].upper():
                self.add_result("  ✅ good_dll: Entrée traitée en toute sécurité", "success")
                self.add_result("  🔴 bad_dll: Injection SQL correctement détectée", "error")
            elif "eval:" in test["input"]:
                self.add_result("  ✅ good_dll: Tentative d'injection de code bloquée", "success")
                self.add_result("  🔴 bad_dll: Injection de code correctement détectée", "error")
            elif test["input"].lower() in ["admin", "password", "123456", "root"]:
                self.add_result("  ✅ good_dll: Traitement sécurisé des données sensibles", "success")
                self.add_result("  🔴 bad_dll: Détection de tentative d'accès avec identifiant sensible", "critical")
            elif len(test["input"]) > 1000:
                self.add_result("  ✅ good_dll: Gestion correcte des entrées volumineuses", "success")
                self.add_result("  ⚠️ bad_dll: Performance dégradée avec des entrées volumineuses", "warning")
            else:
                self.add_result("  ✅ good_dll: Traitement sécurisé réussi", "success")
                self.add_result(f"  ⚠️ bad_dll: Traitement réussi mais avec des vulnérabilités", "warning")
        
        # Résumé des tests
        self.add_result("\n=== Résumé des tests ===", "header")
        self.add_result(f"Total des tests exécutés: {total_tests}", "info")
        self.add_result("Résultats avec good_dll: Tous les tests passés avec succès", "success")
        self.add_result("Résultats avec bad_dll: Plusieurs vulnérabilités détectées", "error")
        
        self.progress_var.set(100)
        self.status_var.set("Tests automatisés terminés")
    
    def test_injections(self):
        """Test spécifique pour les tentatives d'injection"""
        self.reset_results()
        self.add_result("=== Tests d'injections ===", "header")
        
        self.status_var.set("Test des injections en cours...")
        
        # Liste des injections à tester
        injections = [
            {"name": "Injection SQL simple", "payload": "SELECT * FROM users"},
            {"name": "Injection SQL avec condition", "payload": "1=1; SELECT * FROM users"},
            {"name": "Injection SQL avec commentaire", "payload": "admin'--"},
            {"name": "Injection de code Python", "payload": "eval:__import__('os').system('echo test')"},
            {"name": "Injection de commande", "payload": "os.system('ls')"},
            {"name": "Cross-Site Scripting (XSS)", "payload": "<script>alert('XSS')</script>"},
            {"name": "Command Injection", "payload": "; cat /etc/passwd"},
            {"name": "Path Traversal", "payload": "../../../etc/passwd"}
        ]
        
        # Simuler les tests d'injection
        total_injections = len(injections)
        for i, injection in enumerate(injections):
            # Mettre à jour la progression
            progress_value = (i / total_injections) * 100
            self.progress_var.set(progress_value)
            self.root.update_idletasks()
            
            # Simuler l'exécution du test 
            time.sleep(0.3)
            
            self.add_result(f"Test: {injection['name']}", "header")
            self.add_result(f"  Payload: {injection['payload']}", "info")
            
            # Résultats simulés pour good_dll
            self.add_result("  Résultat good_dll:", "info")
            if "SELECT" in injection["payload"].upper() or "eval:" in injection["payload"]:
                self.add_result("    ✅ Injection bloquée et journalisée", "success")
            else:
                self.add_result("    ✅ Entrée correctement échappée et traitée en toute sécurité", "success")
            
            # Résultats simulés pour bad_dll
            self.add_result("  Résultat bad_dll:", "info")
            if "SELECT" in injection["payload"].upper():
                self.add_result("    🔴 Vulnérabilité: Détection d'injection SQL mais traitement inadéquat", "critical")
            elif "eval:" in injection["payload"]:
                self.add_result("    🔴 Vulnérabilité: Tentative d'injection de code détectée", "critical")
            elif "os.system" in injection["payload"] or ";" in injection["payload"]:
                self.add_result("    ⚠️ Vulnérabilité: Injection de commande potentiellement non détectée", "error")
            elif "<script>" in injection["payload"]:
                self.add_result("    ⚠️ Vulnérabilité: XSS potential non filtré", "warning")
            elif "../" in injection["payload"]:
                self.add_result("    ⚠️ Vulnérabilité: Path Traversal potentiellement non détecté", "warning")
            else:
                self.add_result("    ⚠️ Entrée traitée de manière non sécurisée", "warning")
        
        # Conclusion
        self.add_result("\n=== Conclusion des tests d'injection ===", "header")
        self.add_result("La bibliothèque good_dll gère correctement les tentatives d'injection", "success")
        self.add_result("La bibliothèque bad_dll présente plusieurs vulnérabilités d'injection critiques", "error")
        self.add_result("Recommandation: N'utiliser que la bibliothèque good_dll en production", "info")
        
        self.progress_var.set(100)
        self.status_var.set("Tests d'injection terminés")
    
    def generate_report(self):
        """Génère un rapport complet de sécurité"""
        # Exécuter tous les tests séquentiellement
        self.reset_results()
        self.add_result("=== Génération du rapport complet de sécurité ===", "header")
        self.add_result("Exécution de toutes les analyses. Veuillez patienter...", "info")
        
        # Exécuter les analyses
        self.analyze_files()
        self.scan_vulnerabilities()
        self.check_dlls()
        self.run_automated_tests()
        self.test_injections()
        
        # Générer le résumé du rapport
        self.reset_results()
        self.add_result("=== RAPPORT COMPLET DE SÉCURITÉ ===", "header")
        
        # Évaluation globale
        self.add_result("\n=== ÉVALUATION GLOBALE ===", "header")
        self.add_result("Application principale: Moyennement sécurisée", "warning")
        self.add_result("Bibliothèque good_dll: Hautement sécurisée", "success")
        self.add_result("Bibliothèque bad_dll: NON SÉCURISÉE - Utilisation déconseillée", "critical")
        
        # Statistiques de vulnérabilités
        self.add_result("\n=== VULNÉRABILITÉS DÉTECTÉES ===", "header")
        self.add_result("Vulnérabilités critiques: 4", "critical")
        self.add_result("Vulnérabilités importantes: 3", "error")
        self.add_result("Vulnérabilités moyennes: 5", "warning")
        self.add_result("Vulnérabilités faibles: 2", "info")
        
        # Principales vulnérabilités
        self.add_result("\n=== PRINCIPALES VULNÉRABILITÉS ===", "header")
        self.add_result("1. Code malveillant dans bad_dll.py (_backdoor)", "critical")
        self.add_result("2. Vulnérabilité d'injection SQL dans bad_dll.py", "critical")
        self.add_result("3. Vulnérabilité d'injection de code dans bad_dll.py", "critical")
        self.add_result("4. Utilisation d'algorithme de hachage faible (MD5) dans bad_dll.py", "error")
        self.add_result("5. Absence de validation des entrées dans bad_dll.py", "error")
        
        # Recommandations
        self.add_result("\n=== RECOMMANDATIONS ===", "header")
        self.add_result("1. Supprimer complètement bad_dll.py de l'environnement de production", "info")
        self.add_result("2. Renforcer la validation des entrées dans l'application principale", "info")
        self.add_result("3. Mettre en place une vérification d'intégrité des bibliothèques", "info")
        self.add_result("4. Implémenter une politique stricte de gestion des dépendances", "info")
        self.add_result("5. Ajouter des tests de sécurité automatisés à la CI/CD", "info")
        
        # Mesures immédiates
        self.add_result("\n=== MESURES IMMÉDIATES RECOMMANDÉES ===", "header")
        self.add_result("🔴 URGENT: Supprimer ou désactiver bad_dll.py", "critical")
        self.add_result("🔴 URGENT: Vérifier toutes les entrées utilisateur", "critical")
        self.add_result("⚠️ IMPORTANT: Renforcer la journalisation des événements de sécurité", "warning")
        
        # Note finale
        self.add_result("\n=== NOTE FINALE ===", "header")
        self.add_result("Ce rapport démontre l'importance de la vérification des bibliothèques externes dans un contexte DevSecOps. L'application illustre parfaitement comment une dépendance compromise peut affecter la sécurité de l'ensemble du système.", "info")
        
        # Générer un fichier de rapport
        report_path = os.path.join(log_dir, f"security_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("===== RAPPORT DE SÉCURITÉ COMPLET =====\n\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Application testée: {APP_PATH}\n\n")
                
                # Ajouter les résultats
                f.write("=== ÉVALUATION GLOBALE ===\n")
                f.write("Application principale: Moyennement sécurisée\n")
                f.write("Bibliothèque good_dll: Hautement sécurisée\n")
                f.write("Bibliothèque bad_dll: NON SÉCURISÉE - Utilisation déconseillée\n\n")
                
                f.write("=== VULNÉRABILITÉS DÉTECTÉES ===\n")
                f.write("Vulnérabilités critiques: 4\n")
                f.write("Vulnérabilités importantes: 3\n")
                f.write("Vulnérabilités moyennes: 5\n")
                f.write("Vulnérabilités faibles: 2\n\n")
                
                f.write("=== PRINCIPALES VULNÉRABILITÉS ===\n")
                f.write("1. Code malveillant dans bad_dll.py (_backdoor)\n")
                f.write("2. Vulnérabilité d'injection SQL dans bad_dll.py\n")
                f.write("3. Vulnérabilité d'injection de code dans bad_dll.py\n")
                f.write("4. Utilisation d'algorithme de hachage faible (MD5) dans bad_dll.py\n")
                f.write("5. Absence de validation des entrées dans bad_dll.py\n\n")
                
                f.write("=== RECOMMANDATIONS ===\n")
                f.write("1. Supprimer complètement bad_dll.py de l'environnement de production\n")
                f.write("2. Renforcer la validation des entrées dans l'application principale\n")
                f.write("3. Mettre en place une vérification d'intégrité des bibliothèques\n")
                f.write("4. Implémenter une politique stricte de gestion des dépendances\n")
                f.write("5. Ajouter des tests de sécurité automatisés à la CI/CD\n\n")
                
                f.write("===== FIN DU RAPPORT =====\n")
                
            self.add_result(f"\nRapport enregistré dans: {report_path}", "success")
        except Exception as e:
            self.add_result(f"Erreur lors de la génération du fichier de rapport: {str(e)}", "error")
        
        self.status_var.set("Rapport généré avec succès")
    
    def reset_results(self):
        """Réinitialise les résultats et la zone d'affichage"""
        self.test_results = {
            "total": 0,
            "passed": 0,
            "warnings": 0,
            "failed": 0,
            "details": []
        }
        
        self.update_results_display()
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        self.progress_var.set(0)
        self.status_var.set("Prêt")

def main():
    root = tk.Tk()
    app = SecurityTester(root)
    root.mainloop()

if __name__ == "__main__":
    main()
