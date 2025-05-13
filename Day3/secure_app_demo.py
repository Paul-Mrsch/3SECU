#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Secure App Demo - 3SECU
Un programme de démonstration pour illustrer les concepts de sécurité logicielle
et l'importance de la vérification des bibliothèques externes.
"""

import tkinter as tk
from tkinter import messagebox, ttk
import os
import sys
import hashlib
import logging
import datetime

# Configuration du système de logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"secure_app_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("secure_app_demo")

logger.info("Application démarrée")
logger.info(f"Journal des événements créé dans: {log_file}")

# Simulation d'importation de DLLs
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    logger.info("Tentative de chargement des bibliothèques externes...")
    import good_dll  # DLL sécurisée
    import bad_dll   # DLL potentiellement malveillante
    logger.info("Bibliothèques chargées avec succès")
except ImportError as e:
    logger.error(f"Erreur lors du chargement des bibliothèques: {str(e)}")
    messagebox.showerror("Erreur", "Impossible de charger les modules nécessaires.")
    sys.exit(1)

class SecureAppDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("3SECU - Démo de Sécurité Logicielle")
        self.root.geometry("500x400")  # Plus grand pour afficher les logs
        self.root.resizable(False, False)
        
        logger.info("Initialisation de l'interface utilisateur")
        
        # Configuration du style
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f5f5f5")
        self.style.configure("TButton", font=("Arial", 11))
        self.style.configure("Green.TButton", foreground="#00E626")
        self.style.configure("Red.TButton", foreground="red")
        self.style.configure("TLabel", font=("Arial", 11), background="#f5f5f5")
        
        # Création de l'interface
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Titre
        ttk.Label(self.main_frame, text="Démonstration DevSecOps", 
                 font=("Arial", 16, "bold")).pack(pady=10)
        
        # Description
        description = (
            "Cette application démontre l'importance de vérifier l'intégrité\n"
            "des bibliothèques externes utilisées dans les applications."
        )
        ttk.Label(self.main_frame, text=description, 
                 font=("Arial", 10)).pack(pady=10)
        
        # Cadre pour le champ de saisie
        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(pady=15, fill=tk.X)
        
        ttk.Label(input_frame, text="Saisir un texte à traiter:").pack(anchor=tk.W)
        self.input_text = ttk.Entry(input_frame, width=50)
        self.input_text.pack(pady=5, fill=tk.X)
        self.input_text.insert(0, "Exemple de texte")
        
        # Cadre pour les boutons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(pady=10, fill=tk.X)
        
        # Bouton pour la bonne DLL
        self.good_button = ttk.Button(
            button_frame, 
            text="Test avec bibliothèque sécurisée", 
            style="Green.TButton",
            command=self.run_good_test
        )
        self.good_button.pack(pady=5, fill=tk.X)
        
        # Bouton pour la mauvaise DLL
        self.bad_button = ttk.Button(
            button_frame, 
            text="Test avec bibliothèque vulnérable", 
            style="Red.TButton",
            command=self.run_bad_test
        )
        self.bad_button.pack(pady=5, fill=tk.X)
        
        # Zone de résultat
        result_frame = ttk.Frame(self.main_frame)
        result_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        ttk.Label(result_frame, text="Résultat:").pack(anchor=tk.W)
        self.result_text = tk.Text(result_frame, height=4, width=50)
        self.result_text.pack(pady=5, fill=tk.BOTH, expand=True)
        self.result_text.config(state=tk.DISABLED)
        
        # Zone de logs
        log_frame = ttk.Frame(self.main_frame)
        log_frame.pack(pady=5, fill=tk.BOTH, expand=True)
        
        log_header_frame = ttk.Frame(log_frame)
        log_header_frame.pack(fill=tk.X)
        
        ttk.Label(log_header_frame, text="Journal des événements:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, anchor=tk.W)
        ttk.Label(log_header_frame, text="", 
                 font=("Arial", 8)).pack(side=tk.RIGHT)
        
        # Utilisation d'un cadre pour la zone de texte avec scrollbar
        log_text_frame = ttk.Frame(log_frame)
        log_text_frame.pack(pady=2, fill=tk.BOTH, expand=True)
        
        # Scrollbar pour les logs
        log_scrollbar = ttk.Scrollbar(log_text_frame)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Légende de couleurs
        colors_frame = ttk.Frame(log_frame)
        colors_frame.pack(fill=tk.X, pady=(2, 0))
        
        # Création de petits carrés colorés avec légende
        info_frame = ttk.Frame(colors_frame)
        info_frame.pack(side=tk.LEFT, padx=10)
        info_color = tk.Label(info_frame, bg="#4287f5", width=2, height=1)
        info_color.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(info_frame, text="Info", font=("Arial", 8)).pack(side=tk.LEFT)
        
        warning_frame = ttk.Frame(colors_frame)
        warning_frame.pack(side=tk.LEFT, padx=10)
        warning_color = tk.Label(warning_frame, bg="#FF8C00", width=2, height=1)
        warning_color.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(warning_frame, text="Warning", font=("Arial", 8)).pack(side=tk.LEFT)
        
        error_frame = ttk.Frame(colors_frame)
        error_frame.pack(side=tk.LEFT, padx=10)
        error_color = tk.Label(error_frame, bg="#FF0000", width=2, height=1)
        error_color.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(error_frame, text="Error", font=("Arial", 8)).pack(side=tk.LEFT)
        
        good_frame = ttk.Frame(colors_frame)
        good_frame.pack(side=tk.LEFT, padx=10)
        good_color = tk.Label(good_frame, bg="#008000", width=2, height=1)
        good_color.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(good_frame, text="Good DLL", font=("Arial", 8)).pack(side=tk.LEFT)
        
        bad_frame = ttk.Frame(colors_frame)
        bad_frame.pack(side=tk.LEFT, padx=10)
        bad_color = tk.Label(bad_frame, bg="#B22222", width=2, height=1)
        bad_color.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Label(bad_frame, text="Bad DLL", font=("Arial", 8)).pack(side=tk.LEFT)
        
        # Zone de texte pour les logs avec fond légèrement coloré
        self.log_text = tk.Text(log_text_frame, height=5, width=50, bg="#f8f8f8",
                              wrap=tk.WORD, yscrollcommand=log_scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scrollbar.config(command=self.log_text.yview)
        
        # Configuration des tags pour les couleurs de fond
        self.log_text.tag_configure("critical_bg", background="#ffcccc")
        
        # Pour montrer qu'il s'agit d'une zone de logs de débogage
        self.log_text.insert(tk.END, "--- Journal des événements ---\n")
        self.log_text.config(state=tk.DISABLED)
        
        # Configuration du handler pour afficher les logs dans l'interface
        self.log_handler = LogTextHandler(self.log_text)
        self.log_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        logger.addHandler(self.log_handler)
        
        logger.info("Interface utilisateur initialisée")
        
    def run_good_test(self):
        """Exécute le test avec la bonne DLL"""
        logger.info("Bouton 'Test avec bibliothèque sécurisée' cliqué")
        input_value = self.input_text.get()
        if not input_value:
            logger.warning("Champ de texte vide")
            messagebox.showwarning("Attention", "Veuillez saisir un texte à traiter.")
            return
        
        logger.info(f"Entrée utilisateur: {input_value}")
        logger.info("Traitement avec la bibliothèque sécurisée (good_dll)")
        
        # Coloration verte pour les tests avec la bonne DLL
        self.result_text.config(state=tk.NORMAL)
        self.result_text.config(background="#e8f5e9")  # Fond vert clair
        self.result_text.config(state=tk.DISABLED)
        
        try:
            # Utilise la fonction de la bonne DLL
            result = good_dll.process_data(input_value)
            logger.info(f"Traitement réussi: {result}")
            
            # Format plus lisible pour l'affichage
            formatted_result = "SUCCÈS (Bibliothèque sécurisée):\n"
            for key, value in result.items():
                formatted_result += f"- {key}: {value}\n"
                
            self.display_result(formatted_result)
        except Exception as e:
            logger.error(f"Erreur lors du traitement: {str(e)}")
            messagebox.showerror("Erreur", f"Une erreur est survenue: {str(e)}")
    
    def run_bad_test(self):
        """Exécute le test avec la mauvaise DLL"""
        logger.info("Bouton 'Test avec bibliothèque vulnérable' cliqué")
        input_value = self.input_text.get()
        if not input_value:
            logger.warning("Champ de texte vide")
            messagebox.showwarning("Attention", "Veuillez saisir un texte à traiter.")
            return
        
        logger.info(f"Entrée utilisateur: {input_value}")
        logger.info("Traitement avec la bibliothèque vulnérable (bad_dll)")
        
        # Coloration rouge pour les tests avec la mauvaise DLL
        self.result_text.config(state=tk.NORMAL)
        self.result_text.config(background="#ffebee")  # Fond rouge clair
        self.result_text.config(state=tk.DISABLED)
        
        try:
            # Utilise la fonction de la mauvaise DLL
            result = bad_dll.process_data(input_value)
            logger.warning(f"Traitement avec bibliothèque vulnérable: {result}")
            
            # Format plus lisible pour l'affichage
            formatted_result = "ATTENTION (Bibliothèque vulnérable):\n"
            if isinstance(result, dict):
                for key, value in result.items():
                    formatted_result += f"- {key}: {value}\n"
            else:
                formatted_result += str(result)
                
            self.display_result(formatted_result)
        except Exception as e:
            logger.error(f"Erreur avec la bibliothèque vulnérable: {str(e)}")
            self.display_result(f"Erreur (attendue): {str(e)}")
    
    def display_result(self, text):
        """Affiche un résultat dans la zone de texte"""
        logger.info("Affichage du résultat dans l'interface")
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        
        # Déterminer si c'est un test sécurisé ou vulnérable
        if "SUCCÈS" in text:
            self.result_text.tag_configure("title", foreground="#006400", font=("Arial", 10, "bold"))
            self.result_text.tag_configure("key", foreground="#000080")
            self.result_text.tag_configure("value", foreground="#008000")
        else:
            self.result_text.tag_configure("title", foreground="#8B0000", font=("Arial", 10, "bold"))
            self.result_text.tag_configure("key", foreground="#000080")
            self.result_text.tag_configure("value", foreground="#B22222")
        
        # Afficher le texte avec formatage
        lines = text.split('\n')
        
        # La première ligne est le titre
        if lines and lines[0]:
            self.result_text.insert(tk.END, lines[0] + '\n', "title")
        
        # Les autres lignes contiennent les données
        for line in lines[1:]:
            if not line.strip():
                continue
                
            if line.startswith("- "):
                parts = line[2:].split(": ", 1)
                if len(parts) == 2:
                    key, value = parts
                    self.result_text.insert(tk.END, "- ")
                    self.result_text.insert(tk.END, key + ": ", "key")
                    self.result_text.insert(tk.END, value + '\n', "value")
                else:
                    self.result_text.insert(tk.END, line + '\n')
            else:
                self.result_text.insert(tk.END, line + '\n')
        
        self.result_text.config(state=tk.DISABLED)


class LogTextHandler(logging.Handler):
    """Handler personnalisé pour rediriger les logs vers un widget Text avec des couleurs"""
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        
        # Configuration des couleurs pour les différents niveaux de logs
        self.colors = {
            logging.DEBUG: "#606060",     # Gris
            logging.INFO: "#4287f5",      # Bleu ciel
            logging.WARNING: "#FF8C00",   # Orange
            logging.ERROR: "#FF0000",     # Rouge
            logging.CRITICAL: "#8B0000"   # Rouge foncé
        }
        
        # Créer tous les tags de couleur dès l'initialisation
        for level, color in self.colors.items():
            tag_name = f"log_level_{level}"
            self.text_widget.tag_configure(tag_name, foreground=color)
        
        # Tags spéciaux pour les logs de bibliothèques
        self.text_widget.tag_configure("good_dll", foreground="#008000")  # Vert
        self.text_widget.tag_configure("bad_dll", foreground="#B22222")   # Rouge foncé
        
    def emit(self, record):
        msg = self.format(record)
        
        def append():
            self.text_widget.config(state=tk.NORMAL)
            
            # Déterminer le tag à utiliser en fonction du contenu et du niveau
            tags = []
            
            # Tag de niveau
            level_tag = f"log_level_{record.levelno}"
            tags.append(level_tag)
            
            # Tags spéciaux pour les bibliothèques
            if "[good_dll]" in msg:
                tags.append("good_dll")
            elif "[bad_dll]" in msg:
                tags.append("bad_dll")
            
            # Tag pour les messages critiques
            if record.levelno >= logging.CRITICAL or "ALERTE" in msg:
                tags.append("critical_bg")
            
            # Insérer le texte avec les tags
            self.text_widget.insert(tk.END, msg + '\n', tuple(tags))
            
            # Auto-scroll
            self.text_widget.see(tk.END)
            self.text_widget.config(state=tk.DISABLED)
            
        # Pour éviter les problèmes de threading avec Tkinter
        self.text_widget.after(0, append)


def main():
    logger.info("Démarrage de l'application principale")
    root = tk.Tk()
    app = SecureAppDemo(root)
    logger.info("Interface graphique prête, démarrage de la boucle principale")
    root.mainloop()
    logger.info("Application terminée")


if __name__ == "__main__":
    main()
