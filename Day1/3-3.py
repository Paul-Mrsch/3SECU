import hashlib, time, string, sys, multiprocessing, signal
from functools import partial

def hash_md5(texte):
    """Génère un hash MD5 pour une chaîne donnée"""
    return hashlib.md5(texte.encode()).hexdigest()

def verifier_segment_mdp(hash_cible, caracteres, longueur, debut_segment, taille_segment, afficher_tentatives=False):
    """Vérifie un segment de combinaisons de mots de passe"""
    total = len(caracteres) ** longueur
    fin_segment = min(debut_segment + taille_segment, total)
    
    # Pour limiter le nombre d'affichages et éviter de saturer la console
    echantillon_max = min(taille_segment, 500)  # Augmenter pour plus de vitesse
    afficher_interval = max(1, taille_segment // echantillon_max)
    
    # Mémoriser la longueur de la dernière ligne affichée pour nettoyer correctement
    derniere_longueur = 0
    
    for i in range(debut_segment, fin_segment):
        # Construit la combinaison à partir de l'indice
        combinaison = []
        temp = i
        for _ in range(longueur):
            combinaison.append(caracteres[temp % len(caracteres)])
            temp //= len(caracteres)
        
        mdp = ''.join(reversed(combinaison))
        
        # Afficher les tentatives en temps réel (échantillonnées)
        if afficher_tentatives and (i - debut_segment) % afficher_interval == 0:
            message = f"[*] Essai: {mdp}"
            # S'assurer que la nouvelle ligne efface complètement l'ancienne
            if len(message) < derniere_longueur:
                message += ' ' * (derniere_longueur - len(message))
            print(f"\r{message}", end='', flush=True)
            derniere_longueur = len(message)
            
        if hash_md5(mdp) == hash_cible:
            return mdp
    return None

def cracker_mdp(hash_cible, caracteres=None, temps_max=300, afficher_tentatives=False):
    """Force brutalement un hash MD5 avec multiprocessing"""
    caracteres = caracteres or (string.ascii_lowercase + string.digits)
    debut_temps = time.time()
    
    # Réduire le nombre de coeurs pour éviter les problèmes d'affichage
    if afficher_tentatives:
        nb_coeurs = 1  # Utiliser un seul cœur si on affiche les tentatives
    else:
        nb_coeurs = multiprocessing.cpu_count()
    
    print(f"[+] Hash: {hash_cible}")
    print(f"[+] Caractères ({len(caracteres)}): {caracteres if len(caracteres) < 50 else caracteres[:47]+'...'}")
    print(f"[+] Utilisation de {nb_coeurs} {'cœur' if nb_coeurs == 1 else 'cœurs'} CPU")
    
    longueur = 1
    while True:
        combis = len(caracteres)**longueur
        print(f"\n[*] Test longueur {longueur} ({combis:,} combinaisons)")
        
        # Limite pratique pour éviter de bloquer indéfiniment
        if combis > 100_000_000_000:
            print(f"[!] Arrêt: trop de combinaisons pour longueur {longueur}")
            break
            
        # Taille optimale de segment
        taille_segment = max(1000, min(combis // (nb_coeurs * 20), 1000000))
        segments = list(range(0, combis, taille_segment))
        nb_segments = len(segments)
        
        # Version simplifiée sans pool si on affiche les tentatives
        if afficher_tentatives:
            # Traiter directement les segments dans le thread principal pour faciliter l'affichage
            for debut in segments:
                mdp = verifier_segment_mdp(hash_cible, caracteres, longueur, debut, taille_segment, True)
                if mdp:
                    temps_ecoule = time.time() - debut_temps
                    print(f"\n[+] Mot de passe trouvé: '{mdp}' ({longueur} caractères)")
                    print(f"[+] Temps: {temps_ecoule:.2f} secondes")
                    return mdp
                
                # Vérifier si on a dépassé le temps imparti
                if time.time() - debut_temps > temps_max:
                    print(f"\n[!] Limite de temps ({temps_max}s) dépassée")
                    return None
        else:
            # Version multiprocessing standard sans affichage des tentatives
            with multiprocessing.Pool(processes=nb_coeurs) as pool:
                verification = partial(verifier_segment_mdp, hash_cible, caracteres, longueur, afficher_tentatives=False)
                resultats = []
                
                for idx, debut in enumerate(segments):
                    # Affiche la progression
                    if idx > 0 and idx % max(1, nb_segments // 10) == 0:
                        temps_ecoule = time.time() - debut_temps
                        
                        if temps_ecoule > temps_max:
                            print(f"\n[!] Limite de temps ({temps_max}s) dépassée")
                            pool.terminate()
                            pool.join()
                            return None
                    
                    resultats.append(pool.apply_async(verification, (debut, taille_segment)))
                
                # Vérifie les résultats en temps réel
                for resultat in resultats:
                    try:
                        mdp = resultat.get(timeout=max(1, temps_max // 10))
                        if mdp:
                            temps_ecoule = time.time() - debut_temps
                            print(f"\n[+] Mot de passe trouvé: '{mdp}' ({longueur} caractères)")
                            print(f"[+] Temps: {temps_ecoule:.2f} secondes")
                            pool.terminate()
                            pool.join()
                            return mdp
                    except (multiprocessing.TimeoutError, KeyboardInterrupt):
                        if time.time() - debut_temps > temps_max:
                            print(f"\n[!] Limite de temps ({temps_max}s) dépassée")
                            pool.terminate()
                            pool.join()
                            return None
        
        longueur += 1
    
    print(f"[!] Échec après {time.time() - debut_temps:.2f}s")
    return None


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda sig, frame: print("\n[!] Interruption...") or sys.exit(0))
    
    print("===== Cracker de Hash MD5 =====")
    # Configuration du crackage
    # Jeu de caractères fixe: majuscules, minuscules et chiffres
    caracteres = string.ascii_lowercase + string.ascii_uppercase + string.digits
    print(f"[+] Jeu de caractères: lettres majuscules, minuscules et chiffres ({len(caracteres)} caractères)")
    
    # Demande du mot de passe à l'utilisateur
    mot_de_passe = input("Entrez le mot de passe à forcer: ")
    
    # Génération du hash MD5 et affichage
    hash_cible = hash_md5(mot_de_passe)
    print(f"[+] Mot de passe entré: '{mot_de_passe}'\n[+] Hash MD5 correspondant: {hash_cible}")
    
    # Configuration du temps et des options
    temps_max = 300
    
    # Option d'affichage des tentatives
    afficher_tentatives = input("Afficher les tentatives en temps réel? (o/N): ").lower().startswith('o')
    
    print("\n[+] Démarrage du crackage...")
    trouve = cracker_mdp(hash_cible, caracteres, temps_max, afficher_tentatives)
    
    # Affichage du résultat
    print(f"\n[{'+'if trouve else '!'}] {'Succès! Le mot de passe a été retrouvé avec succès.' if trouve else 'Échec: Le mot de passe n\'a pas été retrouvé dans le temps imparti.'}")
    print("\n[+] Terminé.")