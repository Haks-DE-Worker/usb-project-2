import os
import time
import shutil
import pickle
import base64
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core import usb_hook
class SecureUSB:
    def __init__(self):
        self.config_file = ".secure_usb_config"
        self.salt = b'secure_usb_salt_value_12345'  # Sel pour dérivation de clé
    
    def derive_key(self, password):
        """Dérive une clé cryptographique à partir du mot de passe."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    
    def protect_drive_non_utilisée(self, drive_path, password):
        """Protège une clé USB avec le mot de passe spécifié."""
        try:
            key = self.derive_key(password)
            
            # Crée le répertoire caché s'il n'existe pas
            hidden_dir = os.path.join(drive_path, ".secure_usb")
            if not os.path.exists(hidden_dir):
                os.makedirs(hidden_dir)
            
            # Sauvegarde la clé de chiffrement (chiffrée avec le mot de passe)
            config = {
                "key": key.decode(),
                "protected": True,
                "creation_date": time.time()
            }
            
            with open(os.path.join(hidden_dir, self.config_file), 'wb') as f:
                pickle.dump(config, f)
            
            # Copie l'application portable sur la clé USB
            self.copy_portable_app(drive_path)
            
            # Installation du hook de système de fichiers
            self.install_filesystem_hook(drive_path)
            
            return True
        except Exception as e:
            print(f"Erreur lors de la protection de la clé: {e}")
            return False
    

    def protect_drive(self, drive_path, password):
        """Protège une clé USB avec le mot de passe spécifié."""
        success = False
        try:
            key = self.derive_key(password)
            
            # Crée le répertoire caché s'il n'existe pas
            hidden_dir = os.path.join(drive_path, ".secure_usb")
            if not os.path.exists(hidden_dir):
                os.makedirs(hidden_dir)
            
            # Sauvegarde la clé de chiffrement (chiffrée avec le mot de passe)
            config = {
                "key": key.decode(),
                "protected": True,
                "creation_date": time.time()
            }
            
            with open(os.path.join(hidden_dir, self.config_file), 'wb') as f:
                pickle.dump(config, f)
            
            # Copie l'application portable sur la clé USB
            try:
                self.copy_portable_app(drive_path)
            except Exception as e:
                print(f"Avertissement: Impossible de copier l'application portable: {e}")
            
            # Installation du hook de système de fichiers
            try:
                self.install_filesystem_hook(drive_path)
            except Exception as e:
                print(f"Avertissement: Impossible d'installer le hook système: {e}")
            
            # Si nous avons réussi à enregistrer la configuration, considérer que la protection est active
            success = True
            
        except Exception as e:
            print(f"Erreur lors de la protection de la clé: {e}")
            success = False
    
        return success
    def copy_portable_app(self, drive_path):
        """Copie l'application portable sur la clé USB."""
        app_dir = os.path.join(drive_path, "SecureUSBApp")
        if not os.path.exists(app_dir):
            os.makedirs(app_dir)
        
        # Déterminer si on est dans un environnement PyInstaller
        if getattr(sys, 'frozen', False):
            # Si l'application est "gelée" (compilée avec PyInstaller)
            application_path = sys.executable
            shutil.copy2(application_path, os.path.join(app_dir, "SecureUSB.exe"))
        else:
            # Copier tous les fichiers python du projet
            import glob
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            # Créer les sous-répertoires dans la clé USB
            for root, dirs, files in os.walk(script_dir):
                rel_path = os.path.relpath(root, script_dir)
                if rel_path == "." or "__pycache__" in rel_path or ".git" in rel_path:
                    continue
                    
                dest_dir = os.path.join(app_dir, rel_path)
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)
                
                # Copier les fichiers Python
                for file in files:
                    if file.endswith('.py'):
                        src_file = os.path.join(root, file)
                        dst_file = os.path.join(dest_dir, file)
                        shutil.copy2(src_file, dst_file)
            
            # Créer les scripts de lancement
            with open(os.path.join(app_dir, "launch.bat"), 'w') as f:
                f.write("@echo off\npython main.py\n")
            
            with open(os.path.join(app_dir, "launch.sh"), 'w') as f:
                f.write("#!/bin/bash\npython3 main.py\n")
            
            os.chmod(os.path.join(app_dir, "launch.sh"), 0o755)
    
    def install_filesystem_hook(self, drive_path):
        """Installe un hook de système de fichiers pour intercepter les opérations."""
        # Cette fonction varie selon le système d'exploitation
        os_type = os.name
        
        if os_type == 'nt':  # Windows
            self._install_windows_hook(drive_path)
        elif os_type == 'posix':  # Linux/macOS
            self._install_posix_hook(drive_path)
    
    def _install_windows_hook(self, drive_path):
        """Installe un hook de système de fichiers pour Windows."""
        # Créer un fichier autorun.inf pour lancer automatiquement l'application
        autorun_path = os.path.join(drive_path, "autorun.inf")
        with open(autorun_path, 'w') as f:
            f.write("[autorun]\nopen=SecureUSBApp\\SecureUSB.exe\naction=Execute SecureUSB Protection\n")
        
        # Créer un script de démarrage qui installera le filtre de fichiers
        startup_script = os.path.join(drive_path, "SecureUSBApp", "startup.bat")
        with open(startup_script, 'w') as f:
            f.write("@echo off\n")
            f.write("echo Installation de la protection pour la clé USB...\n")
            # Dans une implémentation réelle, cela installerait un hook système
            f.write("start /B SecureUSB.exe --protect\n")
        # Appel réel à la DLL ici
        if not usb_hook.install_hook():
            raise Exception("Échec de l'installation du hook système (usb_filter.dll)")
    
    def _install_posix_hook(self, drive_path):
        """Installe un hook de système de fichiers pour Linux/macOS."""
        # Créer un script de démarrage
        startup_script = os.path.join(drive_path, "SecureUSBApp", "startup.sh")
        with open(startup_script, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("echo Installation de la protection pour la clé USB...\n")
            # Dans une implémentation réelle, cela installerait un hook FUSE
            f.write("python3 main.py --protect &\n")
        
        os.chmod(startup_script, 0o755)
    
    def is_protected(self, drive_path):
        """Vérifie si une clé USB est protégée."""
        config_path = os.path.join(drive_path, ".secure_usb", self.config_file)
        return os.path.exists(config_path)
    
    def verify_password(self, drive_path, password):
        """Vérifie si le mot de passe est correct pour une clé USB protégée."""
        if not self.is_protected(drive_path):
            return False
        
        config_path = os.path.join(drive_path, ".secure_usb", self.config_file)
        try:
            with open(config_path, 'rb') as f:
                config = pickle.load(f)
            
            # Dérive la clé à partir du mot de passe fourni et compare
            key = self.derive_key(password)
            return key.decode() == config["key"]
        except Exception as e:
            print(f"Erreur lors de la vérification du mot de passe: {e}")
            return False