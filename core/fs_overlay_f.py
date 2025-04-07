import os
import platform
import shutil
import ctypes
from functools import wraps
import time
import threading

class FileSystemOverlay:
    """
    Cette classe implémente la logique pour intercepter et contrôler
    les opérations sur les fichiers de la clé USB.
    """
    def __init__(self, secure_usb):
        self.secure_usb = secure_usb
        self.protected_drives = set()
        self.temporary_access = {}  # {drive_path: expiration_time}
        self.access_lock = threading.Lock()
        
        # Hook les fonctions système de fichiers
        self.patch_filesystem_functions()
    
    def patch_filesystem_functions(self):
        """Patch les fonctions de manipulation de fichiers pour intercepter les opérations."""
        # Sauvegarde des fonctions originales
        self._original_copy = shutil.copy2
        self._original_move = shutil.move
        self._original_copyfile = shutil.copyfile
        self._original_rmtree = shutil.rmtree
        self._original_remove = os.remove
        
        # Remplacement des fonctions
        shutil.copy2 = self._secure_copy2
        shutil.move = self._secure_move
        shutil.copyfile = self._secure_copyfile
        shutil.rmtree = self._secure_rmtree
        os.remove = self._secure_remove
        
        # Sur Windows, on peut aussi intercepter les opérations au niveau du système
        if platform.system() == "Windows":
            self._hook_windows_file_operations()
    
    def restore_filesystem_functions(self):
        """Restaure les fonctions originales du système de fichiers."""
        shutil.copy2 = self._original_copy
        shutil.move = self._original_move
        shutil.copyfile = self._original_copyfile
        shutil.rmtree = self._original_rmtree
        os.remove = self._original_remove
    
    def _hook_windows_file_operations(self):
        """Installe des hooks système pour Windows."""
        try:
            import win32file
            import win32api
            import win32con
            
            # Ceci est une implémentation simplifiée. Dans une version réelle,
            # on utiliserait les APIs Windows pour installer un filtre de fichiers.
            # Exemple: utilisation de CBFS (Callback File System) ou un pilote minifilter
            pass
        except ImportError:
            print("Module win32api non disponible. Interception limitée sur Windows.")
    
    def _secure_copy2(self, src, dst, *args, **kwargs):
        """Version sécurisée de shutil.copy2"""
        if self._is_operation_restricted(src, "copy"):
            if not self._check_temporary_access(src) and not self._request_authentication(src):
                raise PermissionError(f"Copie non autorisée depuis {src}")
        return self._original_copy(src, dst, *args, **kwargs)
    
    def _secure_move(self, src, dst, *args, **kwargs):
        """Version sécurisée de shutil.move"""
        if self._is_operation_restricted(src, "move"):
            if not self._check_temporary_access(src) and not self._request_authentication(src):
                raise PermissionError(f"Déplacement non autorisé depuis {src}")
        return self._original_move(src, dst, *args, **kwargs)
    
    def _secure_copyfile(self, src, dst, *args, **kwargs):
        """Version sécurisée de shutil.copyfile"""
        if self._is_operation_restricted(src, "copy"):
            if not self._check_temporary_access(src) and not self._request_authentication(src):
                raise PermissionError(f"Copie de fichier non autorisée depuis {src}")
        return self._original_copyfile(src, dst, *args, **kwargs)
    
    def _secure_rmtree(self, path, *args, **kwargs):
        """Version sécurisée de shutil.rmtree"""
        if self._is_operation_restricted(path, "delete"):
            if not self._check_temporary_access(path) and not self._request_authentication(path):
                raise PermissionError(f"Suppression de répertoire non autorisée pour {path}")
        return self._original_rmtree(path, *args, **kwargs)
    
    def _secure_remove(self, path, *args, **kwargs):
        """Version sécurisée de os.remove"""
        if self._is_operation_restricted(path, "delete"):
            if not self._check_temporary_access(path) and not self._request_authentication(path):
                raise PermissionError(f"Suppression de fichier non autorisée pour {path}")
        return self._original_remove(path, *args, **kwargs)
    
    def _is_operation_restricted(self, path, operation_type):
        """
        Vérifie si l'opération est restreinte pour le chemin donné.
        operation_type peut être 'copy', 'move', 'delete'
        """
        for drive in self.protected_drives:
            if path.startswith(drive):
                # Opérations restreintes sur une clé protégée
                return operation_type in ['copy', 'move', 'delete']
        return False
    
    def _check_temporary_access(self, path):
        """Vérifie si un accès temporaire a été accordé pour ce chemin."""
        with self.access_lock:
            current_time = time.time()
            
            # Nettoyer les accès temporaires expirés
            expired_drives = []
            for drive, expiration_time in self.temporary_access.items():
                if current_time > expiration_time:
                    expired_drives.append(drive)
            
            for drive in expired_drives:
                del self.temporary_access[drive]
            
            # Vérifier si le chemin est dans une clé USB avec accès temporaire
            for drive, expiration_time in self.temporary_access.items():
                if path.startswith(drive) and current_time <= expiration_time:
                    return True
                    
            return False
    
    def enable_temporary_access(self, drive_path, password, duration=300):
        """
        Active un accès temporaire à une clé USB protégée.
        
        Args:
            drive_path (str): Chemin de la clé USB
            password (str): Mot de passe pour la clé USB
            duration (int): Durée de l'accès temporaire en secondes (par défaut: 5 minutes)
        
        Returns:
            bool: True si l'accès temporaire a été activé, False sinon
        """
        if drive_path in self.protected_drives and self.secure_usb.verify_password(drive_path, password):
            with self.access_lock:
                self.temporary_access[drive_path] = time.time() + duration
            return True
        return False
    
    def disable_temporary_access(self, drive_path):
        """Désactive l'accès temporaire à une clé USB."""
        with self.access_lock:
            if drive_path in self.temporary_access:
                del self.temporary_access[drive_path]
    
    def _request_authentication(self, path):
        """
        Demande l'authentification pour une opération restreinte.
        Dans l'implémentation réelle, cela afficherait une boîte de dialogue.
        """
        # Trouver la clé USB correspondante
        drive = None
        for d in self.protected_drives:
            if path.startswith(d):
                drive = d
                break
        
        if drive is None:
            return False
        
        # Dans une implémentation réelle, cela afficherait une boîte de dialogue
        # Pour cette version de démonstration, on va simuler une demande d'authentification
        try:
            import tkinter as tk
            from tkinter import simpledialog
            
            root = tk.Tk()
            root.withdraw()  # Cacher la fenêtre principale
            
            password = simpledialog.askstring(
                "Authentification requise", 
                f"Entrez le mot de passe pour accéder à {os.path.basename(drive)}:", 
                show='*'
            )
            
            root.destroy()
            
            if password is None:  # L'utilisateur a annulé
                return False
                
            return self.secure_usb.verify_password(drive, password)
            
        except Exception as e:
            print(f"Erreur lors de la demande d'authentification: {e}")
            return False
    
    def add_protected_drive(self, drive_path):
        """Ajoute une clé USB à la liste des périphériques protégés."""
        self.protected_drives.add(drive_path)
    
    def remove_protected_drive(self, drive_path):
        """Retire une clé USB de la liste des périphériques protégés."""
        if drive_path in self.protected_drives:
            self.protected_drives.remove(drive_path)
        
        # Également supprimer tout accès temporaire
        with self.access_lock:
            if drive_path in self.temporary_access:
                del self.temporary_access[drive_path]