import os
import platform
import shutil
import ctypes
import threading
import time
import subprocess
import sys

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
        self.hook_installed = False
        
        # Hook les fonctions système de fichiers
        self.patch_filesystem_functions()
        
        # Sur Windows, installer également le hook système
        if platform.system() == "Windows":
            self._hook_windows_file_operations()
    
    def patch_filesystem_functions(self):
        """Patch les fonctions de manipulation de fichiers pour intercepter les opérations."""
        # Sauvegarde des fonctions originales
        self._original_copy = shutil.copy2
        self._original_move = shutil.move
        self._original_copyfile = shutil.copyfile
        self._original_rmtree = shutil.rmtree
        self._original_remove = os.remove
        self._original_open = open
        
        # Remplacement des fonctions
        shutil.copy2 = self._secure_copy2
        shutil.move = self._secure_move
        shutil.copyfile = self._secure_copyfile
        shutil.rmtree = self._secure_rmtree
        os.remove = self._secure_remove
        builtins.open = self._secure_open  # Ajouter cette ligne pour intercepter l'ouverture de fichiers
    
    def restore_filesystem_functions(self):
        """Restaure les fonctions originales du système de fichiers."""
        shutil.copy2 = self._original_copy
        shutil.move = self._original_move
        shutil.copyfile = self._original_copyfile
        shutil.rmtree = self._original_rmtree
        os.remove = self._original_remove
        builtins.open = self._original_open  # Restaurer la fonction open
        
        # Désinstaller le hook système si présent
        self._unhook_windows_file_operations()
    
    def _hook_windows_file_operations_nt_used(self):
        """Installe des hooks système pour Windows."""
        try:
            # Vérifier si on est dans un environnement qui peut installer un hook système
            if self.hook_installed:
                return
                
            if platform.system() != "Windows":
                return
                
            # Installer le pilote de filtre ou le hook DLL
            # Cette partie nécessite un composant natif (DLL/SYS)
            hook_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks", "usb_filter.dll")
            
            if os.path.exists(hook_path):
                try:
                    # Charger la DLL avec ctypes
                    filter_dll = ctypes.CDLL(hook_path)
                    
                    # Enregistrer chaque lecteur protégé
                    for drive in self.protected_drives:
                        drive_letter = drive[0] if drive.endswith(':\\') else drive
                        result = filter_dll.InstallFilter(ctypes.c_wchar_p(drive_letter))
                        if result == 0:
                            print(f"Filtre installé avec succès pour {drive}")
                        else:
                            print(f"Échec de l'installation du filtre pour {drive}: code {result}")
                    
                    self.hook_installed = True
                    self.filter_dll = filter_dll
                    
                except Exception as e:
                    print(f"Erreur lors du chargement du filtre: {e}")
                    self._install_alternative_protection()
            else:
                print(f"Le fichier de filtre USB n'existe pas: {hook_path}")
                self._install_alternative_protection()
                
        except Exception as e:
            print(f"Erreur lors de l'installation du hook Windows: {e}")
            self._install_alternative_protection()
    
    def _hook_windows_file_operations(self):
        """Installe des hooks système pour Windows."""
        try:
            # Vérifier si on est dans un environnement qui peut installer un hook système
            if self.hook_installed:
                return
                    
            if platform.system() != "Windows":
                return
                    
            # Installer le pilote de filtre ou le hook DLL
            # On cherche d'abord dans le répertoire de l'application
            script_dir = os.path.dirname(os.path.abspath(__file__))
            hook_path = os.path.join(script_dir, "hooks", "usb_filter.dll")
            
            # Si nous ne trouvons pas la DLL dans le répertoire de l'application,
            # chercher dans le répertoire parent (pour le développement)
            if not os.path.exists(hook_path):
                hook_path = os.path.join(os.path.dirname(script_dir), "hooks", "usb_filter.dll")
                
            # Si nous ne trouvons toujours pas, chercher dans le répertoire temporaire
            if not os.path.exists(hook_path):
                hook_path = os.path.join(os.environ.get('TEMP', ''), "usb_filter.dll")
                
            # Si nous ne trouvons toujours pas, extraire la DLL depuis les ressources
            if not os.path.exists(hook_path):
                # Essayer de créer le répertoire hooks s'il n'existe pas
                os.makedirs(os.path.join(script_dir, "hooks"), exist_ok=True)
                
                # Tenter d'extraire la DLL depuis les ressources (si elle est embarquée)
                try:
                    import pkg_resources
                    dll_data = pkg_resources.resource_string(__name__, "resources/usb_filter.dll")
                    with open(hook_path, 'wb') as f:
                        f.write(dll_data)
                except Exception as e:
                    print(f"Impossible d'extraire la DLL depuis les ressources: {e}")
                    
                    # Créer un avertissement dans le journal
                    import logging
                    logging.warning(f"Le filtre USB n'a pas pu être chargé: {e}")
                    
                    # Passer à la méthode alternative
                    self._install_alternative_protection()
                    return
                    
            # Charger la DLL avec ctypes
            if os.path.exists(hook_path):
                try:
                    print(f"Chargement du filtre USB depuis: {hook_path}")
                    filter_dll = ctypes.CDLL(hook_path)
                    
                    # Vérifier que les fonctions nécessaires sont disponibles
                    required_functions = ["InstallFilter", "UninstallFilter", "AllowAccess", "DenyAccess", "GetProtectionStatus"]
                    all_functions_available = True
                    
                    for func_name in required_functions:
                        if not hasattr(filter_dll, func_name):
                            print(f"Fonction manquante dans la DLL: {func_name}")
                            all_functions_available = False
                            break
                    
                    if not all_functions_available:
                        print("La DLL ne contient pas toutes les fonctions requises.")
                        self._install_alternative_protection()
                        return
                    
                    # Enregistrer chaque lecteur protégé
                    for drive in self.protected_drives:
                        drive_letter = drive[0] if drive.endswith(':\\') else drive
                        result = filter_dll.InstallFilter(ctypes.c_wchar_p(drive_letter))
                        if result == 0:
                            print(f"Filtre installé avec succès pour {drive}")
                        else:
                            print(f"Échec de l'installation du filtre pour {drive}: code {result}")
                    
                    self.hook_installed = True
                    self.filter_dll = filter_dll
                    
                    # Installer un hook de détection de tentatives d'opérations interdites
                    def _check_file_operations():
                        """Thread qui vérifie périodiquement les opérations de fichier."""
                        import time
                        import win32clipboard
                        
                        last_clipboard_content = None
                        
                        while self.hook_installed:
                            try:
                                # Vérifier si le presse-papiers contient des références à des lecteurs protégés
                                if win32clipboard.OpenClipboard(None):
                                    try:
                                        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_HDROP):
                                            # Des fichiers sont dans le presse-papiers
                                            file_paths = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)
                                            
                                            # Vérifier si ces fichiers sont sur un lecteur protégé
                                            for file_path in file_paths:
                                                for drive in self.protected_drives:
                                                    if file_path.startswith(drive):
                                                        # Fichier protégé détecté dans le presse-papiers
                                                        # Vérifier si l'accès temporaire est autorisé
                                                        if not self._check_temporary_access(drive):
                                                            print(f"Tentative de copie détectée via le presse-papiers: {file_path}")
                                                            # Effacer le presse-papiers
                                                            win32clipboard.EmptyClipboard()
                                                            break
                                    finally:
                                        win32clipboard.CloseClipboard()
                                        
                            except Exception as e:
                                pass
                                
                            time.sleep(0.5)  # Vérifier toutes les 0.5 secondes
                    
                    # Démarrer le thread de surveillance
                    self.file_operations_thread = threading.Thread(target=_check_file_operations)
                    self.file_operations_thread.daemon = True
                    self.file_operations_thread.start()
                    
                except Exception as e:
                    print(f"Erreur lors du chargement du filtre: {e}")
                    self._install_alternative_protection()
            else:
                print(f"Le fichier de filtre USB n'existe pas: {hook_path}")
                self._install_alternative_protection()
                    
        except Exception as e:
            print(f"Erreur lors de l'installation du hook Windows: {e}")
            self._install_alternative_protection()


    def _unhook_windows_file_operations(self):
        """Désinstalle les hooks système pour Windows."""
        if not self.hook_installed:
            return
            
        try:
            # Désinstaller le filtre
            if hasattr(self, 'filter_dll'):
                for drive in self.protected_drives:
                    drive_letter = drive[0] if drive.endswith(':\\') else drive
                    self.filter_dll.UninstallFilter(ctypes.c_wchar_p(drive_letter))
            
            self.hook_installed = False
            
        except Exception as e:
            print(f"Erreur lors de la désinstallation du hook Windows: {e}")
    
    def _install_alternative_protection(self):
        """Installe une protection alternative (moins efficace mais ne nécessite pas de pilote)."""
        try:
            # Technique 1: Attributs de fichier en lecture seule et cachés
            self._set_file_attributes_for_protected_drives()
            
            # Technique 2: Modification des ACLs (nécessite des droits d'admin)
            self._set_acls_for_protected_drives()
            
            # Technique 3: Moniteur de processus pour détecter les tentatives de copie
            self._start_process_monitor()
            
        except Exception as e:
            print(f"Erreur lors de l'installation de la protection alternative: {e}")
    
    def _set_file_attributes_for_protected_drives(self):
        """Définit les attributs de fichier en lecture seule et cachés pour les fichiers des lecteurs protégés."""
        import stat
        
        for drive in self.protected_drives:
            try:
                # Parcourir récursivement tous les fichiers de la clé USB
                for root, dirs, files in os.walk(drive):
                    # Ne pas traiter les dossiers système/cachés
                    if ".secure_usb" in root or "System Volume Information" in root:
                        continue
                        
                    # Pour chaque fichier, définir les attributs
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            # Définir en lecture seule
                            current_mode = os.stat(file_path).st_mode
                            os.chmod(file_path, current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
                            
                            # Sur Windows, définir également l'attribut caché
                            if platform.system() == "Windows":
                                ctypes.windll.kernel32.SetFileAttributesW(
                                    file_path, 
                                    0x01  # FILE_ATTRIBUTE_READONLY
                                )
                        except Exception as e:
                            print(f"Impossible de définir les attributs pour {file_path}: {e}")
            except Exception as e:
                print(f"Erreur lors du traitement du lecteur {drive}: {e}")
    
    def _set_acls_for_protected_drives(self):
        """Définit des ACLs restrictives pour les fichiers des lecteurs protégés."""
        if platform.system() != "Windows":
            return
            
        try:
            import win32security
            import ntsecuritycon as con
            
            for drive in self.protected_drives:
                try:
                    # Définir l'ACL pour le lecteur entier à Read-Only pour tous les utilisateurs sauf l'administrateur
                    sd = win32security.GetFileSecurity(
                        drive, 
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    dacl = sd.GetSecurityDescriptorDacl()
                    
                    # Réinitialiser la DACL
                    dacl = win32security.ACL()
                    
                    # Ajouter l'utilisateur actuel avec droits de lecture uniquement
                    user, domain, type = win32security.LookupAccountName("", os.environ["USERNAME"])
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE,
                        user
                    )
                    
                    # Mettre à jour la sécurité
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        drive, 
                        win32security.DACL_SECURITY_INFORMATION, 
                        sd
                    )
                    
                except Exception as e:
                    print(f"Erreur lors de la définition des ACLs pour {drive}: {e}")
        except ImportError:
            print("Module win32security non disponible, impossible de définir les ACLs")
    
    def _start_process_monitor(self):
        """Démarre un moniteur de processus pour détecter les tentatives de copie."""
        # Créer un thread pour surveiller les processus qui accèdent aux lecteurs protégés
        self.process_monitor_thread = threading.Thread(target=self._process_monitor_loop)
        self.process_monitor_thread.daemon = True
        self.process_monitor_thread.start()
    
    def _process_monitor_loop(self):
        """Boucle de surveillance des processus."""
        import psutil
        
        while True:
            try:
                # Vérifier les processus qui accèdent aux lecteurs protégés
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'open_files']):
                    try:
                        # Vérifier si le processus accède à un lecteur protégé
                        if proc.info['open_files']:
                            for file in proc.info['open_files']:
                                for drive in self.protected_drives:
                                    if file.path.startswith(drive):
                                        # Vérifier si c'est une opération de copie
                                        if self._is_copy_process(proc.info['name'], proc.info['cmdline']):
                                            # Demander une authentification si nécessaire
                                            if not self._check_temporary_access(drive):
                                                # Tuer le processus pour empêcher la copie
                                                print(f"Tentative de copie détectée: {proc.info['name']} (PID: {proc.info['pid']})")
                                                proc.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception as e:
                print(f"Erreur dans la surveillance des processus: {e}")
                
            time.sleep(1)  # Vérifier toutes les secondes
    
    def _is_copy_process(self, process_name, cmdline):
        """Détermine si un processus est susceptible d'effectuer une opération de copie."""
        copy_processes = [
            "explorer.exe", "cmd.exe", "powershell.exe", "xcopy.exe", "robocopy.exe",
            "totalcmd.exe", "winrar.exe", "7z.exe", "winzip.exe"
        ]
        
        if any(proc.lower() in process_name.lower() for proc in copy_processes):
            # Vérifier les arguments de ligne de commande pour des indications de copie
            if cmdline:
                copy_commands = ["copy", "xcopy", "move", "robocopy", "cp", "mv"]
                return any(cmd in ' '.join(cmdline).lower() for cmd in copy_commands)
        
        return False
    
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
    
    def _secure_open(self, file, mode='r', *args, **kwargs):
        """Version sécurisée de la fonction open()"""
        # Autoriser la lecture mais bloquer l'écriture sur les lecteurs protégés
        if 'w' in mode or 'a' in mode or '+' in mode:
            # C'est une opération d'écriture
            if self._is_operation_restricted(file, "write"):
                # Autoriser l'écriture (ajout de fichiers autorisé)
                pass
        elif 'r' in mode:
            # C'est une opération de lecture, toujours autorisée
            pass
        
        return self._original_open(file, mode, *args, **kwargs)
    
    def _is_operation_restricted_not_used(self, path, operation_type):
        """
        Vérifie si l'opération est restreinte pour le chemin donné.
        operation_type peut être 'copy', 'move', 'delete', 'write'
        """
        # Si le chemin est un str, vérifier s'il commence par un des lecteurs protégés
        if isinstance(path, str):
            for drive in self.protected_drives:
                if path.startswith(drive):
                    # Autorise les opérations d'écriture et de lecture, mais pas de copie/déplacement/suppression
                    if operation_type in ['copy', 'move', 'delete']:
                        return True
        return False
    
    def _is_operation_restricted(self, path, operation_type):
        """
        Vérifie si l'opération est restreinte pour le chemin donné.
        operation_type peut être 'copy', 'move', 'delete', 'write', 'read'
        
        Returns:
            tuple: (is_restricted, drive_path)
                - is_restricted: booléen indiquant si l'opération est restreinte
                - drive_path: chemin du lecteur concerné ou None
        """
        # Si le chemin est un str, vérifier s'il commence par un des lecteurs protégés
        if isinstance(path, str):
            # Normaliser le chemin pour faciliter la comparaison
            normalized_path = os.path.normpath(path)
            
            for drive in self.protected_drives:
                normalized_drive = os.path.normpath(drive)
                if normalized_path.startswith(normalized_drive):
                    # Le chemin est sur un lecteur protégé
                    
                    # Vérifier si le chemin est dans un répertoire système/caché
                    system_paths = [
                        os.path.join(normalized_drive, ".secure_usb"),
                        os.path.join(normalized_drive, "System Volume Information"),
                        os.path.join(normalized_drive, "SecureUSBApp")
                    ]
                    
                    if any(normalized_path.startswith(sys_path) for sys_path in system_paths):
                        # Autoriser toutes les opérations sur les répertoires système
                        return (False, None)
                    
                    # Définir les restrictions selon le type d'opération
                    if operation_type in ['copy', 'move', 'delete']:
                        # Ces opérations sont toujours restreintes
                        return (True, drive)
                    elif operation_type == 'write':
                        # Écriture autorisée (ajout de fichiers autorisé)
                        return (False, None)
                    elif operation_type == 'read':
                        # Lecture toujours autorisée
                        return (False, None)
        
        # Par défaut, l'opération n'est pas restreinte
        return (False, None)


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
                if isinstance(path, str) and path.startswith(drive) and current_time <= expiration_time:
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
                
                # Si un hook système est en place, mettre à jour ses autorisations
                if self.hook_installed and hasattr(self, 'filter_dll'):
                    try:
                        drive_letter = drive_path[0] if drive_path.endswith(':\\') else drive_path
                        self.filter_dll.AllowAccess(ctypes.c_wchar_p(drive_letter), ctypes.c_int(int(duration)))
                    except Exception as e:
                        print(f"Erreur lors de la mise à jour des autorisations du filtre: {e}")
                
                # Restaurer les attributs et les ACLs temporairement
                self._restore_file_attributes(drive_path)
                
            return True
        return False
    
    def _restore_file_attributes(self, drive_path):
        """Restaure temporairement les attributs de fichier pour permettre la copie."""
        import stat
        
        try:
            # Parcourir récursivement tous les fichiers de la clé USB
            for root, dirs, files in os.walk(drive_path):
                # Ne pas traiter les dossiers système/cachés
                if ".secure_usb" in root or "System Volume Information" in root:
                    continue
                    
                # Pour chaque fichier, restaurer les attributs normaux
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Rendre le fichier inscriptible
                        current_mode = os.stat(file_path).st_mode
                        os.chmod(file_path, current_mode | stat.S_IWUSR)
                        
                        # Sur Windows, retirer l'attribut en lecture seule
                        if platform.system() == "Windows":
                            ctypes.windll.kernel32.SetFileAttributesW(
                                file_path, 
                                0x80  # FILE_ATTRIBUTE_NORMAL
                            )
                    except Exception as e:
                        print(f"Impossible de restaurer les attributs pour {file_path}: {e}")
        except Exception as e:
            print(f"Erreur lors de la restauration des attributs pour {drive_path}: {e}")
    
    def disable_temporary_access(self, drive_path):
        """Désactive l'accès temporaire à une clé USB."""
        with self.access_lock:
            if drive_path in self.temporary_access:
                del self.temporary_access[drive_path]
                
                # Réinitialiser les attributs de protection
                self._set_file_attributes_for_protected_drives()
                
                # Si un hook système est en place, réactiver la protection
                if self.hook_installed and hasattr(self, 'filter_dll'):
                    try:
                        drive_letter = drive_path[0] if drive_path.endswith(':\\') else drive_path
                        self.filter_dll.DenyAccess(ctypes.c_wchar_p(drive_letter))
                    except Exception as e:
                        print(f"Erreur lors de la réactivation de la protection du filtre: {e}")
    
    def _request_authentication_bot_used(self, path):
        """
        Demande l'authentification pour une opération restreinte.
        """
        # Trouver la clé USB correspondante
        drive = None
        for d in self.protected_drives:
            if path.startswith(d):
                drive = d
                break
        
        if drive is None:
            return False
        
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
                
            # Vérifier le mot de passe
            if self.secure_usb.verify_password(drive, password):
                # Activer l'accès temporaire
                self.enable_temporary_access(drive, password, 60)  # Accès temporaire de 1 minute
                return True
            else:
                return False
            
        except Exception as e:
            print(f"Erreur lors de la demande d'authentification: {e}")
            return False
    
    def _request_authentication(self, path):
        """
        Demande l'authentification pour une opération restreinte.
        Retourne True si l'authentification réussit, False sinon.
        """
        # Trouver la clé USB correspondante
        drive = None
        for d in self.protected_drives:
            if isinstance(path, str) and path.startswith(d):
                drive = d
                break
        
        if drive is None:
            return False
        
        try:
            # Vérifier si l'accès temporaire est déjà accordé
            if self._check_temporary_access(drive):
                return True
                
            import tkinter as tk
            from tkinter import simpledialog, messagebox
            
            # Créer une fenêtre Tkinter pour l'authentification
            root = tk.Tk()
            root.withdraw()  # Cacher la fenêtre principale
            root.title("Authentification SecureUSB")
            
            # Centrer la boîte de dialogue
            root.eval('tk::PlaceWindow . center')
            
            # Utiliser simpledialog pour demander le mot de passe
            password = simpledialog.askstring(
                "Authentification SecureUSB", 
                f"Action protégée détectée sur {os.path.basename(drive)}.\n" +
                "Veuillez entrer le mot de passe pour autoriser cette opération:",
                show='*'
            )
            
            # Si l'utilisateur annule (clique sur Annuler ou ferme la fenêtre)
            if password is None:
                messagebox.showinfo("Opération annulée", "L'opération a été annulée.")
                root.destroy()
                return False
                
            # Vérifier le mot de passe avec la méthode verify_password de SecureUSB
            if self.secure_usb.verify_password(drive, password):
                # Durée d'accès temporaire en secondes (5 minutes par défaut)
                duration = 300
                
                # Activer l'accès temporaire
                self.enable_temporary_access(drive, password, duration)
                
                messagebox.showinfo(
                    "Accès accordé", 
                    f"Accès temporaire accordé pour {duration//60} minutes."
                )
                
                root.destroy()
                return True
            else:
                # Mot de passe incorrect
                messagebox.showerror(
                    "Authentification échouée", 
                    "Mot de passe incorrect. Opération refusée."
                )
                
                # Option pour réessayer
                retry = messagebox.askretrycancel(
                    "Réessayer ?", 
                    "Voulez-vous réessayer avec un autre mot de passe ?"
                )
                
                root.destroy()
                
                # Si l'utilisateur veut réessayer, rappeler cette méthode de façon récursive
                if retry:
                    return self._request_authentication(path)
                
                return False
                
        except ImportError as e:
            # Si tkinter n'est pas disponible, utiliser une interface en ligne de commande
            print(f"Authentification requise pour accéder à {drive}")
            print("Entrez le mot de passe (ou appuyez sur Entrée pour annuler):")
            password = input("> ")
            
            if not password:
                print("Opération annulée.")
                return False
                
            if self.secure_usb.verify_password(drive, password):
                self.enable_temporary_access(drive, password, 300)
                print("Accès temporaire accordé pour 5 minutes.")
                return True
            else:
                print("Mot de passe incorrect. Opération refusée.")
                return False
                
        except Exception as e:
            print(f"Erreur lors de la demande d'authentification: {e}")
            return False
        

    def add_protected_drive(self, drive_path):
        """Ajoute une clé USB à la liste des périphériques protégés."""
        self.protected_drives.add(drive_path)
        
        # Mettre à jour la protection au niveau système si elle est active
        if self.hook_installed and hasattr(self, 'filter_dll'):
            try:
                drive_letter = drive_path[0] if drive_path.endswith(':\\') else drive_path
                self.filter_dll.InstallFilter(ctypes.c_wchar_p(drive_letter))
            except Exception as e:
                print(f"Erreur lors de l'ajout de la protection système pour {drive_path}: {e}")
        
        # Appliquer des méthodes de protection alternatives
        self._set_file_attributes_for_protected_drives()
        self._set_acls_for_protected_drives()
    
    def remove_protected_drive(self, drive_path):
        """Retire une clé USB de la liste des périphériques protégés."""
        if drive_path in self.protected_drives:
            self.protected_drives.remove(drive_path)
            
            # Mettre à jour la protection au niveau système si elle est active
            if self.hook_installed and hasattr(self, 'filter_dll'):
                try:
                    drive_letter = drive_path[0] if drive_path.endswith(':\\') else drive_path
                    self.filter_dll.UninstallFilter(ctypes.c_wchar_p(drive_letter))
                except Exception as e:
                    print(f"Erreur lors du retrait de la protection système pour {drive_path}: {e}")
        
        # Également supprimer tout accès temporaire
        with self.access_lock:
            if drive_path in self.temporary_access:
                del self.temporary_access[drive_path]

# Ajouter l'import builtins au début du fichier
import builtins