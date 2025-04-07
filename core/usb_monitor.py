import os
import threading
import time
import platform
import string

class USBMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.drives = set()
        self.running = True
        self.thread = threading.Thread(target=self._monitor)
        self.thread.daemon = True
        self.thread.start()
    
    def _get_drives(self):
        """Obtient la liste des lecteurs amovibles connectés."""
        drives = set()
        
        if platform.system() == "Windows":
            try:
                import win32api
                import win32file
                
                drive_letters = win32api.GetLogicalDriveStrings().split('\000')[:-1]
                for letter in drive_letters:
                    if win32file.GetDriveType(letter) == win32file.DRIVE_REMOVABLE:
                        drives.add(letter)
            except ImportError:
                # Si win32api n'est pas disponible, utiliser une approche alternative
                import ctypes
                
                bitmask = ctypes.windll.kernel32.GetLogicalDrives() & 0xFFFFFFFF
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive = f"{letter}:\\"
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            drives.add(drive)
                    bitmask >>= 1
        
        elif platform.system() == "Darwin":  # macOS
            # Sur macOS, les volumes sont montés dans /Volumes
            import subprocess
            
            try:
                result = subprocess.run(['diskutil', 'list', '-plist', 'external'], 
                                        capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if "Volumes" in line:
                        path = line.strip().split(' ')[-1]
                        if os.path.exists(path):
                            drives.add(path)
            except:
                # Fallback: simplement lister le contenu de /Volumes
                volumes = [f"/Volumes/{vol}" for vol in os.listdir("/Volumes")]
                for vol in volumes:
                    if os.path.ismount(vol) and vol != "/Volumes":
                        drives.add(vol)
        
        else:  # Linux
            # Sur Linux, les périphériques sont généralement montés dans /media/[user]
            # ou /mnt
            username = os.environ.get('USER', '')
            
            # Vérifier /media/[user]
            media_path = f"/media/{username}"
            if os.path.exists(media_path):
                for item in os.listdir(media_path):
                    full_path = os.path.join(media_path, item)
                    if os.path.ismount(full_path):
                        drives.add(full_path)
            
            # Vérifier /mnt
            mnt_path = "/mnt"
            if os.path.exists(mnt_path):
                for item in os.listdir(mnt_path):
                    full_path = os.path.join(mnt_path, item)
                    if os.path.ismount(full_path):
                        drives.add(full_path)
        
        return drives
    
    def _monitor(self):
        """Surveille la connexion et la déconnexion des périphériques USB."""
        old_drives = self._get_drives()
        
        # Notification initiale des périphériques déjà connectés
        if old_drives:
            self.callback(list(old_drives), "added")
        
        while self.running:
            try:
                time.sleep(1)
                new_drives = self._get_drives()
                
                # Détecte les nouvelles clés USB
                added = new_drives - old_drives
                if added:
                    self.callback(list(added), "added")
                
                # Détecte les clés USB retirées
                removed = old_drives - new_drives
                if removed:
                    self.callback(list(removed), "removed")
                
                old_drives = new_drives
            except Exception as e:
                print(f"Erreur dans le moniteur USB: {e}")
                # Continue malgré l'erreur
    
    def stop(self):
        """Arrête le thread de surveillance."""
        self.running = False
        if self.thread.is_alive():
            self.thread.join(2)