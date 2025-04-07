import os
import platform
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from core.usb_monitor import USBMonitor
from core.secure_usb import SecureUSB
from core.fs_overlay import FileSystemOverlay

class SecureUSBApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("Secure USB")
        self.geometry("600x500")
        
        self.secure_usb = SecureUSB()
        self.fs_overlay = FileSystemOverlay(self.secure_usb)
        
        self.usb_drives = {}  # Dictionnaire des clés USB {path: label}
        
        self.create_widgets()
        
        # Démarre le moniteur USB
        self.usb_monitor = USBMonitor(self.handle_usb_event)
    
    def create_widgets(self):
        """Crée l'interface utilisateur."""
        # Frame principale
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Titre
        title_label = ttk.Label(main_frame, text="Sécurisation de clés USB", font=("Helvetica", 16))
        title_label.pack(pady=10)
        
        # Frame pour les clés USB
        usb_frame = ttk.LabelFrame(main_frame, text="Clés USB disponibles")
        usb_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Liste des clés USB avec scrollbar
        usb_scroll = ttk.Scrollbar(usb_frame)
        usb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.usb_listbox = tk.Listbox(usb_frame, selectmode=tk.MULTIPLE, yscrollcommand=usb_scroll.set)
        self.usb_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        usb_scroll.config(command=self.usb_listbox.yview)
        
        # Bouton de rafraîchissement
        refresh_btn = ttk.Button(usb_frame, text="Rafraîchir", command=self.refresh_drives)
        refresh_btn.pack(pady=5)
        
        # Frame pour le mot de passe
        pwd_frame = ttk.Frame(main_frame)
        pwd_frame.pack(fill=tk.X, pady=10)
        
        pwd_label = ttk.Label(pwd_frame, text="Mot de passe:")
        pwd_label.pack(side=tk.LEFT, padx=5)
        
        self.pwd_entry = ttk.Entry(pwd_frame, show="*")
        self.pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Boutons d'action
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.protect_btn = ttk.Button(btn_frame, text="Protéger les clés sélectionnées", command=self.protect_drives)
        self.protect_btn.pack(side=tk.LEFT, padx=5)
        
        self.unlock_btn = ttk.Button(btn_frame, text="Déverrouiller pour copie", command=self.unlock_for_copy)
        self.unlock_btn.pack(side=tk.LEFT, padx=5)
        
        self.browse_btn = ttk.Button(btn_frame, text="Parcourir les fichiers", command=self.browse_files)
        self.browse_btn.pack(side=tk.LEFT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Prêt")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def refresh_drives(self):
        """Rafraîchit manuellement la liste des clés USB."""
        # Nettoie la liste actuelle
        self.usb_listbox.delete(0, tk.END)
        self.usb_drives.clear()
        
        # Récupère les lecteurs amovibles
        try:
            drives = self.usb_monitor._get_drives()
            if drives:
                self.handle_usb_event(list(drives), "added")
                self.status_var.set(f"{len(drives)} clé(s) USB détectée(s)")
            else:
                self.status_var.set("Aucune clé USB détectée")
        except Exception as e:
            self.status_var.set(f"Erreur lors de la détection: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur lors de la détection des clés USB: {str(e)}")
    
    def handle_usb_event(self, drives, event_type):
        """Gère les événements de connexion/déconnexion de clés USB."""
        if event_type == "added":
            for drive in drives:
                if drive not in self.usb_drives:
                    try:
                        drive_label = f"{drive} - {self.get_drive_label(drive)}"
                        self.usb_drives[drive] = drive_label
                        self.usb_listbox.insert(tk.END, drive_label)
                        
                        # Vérifie si la clé est déjà protégée
                        if self.secure_usb.is_protected(drive):
                            self.fs_overlay.add_protected_drive(drive)
                            self.status_var.set(f"Clé USB protégée détectée: {drive}")
                    except Exception as e:
                        print(f"Erreur lors de l'ajout du lecteur {drive}: {e}")
        
        elif event_type == "removed":
            removed_indices = []
            for drive in drives:
                if drive in self.usb_drives:
                    idx = list(self.usb_drives.keys()).index(drive)
                    removed_indices.append(idx)
                    self.fs_overlay.remove_protected_drive(drive)
                    del self.usb_drives[drive]
            
            # Supprime de la liste en commençant par la fin pour éviter les décalages d'indices
            for idx in sorted(removed_indices, reverse=True):
                self.usb_listbox.delete(idx)
    
    def get_drive_label(self, drive_path):
        """Récupère le label d'une clé USB."""
        try:
            # Pour Windows
            if platform.system() == "Windows":
                try:
                    import win32api
                    return win32api.GetVolumeInformation(drive_path)[0] or "Sans nom"
                except:
                    return os.path.basename(drive_path.rstrip('\\')) or "Sans nom"
            # Pour macOS/Linux, on prend simplement le nom du dossier
            else:
                return os.path.basename(drive_path) or "Sans nom"
        except Exception as e:
            print(f"Erreur lors de la récupération du label pour {drive_path}: {e}")
            return "Sans nom"
    
    def protect_drives(self):
        """Protège les clés USB sélectionnées."""
        selected_indices = self.usb_listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("Sélection vide", "Veuillez sélectionner au moins une clé USB.")
            return
        
        password = self.pwd_entry.get()
        if not password:
            messagebox.showwarning("Mot de passe vide", "Veuillez entrer un mot de passe.")
            return
        
        drives = list(self.usb_drives.keys())
        protected_count = 0
        
        for idx in selected_indices:
            try:
                drive_path = drives[idx]
                if self.secure_usb.protect_drive(drive_path, password):
                    self.fs_overlay.add_protected_drive(drive_path)
                    protected_count += 1
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de la protection pour {drives[idx]}: {str(e)}")
        
        if protected_count > 0:
            messagebox.showinfo("Protection réussie", f"{protected_count} clé(s) USB protégée(s) avec succès.")
            self.status_var.set(f"{protected_count} clé(s) USB protégée(s)")
        else:
            messagebox.showerror("Erreur", "Échec de la protection des clés USB.")
    
    def unlock_for_copy(self):
        """Déverrouille temporairement une clé USB pour permettre la copie."""
        selected_indices = self.usb_listbox.curselection()
        if not selected_indices or len(selected_indices) != 1:
            messagebox.showwarning("Sélection incorrecte", "Veuillez sélectionner une seule clé USB.")
            return
        
        password = self.pwd_entry.get()
        if not password:
            messagebox.showwarning("Mot de passe vide", "Veuillez entrer un mot de passe.")
            return
        
        drive_path = list(self.usb_drives.keys())[selected_indices[0]]
        
        if not self.secure_usb.is_protected(drive_path):
            messagebox.showinfo("Information", "Cette clé USB n'est pas protégée.")
            return
        
        if self.secure_usb.verify_password(drive_path, password):
            # Déverrouiller temporairement pour la copie
            try:
                # Création d'une fenêtre de sélection de fichiers
                selected_files = filedialog.askopenfilenames(
                    title="Sélectionnez les fichiers à copier",
                    initialdir=drive_path,
                    filetypes=[("Tous les fichiers", "*.*")]
                )
                
                if selected_files:
                    dest_dir = filedialog.askdirectory(
                        title="Sélectionnez le dossier de destination"
                    )
                    
                    if dest_dir:
                        import shutil
                        copied_count = 0
                        
                        # Temporairement, on désactive la protection pour ces fichiers
                        self.fs_overlay.enable_temporary_access(drive_path, password)
                        
                        try:
                            for file_path in selected_files:
                                file_name = os.path.basename(file_path)
                                dest_path = os.path.join(dest_dir, file_name)
                                shutil.copy2(file_path, dest_path)
                                copied_count += 1
                        finally:
                            # Réactive la protection
                            self.fs_overlay.disable_temporary_access(drive_path)
                        
                        messagebox.showinfo("Copie réussie", f"{copied_count} fichier(s) copié(s) avec succès.")
                        self.status_var.set(f"{copied_count} fichier(s) copié(s)")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de la copie: {str(e)}")
        else:
            messagebox.showerror("Erreur d'authentification", "Mot de passe incorrect.")
    
    def browse_files(self):
        """Ouvre un explorateur de fichiers pour parcourir les fichiers sur la clé USB."""
        selected_indices = self.usb_listbox.curselection()
        if not selected_indices or len(selected_indices) != 1:
            messagebox.showwarning("Sélection incorrecte", "Veuillez sélectionner une seule clé USB.")
            return
        
        drive_path = list(self.usb_drives.keys())[selected_indices[0]]
        
        # Ouvre l'explorateur de fichiers natif
        try:
            if platform.system() == "Windows":
                os.startfile(drive_path)
            elif platform.system() == "Darwin":  # macOS
                import subprocess
                subprocess.run(['open', drive_path])
            else:  # Linux
                import subprocess
                subprocess.run(['xdg-open', drive_path])
                
            self.status_var.set(f"Exploration de {drive_path}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ouvrir l'explorateur: {str(e)}")
    
    def on_closing(self):
        """Gère la fermeture de l'application."""
        # Arrêter le moniteur USB
        if hasattr(self, 'usb_monitor'):
            self.usb_monitor.stop()
        
        # Restaurer les fonctions originales du système de fichiers
        if hasattr(self, 'fs_overlay'):
            self.fs_overlay.restore_filesystem_functions()
        
        self.destroy()