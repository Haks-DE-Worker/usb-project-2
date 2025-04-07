import tkinter as tk
from tkinter import messagebox
import platform
import sys
import os
import ctypes

# Import des modules locaux
from ui.app_ui import SecureUSBApp
from utils.dependency_checker import check_dependencies

def is_admin():
    """Vérifie si l'application s'exécute avec des privilèges administrateur."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    # Vérifier les dépendances requises
    missing_deps = check_dependencies()
    if missing_deps:
        deps_str = ", ".join(missing_deps)
        if tk._default_root is None:
            # Si Tkinter n'est pas encore initialisé
            root = tk.Tk()
            root.withdraw()  # Cacher la fenêtre principale
            messagebox.showwarning(
                "Dépendances manquantes",
                f"Les bibliothèques suivantes sont manquantes: {deps_str}\n\n"
                f"Certaines fonctionnalités peuvent ne pas fonctionner correctement.\n"
                f"Veuillez installer ces dépendances avec pip:\n"
                f"pip install {' '.join(missing_deps)}"
            )
            root.destroy()
        else:
            # Si Tkinter est déjà initialisé
            messagebox.showwarning(
                "Dépendances manquantes",
                f"Les bibliothèques suivantes sont manquantes: {deps_str}\n\n"
                f"Certaines fonctionnalités peuvent ne pas fonctionner correctement.\n"
                f"Veuillez installer ces dépendances avec pip:\n"
                f"pip install {' '.join(missing_deps)}"
            )

    # Lancer l'application
    app = SecureUSBApp()
    app.mainloop()

if __name__ == "__main__":
    if os.name == 'nt' and not is_admin():
        # Re-lancer l'application avec des privilèges administrateur
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)
    main()