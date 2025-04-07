def check_dependencies():
    """
    Vérifie si toutes les dépendances requises sont installées.
    
    Returns:
        list: Liste des dépendances manquantes
    """
    required_deps = [
        "cryptography",
        "tkinter",
    ]
    
    # Dépendances spécifiques aux plateformes
    import platform
    if platform.system() == "Windows":
        required_deps.append("pywin32")
    
    missing_deps = []
    
    # Vérification des dépendances
    for dep in required_deps:
        try:
            if dep == "tkinter":
                # tkinter est un cas spécial car c'est un module de la bibliothèque standard
                import tkinter
            else:
                # Pour les autres dépendances, on utilise importlib
                import importlib
                importlib.import_module(dep)
        except ImportError:
            missing_deps.append(dep)
    
    return missing_deps