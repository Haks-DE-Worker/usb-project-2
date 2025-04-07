import ctypes
import os
import platform

# Détection du chemin de la DLL (dans le même dossier que ce fichier)
DLL_NAME = "usb_filter.dll"
DLL_PATH = os.path.join(os.path.dirname(__file__), DLL_NAME)

# Vérification de l'existence de la DLL
if not os.path.exists(DLL_PATH):
    raise FileNotFoundError(f"Impossible de trouver la DLL requise : {DLL_PATH}")

# Chargement de la DLL
usb_filter = ctypes.WinDLL(DLL_PATH)

# Déclaration des fonctions avec les bons types
try:
    # InstallFilter
    install_filter_func = usb_filter.InstallFilter
    install_filter_func.argtypes = [ctypes.c_wchar_p]
    install_filter_func.restype = ctypes.c_int
    
    # UninstallFilter
    uninstall_filter_func = usb_filter.UninstallFilter
    uninstall_filter_func.argtypes = [ctypes.c_wchar_p]
    uninstall_filter_func.restype = ctypes.c_int
    
    # AllowAccess
    allow_access_func = usb_filter.AllowAccess
    allow_access_func.argtypes = [ctypes.c_wchar_p, ctypes.c_int]
    allow_access_func.restype = ctypes.c_int
    
    # DenyAccess
    deny_access_func = usb_filter.DenyAccess
    deny_access_func.argtypes = [ctypes.c_wchar_p]
    deny_access_func.restype = ctypes.c_int
    
    # GetProtectionStatus
    get_protection_status_func = usb_filter.GetProtectionStatus
    get_protection_status_func.argtypes = [ctypes.c_wchar_p]
    get_protection_status_func.restype = ctypes.c_int
    
except AttributeError as e:
    raise Exception(f"Fonction introuvable dans la DLL: {e}")

def install_filter(drive_letter):
    """
    Installe la protection pour un lecteur spécifié.
    
    :param drive_letter: Lettre du lecteur (ex: "E:" ou "E")
    :return: 0 si succès, code d'erreur sinon
    """
    # S'assurer que la lettre du lecteur est correctement formatée
    if len(drive_letter) == 1:
        drive_letter = f"{drive_letter}:"
    
    try:
        result = install_filter_func(drive_letter)
        return result
    except Exception as e:
        print(f"Erreur lors de l'appel à InstallFilter : {e}")
        return -99  # Code d'erreur générique

def uninstall_filter(drive_letter):
    """
    Désinstalle la protection pour un lecteur spécifié.
    
    :param drive_letter: Lettre du lecteur (ex: "E:" ou "E")
    :return: 0 si succès, code d'erreur sinon
    """
    if len(drive_letter) == 1:
        drive_letter = f"{drive_letter}:"
    
    try:
        result = uninstall_filter_func(drive_letter)
        return result
    except Exception as e:
        print(f"Erreur lors de l'appel à UninstallFilter : {e}")
        return -99

def allow_access(drive_letter, duration_seconds=300):
    """
    Autorise l'accès temporaire au lecteur protégé.
    
    :param drive_letter: Lettre du lecteur (ex: "E:" ou "E")
    :param duration_seconds: Durée de l'accès en secondes
    :return: 0 si succès, code d'erreur sinon
    """
    if len(drive_letter) == 1:
        drive_letter = f"{drive_letter}:"
    
    try:
        result = allow_access_func(drive_letter, duration_seconds)
        return result
    except Exception as e:
        print(f"Erreur lors de l'appel à AllowAccess : {e}")
        return -99

def deny_access(drive_letter):
    """
    Révoque immédiatement l'accès temporaire au lecteur.
    
    :param drive_letter: Lettre du lecteur (ex: "E:" ou "E")
    :return: 0 si succès, code d'erreur sinon
    """
    if len(drive_letter) == 1:
        drive_letter = f"{drive_letter}:"
    
    try:
        result = deny_access_func(drive_letter)
        return result
    except Exception as e:
        print(f"Erreur lors de l'appel à DenyAccess : {e}")
        return -99

def get_protection_status(drive_letter):
    """
    Retourne le statut de protection du lecteur.
    
    :param drive_letter: Lettre du lecteur (ex: "E:" ou "E")
    :return: 0=non protégé, 1=protégé (accès refusé), 2=accès temporaire, <0=erreur
    """
    if len(drive_letter) == 1:
        drive_letter = f"{drive_letter}:"
    
    try:
        result = get_protection_status_func(drive_letter)
        return result
    except Exception as e:
        print(f"Erreur lors de l'appel à GetProtectionStatus : {e}")
        return -99