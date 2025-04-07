// usb_filter.cpp
// Compilez avec: cl /LD usb_filter.cpp /link /OUT:usb_filter.dll
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#define MAX_DRIVES 26

typedef struct {
    WCHAR driveLetter;
    DWORD expirationTime;  // 0 = accès refusé, >0 = temps d'expiration
} DriveAccess;

static DriveAccess g_protectedDrives[MAX_DRIVES];
static CRITICAL_SECTION g_cs;
static HHOOK g_messageHook = NULL;
static HHOOK g_fileOpHook = NULL;

// Fonction pour journaliser les événements (pour le débogage)
void LogEvent(const WCHAR* format, ...) {
    WCHAR buffer[1024];
    va_list args;
    va_start(args, format);
    
    vswprintf_s(buffer, 1024, format, args);
    
    va_end(args);
    
    // Ouvrir/créer un fichier journal
    HANDLE hFile = CreateFileW(L"C:\\SecureUSB_Log.txt", FILE_APPEND_DATA, 
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        WCHAR timeBuffer[128];
        swprintf_s(timeBuffer, 128, L"[%02d:%02d:%02d.%03d] ", 
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        
        // Écrire l'horodatage
        WriteFile(hFile, timeBuffer, lstrlenW(timeBuffer) * sizeof(WCHAR), &written, NULL);
        
        // Écrire le message
        WriteFile(hFile, buffer, lstrlenW(buffer) * sizeof(WCHAR), &written, NULL);
        
        // Ajouter un retour à la ligne
        WriteFile(hFile, L"\r\n", 2 * sizeof(WCHAR), &written, NULL);
        
        CloseHandle(hFile);
    }
}

// Initialisation du module
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialisation
        InitializeCriticalSection(&g_cs);
        memset(g_protectedDrives, 0, sizeof(g_protectedDrives));
        LogEvent(L"DLL chargée - Initialisation réussie");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // Nettoyage
        DeleteCriticalSection(&g_cs);
        if (g_messageHook) {
            UnhookWindowsHookEx(g_messageHook);
            g_messageHook = NULL;
        }
        if (g_fileOpHook) {
            UnhookWindowsHookEx(g_fileOpHook);
            g_fileOpHook = NULL;
        }
        LogEvent(L"DLL déchargée - Nettoyage effectué");
        break;
    }
    return TRUE;
}

// Fonction pour vérifier si un chemin est dans un lecteur protégé
BOOL IsPathInProtectedDrive(LPCWSTR path) {
    if (!path || wcslen(path) < 2 || path[1] != L':')
        return FALSE;
    
    WCHAR driveLetter = towupper(path[0]);
    if (driveLetter < L'A' || driveLetter > L'Z')
        return FALSE;
    
    int index = driveLetter - L'A';
    BOOL isProtected = FALSE;
    
    EnterCriticalSection(&g_cs);
    
    DWORD currentTime = GetTickCount() / 1000;  // Temps en secondes
    isProtected = (g_protectedDrives[index].driveLetter == driveLetter);
    
    // Vérifier si l'accès temporaire a expiré
    if (isProtected && g_protectedDrives[index].expirationTime > 0) {
        if (currentTime >= g_protectedDrives[index].expirationTime) {
            g_protectedDrives[index].expirationTime = 0;  // Expiration de l'accès temporaire
        } else {
            isProtected = FALSE;  // Accès temporaire autorisé
        }
    }
    
    LeaveCriticalSection(&g_cs);
    
    if (isProtected) {
        LogEvent(L"Accès interdit au chemin protégé: %s", path);
    }
    
    return isProtected;
}

// Procédure de hook qui intercepte les messages de fenêtre
LRESULT CALLBACK MessageProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Intercepter les messages liés aux opérations de fichier
    if (nCode >= 0) {
        MSG* pMsg = (MSG*)lParam;
        
        // Intercepter les messages liés aux opérations de fichier
        if (pMsg->message == WM_COPYDATA) {
            COPYDATASTRUCT* cds = (COPYDATASTRUCT*)pMsg->lParam;
            
            // Vérifier si c'est une opération de copie/déplacement
            if (cds && cds->dwData == 1 && cds->lpData) {
                WCHAR* path = (WCHAR*)cds->lpData;
                
                // Vérifier si le chemin est dans un lecteur protégé
                if (IsPathInProtectedDrive(path)) {
                    // Bloquer l'opération
                    LogEvent(L"Opération bloquée par hook de message: %s", path);
                    pMsg->message = WM_NULL;
                    return 0;  // Message traité, ne pas propager
                }
            }
        }
    }
    
    // Laisser passer les autres messages
    return CallNextHookEx(g_messageHook, nCode, wParam, lParam);
}

// Procédure de hook pour les opérations de fichier Shell
UINT_PTR CALLBACK FileOperationHookProc(HWND hdlg, UINT uiMsg, WPARAM wParam, LPARAM lParam) {
    if (uiMsg == WM_NOTIFY) {
        LPOFNOTIFY lpofn = (LPOFNOTIFY)lParam;
        
        // Intercepter les notifications de sélection de fichier
        if (lpofn->hdr.code == CDN_FILEOK) {
            WCHAR filePath[MAX_PATH];
            HWND hwndParent = GetParent(hdlg);
            
            // Obtenir le chemin du fichier sélectionné
            if (CommDlg_OpenSave_GetFilePath(hwndParent, filePath, MAX_PATH) > 0) {
                if (IsPathInProtectedDrive(filePath)) {
                    // Bloquer l'opération
                    LogEvent(L"Opération de fichier bloquée: %s", filePath);
                    SetWindowLongPtr(hdlg, DWLP_MSGRESULT, 1);
                    return 1;  // Bloquer l'opération
                }
            }
        }
    }
    
    return 0;  // Continuer l'opération
}

// Fonction pour intercepter les opérations de copier/coller
LRESULT CALLBACK ClipboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // Intercepter les messages liés au presse-papiers
        if (wParam == WM_COPY || wParam == WM_CUT) {
            // Vérifier si le focus est sur un explorateur de fichiers
            HWND hwndFocus = GetFocus();
            if (hwndFocus) {
                WCHAR className[256];
                GetClassNameW(hwndFocus, className, 256);
                
                // Si c'est l'explorateur Windows
                if (wcscmp(className, L"DirectUIHWND") == 0 || 
                    wcscmp(className, L"SysListView32") == 0) {
                    
                    // Obtenir le chemin de l'explorateur actif
                    HWND hwndExplorer = GetAncestor(hwndFocus, GA_ROOT);
                    if (hwndExplorer) {
                        WCHAR title[MAX_PATH];
                        GetWindowTextW(hwndExplorer, title, MAX_PATH);
                        
                        // Vérifier si le titre contient une lettre de lecteur protégé
                        for (int i = 0; i < MAX_DRIVES; i++) {
                            EnterCriticalSection(&g_cs);
                            WCHAR driveLetter = g_protectedDrives[i].driveLetter;
                            LeaveCriticalSection(&g_cs);
                            
                            if (driveLetter) {
                                WCHAR driveStr[3] = { driveLetter, L':', 0 };
                                if (wcsstr(title, driveStr)) {
                                    LogEvent(L"Opération de copie bloquée depuis lecteur %c:", driveLetter);
                                    return 1;  // Bloquer l'opération
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return CallNextHookEx(g_fileOpHook, nCode, wParam, lParam);
}

// Exporter les fonctions pour l'API

// Installe la protection pour un lecteur
extern "C" __declspec(dllexport) 
int InstallFilter(LPCWSTR drivePath) {
    if (!drivePath || wcslen(drivePath) < 1)
        return -1;  // Paramètre invalide
    
    WCHAR driveLetter = towupper(drivePath[0]);
    if (driveLetter < L'A' || driveLetter > L'Z')
        return -2;  // Lecteur invalide
    
    int index = driveLetter - L'A';
    
    EnterCriticalSection(&g_cs);
    
    g_protectedDrives[index].driveLetter = driveLetter;
    g_protectedDrives[index].expirationTime = 0;  // Accès refusé par défaut
    
    // Installer le hook global si ce n'est pas déjà fait
    if (!g_messageHook) {
        g_messageHook = SetWindowsHookEx(WH_GETMESSAGE, MessageProc, 
                                          GetModuleHandleW(L"usb_filter.dll"), 0);
        
        if (g_messageHook) {
            LogEvent(L"Hook de message installé avec succès");
        } else {
            LogEvent(L"Échec de l'installation du hook de message: %d", GetLastError());
        }
    }
    
    // Installer le hook de presse-papiers si ce n'est pas déjà fait
    if (!g_fileOpHook) {
        g_fileOpHook = SetWindowsHookEx(WH_CALLWNDPROC, (HOOKPROC)ClipboardProc, 
                                       GetModuleHandleW(L"usb_filter.dll"), 0);
        
        if (g_fileOpHook) {
            LogEvent(L"Hook de presse-papiers installé avec succès");
        } else {
            LogEvent(L"Échec de l'installation du hook de presse-papiers: %d", GetLastError());
        }
    }
    
    LogEvent(L"Protection installée pour le lecteur %c:", driveLetter);
    
    LeaveCriticalSection(&g_cs);
    
    return (g_messageHook != NULL && g_fileOpHook != NULL) ? 0 : -3;  // 0 = succès, -3 = échec du hook
}

// Désinstalle la protection pour un lecteur
extern "C" __declspec(dllexport) 
int UninstallFilter(LPCWSTR drivePath) {
    if (!drivePath || wcslen(drivePath) < 1)
        return -1;  // Paramètre invalide
    
    WCHAR driveLetter = towupper(drivePath[0]);
    if (driveLetter < L'A' || driveLetter > L'Z')
        return -2;  // Lecteur invalide
    
    int index = driveLetter - L'A';
    
    EnterCriticalSection(&g_cs);
    
    // Désactiver la protection pour ce lecteur
    g_protectedDrives[index].driveLetter = 0;
    g_protectedDrives[index].expirationTime = 0;
    
    // Vérifier si on peut désinstaller les hooks
    BOOL anyProtected = FALSE;
    for (int i = 0; i < MAX_DRIVES; i++) {
        if (g_protectedDrives[i].driveLetter != 0) {
            anyProtected = TRUE;
            break;
        }
    }
    
    // Si aucun lecteur n'est protégé, on peut désinstaller les hooks
    if (!anyProtected) {
        if (g_messageHook) {
            UnhookWindowsHookEx(g_messageHook);
            g_messageHook = NULL;
            LogEvent(L"Hook de message désinstallé");
        }
        
        if (g_fileOpHook) {
            UnhookWindowsHookEx(g_fileOpHook);
            g_fileOpHook = NULL;
            LogEvent(L"Hook de presse-papiers désinstallé");
        }
    }
    
    LogEvent(L"Protection désinstallée pour le lecteur %c:", driveLetter);
    
    LeaveCriticalSection(&g_cs);
    
    return 0;  // Succès
}

// Autorise l'accès temporaire pour un lecteur
extern "C" __declspec(dllexport) 
int AllowAccess(LPCWSTR drivePath, int durationSeconds) {
    if (!drivePath || wcslen(drivePath) < 1)
        return -1;  // Paramètre invalide
    
    WCHAR driveLetter = towupper(drivePath[0]);
    if (driveLetter < L'A' || driveLetter > L'Z')
        return -2;  // Lecteur invalide
    
    int index = driveLetter - L'A';
    
    EnterCriticalSection(&g_cs);
    
    // Vérifier si le lecteur est protégé
    if (g_protectedDrives[index].driveLetter != driveLetter) {
        LeaveCriticalSection(&g_cs);
        return -3;  // Lecteur non protégé
    }
    
    // Configurer l'expiration
    DWORD currentTime = GetTickCount() / 1000;  // Temps en secondes
    g_protectedDrives[index].expirationTime = currentTime + durationSeconds;
    
    LogEvent(L"Accès temporaire autorisé pour le lecteur %c: pendant %d secondes", 
             driveLetter, durationSeconds);
    
    LeaveCriticalSection(&g_cs);
    
    return 0;  // Succès
}

// Révoque l'accès temporaire pour un lecteur
extern "C" __declspec(dllexport) 
int DenyAccess(LPCWSTR drivePath) {
    if (!drivePath || wcslen(drivePath) < 1)
        return -1;  // Paramètre invalide
    
    WCHAR driveLetter = towupper(drivePath[0]);
    if (driveLetter < L'A' || driveLetter > L'Z')
        return -2;  // Lecteur invalide
    
    int index = driveLetter - L'A';
    
    EnterCriticalSection(&g_cs);
    
    // Vérifier si le lecteur est protégé
    if (g_protectedDrives[index].driveLetter != driveLetter) {
        LeaveCriticalSection(&g_cs);
        return -3;  // Lecteur non protégé
    }
    
    // Révoquer l'accès
    g_protectedDrives[index].expirationTime = 0;
    
    LogEvent(L"Accès révoqué pour le lecteur %c:", driveLetter);
    
    LeaveCriticalSection(&g_cs);
    
    return 0;  // Succès
}

// Retourne le statut de protection d'un lecteur
extern "C" __declspec(dllexport) 
int GetProtectionStatus(LPCWSTR drivePath) {
    if (!drivePath || wcslen(drivePath) < 1)
        return -1;  // Paramètre invalide
    
    WCHAR driveLetter = towupper(drivePath[0]);
    if (driveLetter < L'A' || driveLetter > L'Z')
        return -2;  // Lecteur invalide
    
    int index = driveLetter - L'A';
    int status = 0;
    
    EnterCriticalSection(&g_cs);
    
    if (g_protectedDrives[index].driveLetter == driveLetter) {
        // Vérifier l'accès temporaire
        DWORD currentTime = GetTickCount() / 1000;
        if (g_protectedDrives[index].expirationTime > 0 && 
            currentTime < g_protectedDrives[index].expirationTime) {
            status = 2;  // Accès temporaire
        } else {
            status = 1;  // Protégé
        }
    } else {
        status = 0;  // Non protégé
    }
    
    LeaveCriticalSection(&g_cs);
    
    return status;
}