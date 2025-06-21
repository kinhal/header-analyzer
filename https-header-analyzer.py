import requests
from colorama import Fore, Style, init
import sys

init(autoreset=True)

def print_title():
    title = r"""
 _                     _                                  _                         
| |                   | |                                | |                        
| |__  _____ _____  __| |_____  ____    _____ ____  _____| |_   _ _____ _____  ____ 
|  _ \| ___ (____ |/ _  | ___ |/ ___)  (____ |  _ \(____ | | | | (___  ) ___ |/ ___)
| | | | ____/ ___ ( (_| | ____| |      / ___ | | | / ___ | | |_| |/ __/| ____| |    
|_| |_|_____)_____|\____|_____)_|      \_____|_| |_\_____|\_)__  (_____)_____)_|    
                                                           (____/
                                            
    """
    print(Fore.CYAN + title + Style.RESET_ALL)
    print(Fore.CYAN + "           --- HTTP HEADER ANALYZER ---\n" + Style.RESET_ALL)

def analyze_headers(headers):
    print(Fore.LIGHTBLUE_EX + "[*] Analizzando intestazioni HTTP...\n" + Style.RESET_ALL)

    security_headers = {
        "Content-Security-Policy": "Aiuta a prevenire attacchi XSS e altri code injection.",
        "X-Content-Type-Options": "Impedisce al browser di interpretare tipi MIME non dichiarati.",
        "X-Frame-Options": "Protegge contro clickjacking limitando il framing della pagina.",
        "Strict-Transport-Security": "Forza il browser a usare HTTPS.",
        "Referrer-Policy": "Controlla quali informazioni di referrer vengono inviate.",
        "Permissions-Policy": "Controlla l’accesso a funzionalità browser come la geolocalizzazione."
    }

    for header, desc in security_headers.items():
        if header in headers:
            print(Fore.GREEN + f"[+] {header}: Presente")
            print(Fore.YELLOW + f"    Descrizione: {desc}\n")
        else:
            print(Fore.RED + f"[-] {header}: MANCANTE")
            print(Fore.YELLOW + f"    Suggerimento: {desc}\n")

    server = headers.get("Server", "Non presente")
    print(Fore.LIGHTMAGENTA_EX + f"[*] Server: {server}")

def main():
    print_title()
    url = input(Fore.CYAN + "Inserisci l'URL da analizzare (es. https://example.com): " + Style.RESET_ALL)

    if not (url.startswith("http://") or url.startswith("https://")):
        print(Fore.RED + "Errore: inserisci un URL valido che inizi con http:// o https://")
        sys.exit(1)

    print(Fore.CYAN + "\nRecupero intestazioni..." + Style.RESET_ALL)

    try:
        response = requests.get(url, timeout=10)
        analyze_headers(response.headers)
    except requests.RequestException as e:
        print(Fore.RED + f"Errore durante la richiesta: {e}")
        sys.exit(1)

    input(Fore.CYAN + "\nPremi un tasto per uscire..." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
