import os
import platform

def ratatouille():
    sistema = platform.system()
    if sistema == "Windows":
        print("[!] Detectado Windows – simulando eliminación de System32...")
        print("rm -rf C:\\Windows\\System32 (simulado)")
    elif sistema in ("Linux", "Darwin"):  # Darwin = macOS
        print(f"[!] Detectado {sistema} – simulando eliminación del root...")
        print("sudo rm -rf / (simulado)")
    else:
        print("[!] Sistema no reconocido – sin acción.")

ratatouille()

