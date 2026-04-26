import sys
import tkinter as tk
from tkinter import filedialog
from ecdsa import SigningKey, SECP256k1, util, BadSignatureError
from hashlib import sha256

def load_key():
    while True:
        private_key = reading(op=None)
        try:
            with open(private_key, "rb") as pem:
                sk = SigningKey.from_pem(pem.read())
        except Exception:
            a = input("Error al cargar la llave. ¿Intentar de nuevo? [S/N]: ")
            if a.lower().strip() != "s":
                sys.exit()
        else:
            break
    return sk
        
def signing(readingfile, sk):
    with open(readingfile, "rb") as f:
        file = f.read()

    signature = sk.sign(
        file, 
        hashfunc=sha256, 
        sigencode=util.sigencode_der
    )

    with open(readingfile + ".sig", "wb") as f:
        f.write(signature)

def verifying(readingfile, readingsignature, vk):
    try:
        with open(readingfile, "rb") as f:
            file = f.read()
        with open(readingsignature, "rb") as f:
            signature_to_verify = f.read()
        
        is_valid = vk.verify(
            signature_to_verify,
            file,
            hashfunc=sha256,
            sigdecode=util.sigdecode_der)
        print("El documento firmado es legítimo.")
    except BadSignatureError:
        print("Firma inváida. Es posible que el documento o la firma hayan sido alterados.")

def reading(op):
    if op == None:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        private_key = filedialog.askopenfilename(
                title="Ingresa la llave secreta",
                filetypes=[("Key files", "*.pem")]
                )
        root.destroy()
        return private_key
    if op == "1":
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        readingfile = filedialog.askopenfilename(
                title="Selecciona el archivo a firmar"
                )
        root.destroy()
        return readingfile
    if op == "2":
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        readingfile = filedialog.askopenfilename(
                title="Selecciona el archivo a verificar"
                )
        root.destroy()
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        readingsignature = filedialog.askopenfilename(
                title="Selecciona la firma del archivo",
                filetypes=[("Signature files", "*.sig")]
                )
        root.destroy()
        return readingfile, readingsignature

def main():
    sk = load_key()
    menu = """--- SISTEMA DE FIRMA DIGITAL ---
1. Firmar
2. Verificar
3. Cambiar de llave
4. Salir
Selecciona una opción: """
    while True:
        op = input(menu)
        if op == "1":
            readingfile = reading(op)
            try:
                signing(readingfile, sk)
            except FileNotFoundError:
                print("No se encontró el archivo. Revisa la entrada.")
                """except Exception:
                print("Error al firmar.")"""
            else:
                print("Archivo firmado con éxito.")
                print(f"Firma guardada como {readingfile + '.sig'}")
        elif op == "2":
            readingfile, readingsignature = reading(op)
            vk = sk.verifying_key
            try:
                verifying(readingfile, readingsignature, vk)
            except FileNotFoundError:
                print("No se encontró el archivo o la firma. Revisa la entrada.")
            except Exception:
                print("Error al verificar.")
        elif op == "3":
            sk = load_key()
        elif op == "4":
            break
        else:
            print("Ingresa una opción válida.")

if __name__ == "__main__":
    main()
