import sys
import os
import tkinter as tk
from time import time
from shutil import rmtree
from pathlib import Path
from tkinter import filedialog
from ecdsa import SigningKey, SECP256k1, util, BadSignatureError
from hashlib import sha256
from zipfile import ZipFile

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
    sign_path = readingfile + ".sig"
    with open(sign_path, "wb") as f:
        f.write(signature)
    return sign_path

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
    elif op == "1":
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        readingfile = filedialog.askopenfilename(
                title="Selecciona el archivo a firmar"
                )
        root.destroy()
        return readingfile
    elif op == "2":
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        readingfile = filedialog.askopenfilename(
                title="Selecciona el archivo a verificar"
                )
        root.destroy()
        if ".zip" in readingfile:
            return readingfile, None
        else:
            readingsignature = readingfile + ".sig"
            return readingfile, readingsignature

def compress(path1, path2):
    zipname = ".//" + str(time()).replace('.', '') + ".zip"
    with ZipFile(zipname, 'w') as myzip:
        myzip.write(path1, arcname=path1.name)
        myzip.write(path2, arcname=path2.name)
    os.remove(path2)
    return zipname

def main():
    sk = load_key()
    menu = """\n--- SISTEMA DE FIRMA DIGITAL ---
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
                sign_path = signing(readingfile, sk)
                while True:
                    op = input("¿Desea comprimir el archivo? (S/N): ")
                    op = op.strip().lower()
                    if op == "s" or op == "n":
                        break
                if op == "s":
                    path1 = Path(readingfile)
                    path2 = Path(sign_path)
                    zipname = compress(path1, path2)
            except FileNotFoundError:
                print("No se encontró el archivo. Revisa la entrada.")
            except Exception as e:
                print(f"Error al firmar. {e}")
            else:
                if op == "s":
                    print(f"Archivo y firma comprimidos en {zipname}")
                if op == "n":     
                    print("Archivo firmado con éxito.")
                    print(f"Firma guardada como {sign_path}")
        elif op == "2":
            readingfile, readingsignature = reading(op)
            vk = sk.verifying_key
            try:
                if readingsignature == None:
                    with ZipFile(readingfile, "r") as myzip:
                        myzip.extractall(".//tmp")
                    files = [i for i in os.walk(".//tmp")][0][2]
                    readingfile = f".//tmp//{files[0]}"
                    readingsignature = f".//tmp//{files[1]}"
                    verifying(readingfile, readingsignature, vk)
                    rmtree(".//tmp")
                else:
                    verifying(readingfile, readingsignature, vk)
            except FileNotFoundError:
                print("No se encontró el archivo o la firma. Revisa la entrada.")
            except Exception as e:
                print(f"Error al verificar. {e}")
        elif op == "3":
            sk = load_key()
        elif op == "4":
            break
        else:
            print("Ingresa una opción válida.")

if __name__ == "__main__":
    main()
