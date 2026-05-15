import os
import sys
import customtkinter as ctk
from tkinter import filedialog, messagebox
from pathlib import Path
from time import time
from zipfile import ZipFile
from shutil import rmtree
from hashlib import sha256
from ecdsa import SigningKey, SECP256k1, util, BadSignatureError

ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("green")

class SignatureApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sistema de Firma Digital")
        self.geometry("800x500")
        
        self.sk = None
        self.vk = None
        self.current_key_path = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="Firmas Digitales", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.pack(pady=20, padx=20)

        self.btn_load_key = ctk.CTkButton(self.sidebar, text="🔑 Insertar llave", command=self.load_key_dialog)
        self.btn_load_key.pack(pady=10, padx=20)

        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.status_frame.pack(side="bottom", fill="x", pady=20, padx=20)
        
        self.key_status_label = ctk.CTkLabel(self.status_frame, text="Sin llave", text_color="#FF6666", font=ctk.CTkFont(size=12))
        self.key_status_label.pack()

        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tabview.add("Firmar documento")
        self.tabview.add("Verificar firma")

        self.setup_sign_tab()
        self.setup_verify_tab()

    def setup_sign_tab(self):
        frame = self.tabview.tab("Firmar documento")
        
        self.sign_label = ctk.CTkLabel(frame, text="Paso 1: Selecciona el archivo a firmar", font=ctk.CTkFont(size=16))
        self.sign_label.pack(pady=(20, 10))

        self.btn_select_sign = ctk.CTkButton(frame, text="📁 Seleccionar archivo", command=self.select_file_to_sign)
        self.btn_select_sign.pack(pady=10)

        self.file_to_sign_path = ctk.CTkLabel(frame, text="Ningún archivo seleccionado", font=ctk.CTkFont(slant="italic"))
        self.file_to_sign_path.pack()

        self.compress_var = ctk.BooleanVar(value=False)
        self.check_compress = ctk.CTkCheckBox(frame, text="Comprimir archivo y firma", variable=self.compress_var)
        self.check_compress.pack(pady=30)

        self.btn_execute_sign = ctk.CTkButton(frame, text="Firmar", fg_color="#2ECC71", hover_color="#27AE60", 
                                             command=self.execute_signing, state="disabled")
        self.btn_execute_sign.pack(pady=20, ipadx=20, ipady=10)

    def setup_verify_tab(self):
        frame = self.tabview.tab("Verificar firma")

        self.verify_label = ctk.CTkLabel(frame, text="Seleccionar archivo o carpeta comprimida", font=ctk.CTkFont(size=16))
        self.verify_label.pack(pady=(20, 10))

        self.btn_select_verify = ctk.CTkButton(frame, text="📂 Abrir archivo", command=self.select_file_to_verify)
        self.btn_select_verify.pack(pady=10)

        self.file_to_verify_path = ctk.CTkLabel(frame, text="Ningún archivo seleccionado", font=ctk.CTkFont(slant="italic"))
        self.file_to_verify_path.pack()

        self.btn_execute_verify = ctk.CTkButton(frame, text="Verificar firma", fg_color="#2ECC71", hover_color="#27AE60",
                                               command=self.execute_verification, state="disabled")
        self.btn_execute_verify.pack(pady=40, ipadx=20, ipady=10)

    def load_key_dialog(self):
        file_path = filedialog.askopenfilename(title="Insertar llave", filetypes=[("Key files", "*.pem")])
        if file_path:
            try:
                with open(file_path, "rb") as pem:
                    self.sk = SigningKey.from_pem(pem.read())
                    self.vk = self.sk.verifying_key
                    self.current_key_path = file_path
                    self.key_status_label.configure(text="Llave lista", text_color="#2ECC71")
                    self.btn_execute_sign.configure(state="normal")
                    self.btn_execute_verify.configure(state="normal")
                    messagebox.showinfo("Aviso", "¡Llave insertada con éxito!")
            except Exception as e:
                messagebox.showerror("Error", f"Error al insertar la llave: {e}")

    def select_file_to_sign(self):
        path = filedialog.askopenfilename(title="Selecciona el archivo a firmar")
        if path:
            self.file_to_sign_path.configure(text=os.path.basename(path))
            self.target_sign_path = path

    def select_file_to_verify(self):
        path = filedialog.askopenfilename(title="Selecciona el archivo a verificar")
        if path:
            self.file_to_verify_path.configure(text=os.path.basename(path))
            self.target_verify_path = path

    def execute_signing(self):
        if not self.sk:
            messagebox.showwarning("Advertencia", "Selecciona una llave antes de continuar")
            return

        try:
            with open(self.target_sign_path, "rb") as f:
                file_data = f.read()

            signature = self.sk.sign(file_data, hashfunc=sha256, sigencode=util.sigencode_der)
            sign_path = self.target_sign_path + ".sig"
            
            with open(sign_path, "wb") as f:
                f.write(signature)

            if self.compress_var.get():
                zip_name = ".//" + str(time()).replace('.', '') + ".zip"
                with ZipFile(zip_name, 'w') as myzip:
                    myzip.write(self.target_sign_path, arcname=Path(self.target_sign_path).name)
                    myzip.write(sign_path, arcname=Path(sign_path).name)
                os.remove(sign_path)
                messagebox.showinfo("Aviso", f"Archivo firmado y comprimido en:\n{zip_name}")
            else:
                messagebox.showinfo("Aviso", f"Firma guardada como:\n{os.path.basename(sign_path)}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar: {e}")

    def execute_verification(self):
        path = self.target_verify_path
        try:
            if path.endswith(".zip"):
                with ZipFile(path, "r") as myzip:
                    myzip.extractall("./tmp_verify")
                files = os.listdir("./tmp_verify")
                sig_file = [f for f in files if f.endswith(".sig")][0]
                data_file = [f for f in files if not f.endswith(".sig")][0]
                
                with open(f"./tmp_verify/{data_file}", "rb") as f: file_data = f.read()
                with open(f"./tmp_verify/{sig_file}", "rb") as f: sig_data = f.read()
                rmtree("./tmp_verify")
            else:
                sig_path = path + ".sig"
                if not os.path.exists(sig_path):
                    messagebox.showerror("Error", "Frima no encontrada")
                    return
                with open(path, "rb") as f: file_data = f.read()
                with open(sig_path, "rb") as f: sig_data = f.read()

            self.vk.verify(sig_data, file_data, hashfunc=sha256, sigdecode=util.sigdecode_der)
            messagebox.showinfo("Verificación exitosa", "✅ El documento es legítmo.")
        
        except BadSignatureError:
            messagebox.showerror("Verificación fallida", "❌ Firma inválida. Es posible que el documento o la firma hayan sido alterados")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {e}")

if __name__ == "__main__":
    app = SignatureApp()
    app.mainloop()
