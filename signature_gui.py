import os
import customtkinter as ctk
from tkinter import filedialog, messagebox
from pathlib import Path
from time import time
from shutil import rmtree
from zipfile import ZipFile
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, SECP256k1, util, BadSignatureError

ctk.set_appearance_mode("Light") 
ctk.set_default_color_theme("green") 

class DigitalSignatureApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sistema de firma digital")
        self.geometry("800x550")

        self.private_key = None
        self.public_key = None
        self.private_key_path = ctk.StringVar(value="Sin llave privada")
        self.public_key_path = ctk.StringVar(value="Sin llave pública")
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self, width=650)
        self.tabview.grid(row=0, column=0, padx=20, pady=(10, 20), sticky="nsew")
        self.tabview.add("Firmar documento")
        self.tabview.add("Verificar firma")
        self.tabview.add("Administrador de llaves")

        self.setup_sign_tab()
        self.setup_verify_tab()
        self.setup_key_tab()

        self.status_label = ctk.CTkLabel(self, text="Listo", anchor="w")
        self.status_label.grid(row=1, column=0, padx=20, pady=5, sticky="ew")

    def setup_key_tab(self):
        parent = self.tabview.tab("Administrador de llaves")
        
        ctk.CTkLabel(parent, text="Llaves criptográficas", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=10)
        
        priv_frame = ctk.CTkFrame(parent)
        priv_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(priv_frame, text="Llave privada para firmar:").pack(side="top", anchor="w", padx=10)
        ctk.CTkEntry(priv_frame, textvariable=self.private_key_path, width=400, state="disabled").pack(side="left", padx=10, pady=10)
        ctk.CTkButton(priv_frame, text="Insertar llave", command=self.load_private_key, width=100).pack(side="right", padx=10)

        pub_frame = ctk.CTkFrame(parent)
        pub_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(pub_frame, text="Llave privada para verificar:").pack(side="top", anchor="w", padx=10)
        ctk.CTkEntry(pub_frame, textvariable=self.public_key_path, width=400, state="disabled").pack(side="left", padx=10, pady=10)
        ctk.CTkButton(pub_frame, text="Insertar llave", command=self.load_public_key, width=100).pack(side="right", padx=10)

        ctk.CTkLabel(parent, text="Opciones de interfaz").pack(pady=(20, 0))
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(parent, values=["Dark", "Light", "System"],
                                                               command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.pack(pady=10)

    def setup_sign_tab(self):
        parent = self.tabview.tab("Firmar documento")
        
        self.sign_file_path = ctk.StringVar(value="")
        self.compress_var = ctk.BooleanVar(value=True)

        ctk.CTkLabel(parent, text="Crear firma digital", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        ctk.CTkLabel(parent, text="Archivo a firmar:").pack(anchor="w", padx=50)
        file_frame = ctk.CTkFrame(parent, fg_color="transparent")
        file_frame.pack(fill="x", padx=50)
        ctk.CTkEntry(file_frame, textvariable=self.sign_file_path, placeholder_text="Selecciona el archivo a firmar").pack(side="left", fill="x", expand=True)
        ctk.CTkButton(file_frame, text="Buscar", command=self.browse_sign_file, width=80).pack(side="right", padx=(5,0))

        ctk.CTkCheckBox(parent, text="Comprimir el archivo y la firma", variable=self.compress_var).pack(pady=20)

        self.sign_btn = ctk.CTkButton(parent, text="Firmar archivo", height=45, font=ctk.CTkFont(weight="bold"), 
                                     command=self.execute_signing, fg_color="#2ecc71", hover_color="#27ae60")
        self.sign_btn.pack(pady=20, padx=50, fill="x")

    def setup_verify_tab(self):
        parent = self.tabview.tab("Verificar firma")
        
        self.verify_file_path = ctk.StringVar(value="")
        
        ctk.CTkLabel(parent, text="Verificar integridad", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)

        ctk.CTkLabel(parent, text="Insertar archivo:").pack(anchor="w", padx=50)
        v_file_frame = ctk.CTkFrame(parent, fg_color="transparent")
        v_file_frame.pack(fill="x", padx=50)
        ctk.CTkEntry(v_file_frame, textvariable=self.verify_file_path, placeholder_text="Seleccionar archivo a verificar").pack(side="left", fill="x", expand=True)
        ctk.CTkButton(v_file_frame, text="Buscar", command=self.browse_verify_file, width=80).pack(side="right", padx=(5,0))

        self.verify_btn = ctk.CTkButton(parent, text="Verificar firma", height=45, font=ctk.CTkFont(weight="bold"),
                                       command=self.execute_verification)
        self.verify_btn.pack(pady=40, padx=50, fill="x")


    def load_private_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if path:
            try:
                with open(path, "rb") as f:
                    self.private_key = SigningKey.from_pem(f.read())
                self.private_key_path.set(path)
                self.update_status("Llave insertada con éxito")
            except Exception as e:
                messagebox.showerror("Error", f"Error al insertar la llave: {e}")

    def load_public_key(self):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        if path:
            try:
                with open(path, "rb") as f:
                    self.public_key = VerifyingKey.from_pem(f.read())
                self.public_key_path.set(path)
                self.update_status("Llave insertada con éxito.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al insertar llave: {e}")

    def browse_sign_file(self):
        path = filedialog.askopenfilename()
        if path: self.sign_file_path.set(path)

    def browse_verify_file(self):
        path = filedialog.askopenfilename()
        if path: self.verify_file_path.set(path)

    def update_status(self, text):
        self.status_label.configure(text=f"Estado: {text}")

    def change_appearance_mode_event(self, new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    def execute_signing(self):
        if not self.private_key:
            return messagebox.showwarning("Sin llave", "Inserta una llave privada antes de continuar.")
        
        input_file = self.sign_file_path.get()
        if not input_file or not os.path.exists(input_file):
            return messagebox.showwarning("Error", "Por favor revisa la entrada.")

        try:
            with open(input_file, "rb") as f:
                data = f.read()
            
            signature = self.private_key.sign(data, hashfunc=sha256, sigencode=util.sigencode_der)
            sig_path = input_file + ".sig"
            
            with open(sig_path, "wb") as f:
                f.write(signature)

            if self.compress_var.get():
                zip_name = ".//" + str(time()).replace('.', '') + ".zip"
                with ZipFile(zip_name, 'w') as z:
                    z.write(input_file, arcname=Path(input_file).name)
                    z.write(sig_path, arcname=Path(sig_path).name)
                os.remove(sig_path)
                messagebox.showinfo("Aviso", f"Archivo firmado y comprimido:\n{zip_name}")
            else:
                messagebox.showinfo("Aviso", f"Firma guardada como:\n{sig_path}")
            
            self.update_status("Firma realizada con éxito.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar: {e}")

    def execute_verification(self):
        if not self.public_key:
            return messagebox.showwarning("Sin llave", "Inserta una llave pública antes de continuar.")
        
        path = self.verify_file_path.get()
        if not path or not os.path.exists(path):
            return messagebox.showwarning("Error", "Por favor revisa la entrada.")

        try:
            if path.endswith(".zip"):
                if os.path.exists("tmp_verify"): rmtree("tmp_verify")
                os.makedirs("tmp_verify")
                with ZipFile(path, 'r') as z:
                    z.extractall("tmp_verify")
                
                files = os.listdir("tmp_verify")
                sig_file = next((f for f in files if f.endswith(".sig")), None)
                data_file = next((f for f in files if not f.endswith(".sig")), None)
                
                if not sig_file or not data_file:
                    raise Exception("Formato del archivo inválido.")
                
                with open(f"tmp_verify/{data_file}", "rb") as f: data = f.read()
                with open(f"tmp_verify/{sig_file}", "rb") as f: sig = f.read()
                rmtree("tmp_verify")
            else:
                if not path.endswith(".sig"):
                    sig_path = path + ".sig"
                    data_path = path
                else:
                    sig_path = path
                    data_path = path.replace(".sig", "")

                with open(data_path, "rb") as f: data = f.read()
                with open(sig_path, "rb") as f: sig = f.read()

            self.public_key.verify(sig, data, hashfunc=sha256, sigdecode=util.sigdecode_der)
            messagebox.showinfo("Verificado", "El documento el legítimo.")
            self.update_status("Verificación realizada con éxito.")
            
        except BadSignatureError:
            messagebox.showerror("Error", "Firma inválida. Es posible que el documento o la firma hayan sido alterados.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {e}")

if __name__ == "__main__":
    app = DigitalSignatureApp()
    app.mainloop()
