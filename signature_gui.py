import customtkinter as ctk
from tkinter import filedialog, messagebox
from ecdsa import SigningKey, SECP256k1, util, BadSignatureError
from hashlib import sha256
import os

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SignatureApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sistema de firma digital")
        self.geometry("800x450")
        self.sk = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=160, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="Firma digital de documentos", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.pack(pady=20, padx=10)

        self.load_btn = ctk.CTkButton(self.sidebar, text="Cargar llave", command=self.load_key_dialog)
        self.load_btn.pack(pady=10, padx=20)

        self.status_indicator = ctk.CTkLabel(self.sidebar, text="No se ha cargado ninguna llave", text_color="#FF6666")
        self.status_indicator.pack(pady=10)

        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        
        self.tabview = ctk.CTkTabview(self.main_frame, width=400)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)
        
        self.tabview.add("Frimar documento")
        self.tabview.add("Verificar firma")

        self.setup_sign_tab()
        self.setup_verify_tab()

    def setup_sign_tab(self):
        tab = self.tabview.tab("Frimar documento")
        ctk.CTkLabel(tab, text="Firma un documento con tu llave secreta", font=("Arial", 14)).pack(pady=10)
        
        self.sign_file_btn = ctk.CTkButton(tab, text="Selecciona un archivo", 
                                           command=self.sign_process, fg_color="#1f538d")
        self.sign_file_btn.pack(pady=20)
        
        self.sign_status = ctk.CTkLabel(tab, text="")
        self.sign_status.pack()

    def setup_verify_tab(self):
        tab = self.tabview.tab("Verificar firma")
        ctk.CTkLabel(tab, text="Verificar la autenticidad de un documento", font=("Arial", 14)).pack(pady=10)
        
        self.verify_btn = ctk.CTkButton(tab, text="Selecciona un archivo y su firma", 
                                        command=self.verify_process, fg_color="#2b719e")
        self.verify_btn.pack(pady=20)
        
        self.verify_status = ctk.CTkLabel(tab, text="")
        self.verify_status.pack()

    def load_key_dialog(self):
        file_path = filedialog.askopenfilename(title="Selecciona tu llave secreta", filetypes=[("Key files", "*.pem")])
        if file_path:
            try:
                with open(file_path, "rb") as pem:
                    self.sk = SigningKey.from_pem(pem.read())
                self.status_indicator.configure(text="Llave cargada", text_color="#66FF66")
                messagebox.showinfo("Aviso", "Llave cargada con éxito.")
            except Exception:
                messagebox.showerror("Error", "Error al cargar la llave.")

    def sign_process(self):
        if not self.sk:
            messagebox.showwarning("Advertencia", "Inserta una llave antes de continuar")
            return

        file_path = filedialog.askopenfilename(title="Selecciona el archivo a firmar")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                
                signature = self.sk.sign(data, hashfunc=sha256, sigencode=util.sigencode_der)
                
                sig_path = file_path + ".sig"
                with open(sig_path, "wb") as f:
                    f.write(signature)
                
                messagebox.showinfo("Aviso", f"Firma guardada como:\n{sig_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al firmar: {e}")

    def verify_process(self):
        if not self.sk:
            messagebox.showwarning("Advertencia", "Inserta una llave antes de continuar")
            return

        file_path = filedialog.askopenfilename(title="Selecciona el archivo a verificar")
        if not file_path: return
        
        sig_path = filedialog.askopenfilename(title="Selecciona la firma del archivo", filetypes=[("Signature files", "*.sig")])
        if not sig_path: return

        try:
            with open(file_path, "rb") as f:
                data = f.read()
            with open(sig_path, "rb") as f:
                signature = f.read()

            vk = self.sk.verifying_key
            vk.verify(signature, data, hashfunc=sha256, sigdecode=util.sigdecode_der)
            
            messagebox.showinfo("Verificado", "El documento es legítimo.")
        except BadSignatureError:
            messagebox.showerror("Rechazado", "Es posible que el documento o la firma hayan sido alterados.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {e}")

if __name__ == "__main__":
    app = SignatureApp()
    app.mainloop()
