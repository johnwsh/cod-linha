import tkinter as tk
from tkinter import scrolledtext, LabelFrame, Entry, Button, messagebox, W, E, X, BOTH
import base64
import json
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from criptAndBinary import encryptMessage, binarize
from twoboneq import lineEncode
from criptAndBinary import decryptMessage, debinarize
from twoboneq import lineDecode
import server

class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cliente Codificador 2B1Q")
        self.root.geometry("800x750")
        self.encoded_levels = [] # Armazena a lista gerada

        # --- Frame de Entrada ---
        input_frame = LabelFrame(root, text="Entradas", padx=10, pady=10)
        input_frame.pack(padx=10, pady=10, fill=X)
        tk.Label(input_frame, text="Mensagem:").grid(row=0, column=0, sticky=W, pady=2)
        self.message_entry = Entry(input_frame, width=80)
        self.message_entry.grid(row=0, column=1, sticky=(W, E))
        self.message_entry.insert(0, "Hello, World!")
        tk.Label(input_frame, text="Senha:").grid(row=1, column=0, sticky=W, pady=2)
        self.password_entry = Entry(input_frame, show="*", width=80)
        self.password_entry.grid(row=1, column=1, sticky=(W, E))
        self.password_entry.insert(0, "my_secret_password")

        # --- Botões ---
        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)
        self.process_button = Button(button_frame, text="1. Processar Localmente", command=self.process_data_locally)
        self.process_button.pack(side=tk.LEFT, padx=5)
        self.send_button = Button(button_frame, text="2. Enviar pela Rede", command=self.send_data_to_server, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5)

        # --- Frame de Saídas ---
        output_frame = LabelFrame(root, text="Resultados Locais", padx=10, pady=10)
        output_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        tk.Label(output_frame, text="Lista de Níveis (2B1Q) Gerada:").pack(anchor=W)
        self.levels_text = scrolledtext.ScrolledText(output_frame, height=4, wrap=tk.WORD)
        self.levels_text.pack(fill=X, pady=5)
        
        # --- Frame do Gráfico ---
        graph_frame = LabelFrame(root, text="Gráfico dos Níveis de Tensão (2B1Q)", padx=10, pady=10)
        graph_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        self.fig, self.ax = plt.subplots(figsize=(5, 2), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=BOTH, expand=True)
        
    def process_data_locally(self):
        message_str = self.message_entry.get()
        password_str = self.password_entry.get()
        if not message_str or not password_str:
            messagebox.showerror("Erro", "Mensagem e senha não podem estar vazias.")
            return

        message_bytes = message_str.encode('utf-8')
        password_bytes = password_str.encode('utf-8')
        encrypted_message = encryptMessage(message_bytes, password_bytes)
        binarized_message = binarize(encrypted_message)
        self.encoded_levels = lineEncode(binarized_message)
        
        self.levels_text.delete(1.0, tk.END)
        self.levels_text.insert(tk.END, str(self.encoded_levels))
        self.plot_levels(self.encoded_levels)
        self.send_button.config(state=tk.NORMAL) # Habilita o botão de envio

    def plot_levels(self, levels):
        self.ax.clear()
        self.ax.step(range(len(levels)), levels, where='post', linewidth=2)
        self.ax.set_title("Sinal Codificado em 2B1Q")
        self.ax.set_ylabel("Nível de Tensão")
        self.ax.set_xticks([])
        self.ax.set_yticks([-3, -1, 1, 3])
        self.ax.margins(x=0.05, y=0.1)
        self.fig.tight_layout()
        self.canvas.draw()
        
    def send_data_to_server(self, host='localhost', port=65432):
        if not self.encoded_levels:
            messagebox.showerror("Erro", "Primeiro processe os dados localmente para gerar a lista.")
            return
            
        # Empacota os dados em um dicionário para enviar como JSON
        payload = {
            "levels": self.encoded_levels,
            "password": self.password_entry.get()
        }
        
        # Converte o dicionário para uma string JSON e depois para bytes
        json_data = json.dumps(payload).encode('utf-8')

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                print(f"📡 Tentando conectar a {host}:{port}...")
                s.connect((host, port))
                s.sendall(json_data)
                print("✅ Dados enviados com sucesso!")
                messagebox.showinfo("Sucesso", "Dados enviados para o servidor com sucesso!")
        except ConnectionRefusedError:
            messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor em {host}:{port}. O servidor está em execução?")
        except Exception as e:
            messagebox.showerror("Erro de Rede", f"Ocorreu um erro: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()