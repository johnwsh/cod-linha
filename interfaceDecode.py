import tkinter as tk
from tkinter import scrolledtext, LabelFrame, Entry, Button, Frame, LEFT, RIGHT, X, Y, BOTH, TOP, SUNKEN, W, E, N, S, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from criptAndBinary import decryptMessage, debinarize
from twoboneq import lineDecode
import sys
import ast
from cryptography.fernet import InvalidToken

class DecoderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Decodificador de Linha 2B1Q")
        self.root.geometry("800x750")

        # --- Frame de Entrada ---
        input_frame = LabelFrame(root, text="Entradas", padx=10, pady=10)
        input_frame.pack(padx=10, pady=10, fill=X)

        tk.Label(input_frame, text="Lista de Níveis:").grid(row=0, column=0, sticky=W, pady=2)
        self.levels_entry = scrolledtext.ScrolledText(input_frame, height=4, wrap=tk.WORD)
        self.levels_entry.grid(row=0, column=1, sticky=(W, E))

        tk.Label(input_frame, text="Senha:").grid(row=1, column=0, sticky=W, pady=2)
        self.password_entry = Entry(input_frame, width=80)
        self.password_entry.grid(row=1, column=1, sticky=(W, E))
        
        # --- Botão ---
        self.process_button = Button(root, text="Decodificar e Gerar Gráfico", command=self.process_data)
        self.process_button.pack(pady=5)

        # --- Frame do Gráfico ---
        graph_frame = LabelFrame(root, text="Gráfico dos Níveis de Tensão (Entrada)", padx=10, pady=10)
        graph_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        
        self.fig, self.ax = plt.subplots(figsize=(5, 2), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=BOTH, expand=True)

        # --- Frame de Saídas ---
        output_frame = LabelFrame(root, text="Resultados da Decodificação", padx=10, pady=10)
        output_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        
        tk.Label(output_frame, text="Decodificado para Binário:").pack(anchor=W)
        self.binary_text = scrolledtext.ScrolledText(output_frame, height=6, wrap=tk.WORD)
        self.binary_text.pack(fill=X, pady=5)
        
        tk.Label(output_frame, text="Mensagem Criptografada (Bytes reconstruídos):").pack(anchor=W)
        self.encrypted_text = scrolledtext.ScrolledText(output_frame, height=4, wrap=tk.WORD)
        self.encrypted_text.pack(fill=X, pady=5)

        tk.Label(output_frame, text="Mensagem Final Descriptografada:").pack(anchor=W)
        self.decrypted_text = scrolledtext.ScrolledText(output_frame, height=3, wrap=tk.WORD)
        self.decrypted_text.pack(fill=X, pady=5)

    def clear_outputs(self):
        self.ax.clear()
        self.ax.set_title("Aguardando entrada...")
        self.canvas.draw()
        self.binary_text.delete(1.0, tk.END)
        self.encrypted_text.delete(1.0, tk.END)
        self.decrypted_text.delete(1.0, tk.END)

    def process_data(self):
        self.clear_outputs()
        levels_str = self.levels_entry.get(1.0, tk.END).strip()
        password_str = self.password_entry.get()

        if not levels_str or not password_str:
            messagebox.showerror("Erro", "A lista de níveis e a senha não podem estar vazias.")
            return

        try:
            # Converte a string de entrada para uma lista de inteiros
            levels_list = ast.literal_eval(levels_str)
            if not isinstance(levels_list, list):
                raise ValueError
        except (ValueError, SyntaxError):
            messagebox.showerror("Erro de Formato", "A entrada de níveis não é uma lista válida. Ex: [1, -1, 3, -3]")
            return

        try:
            # 1. Plotar o gráfico dos níveis de entrada
            self.plot_levels(levels_list)

            # 2. Decodificar os níveis para binário
            decoded_binary = lineDecode(levels_list)
            self.binary_text.insert(tk.END, decoded_binary)
            
            # 3. Converter o binário para bytes (mensagem criptografada)
            debinarized_data = debinarize(decoded_binary)
            self.encrypted_text.insert(tk.END, str(debinarized_data))

            # 4. Descriptografar a mensagem
            password_bytes = password_str.encode('utf-8')
            decrypted_message_bytes = decryptMessage(debinarized_data, password_bytes)
            self.decrypted_text.insert(tk.END, decrypted_message_bytes.decode('utf-8'))

        except ValueError as e:
            messagebox.showerror("Erro na Decodificação", f"Valor de nível inválido na lista: {e}")
        except InvalidToken:
            messagebox.showerror("Erro de Descriptografia", "Senha incorreta ou dados corrompidos. Não foi possível descriptografar.")
        except Exception as e:
            messagebox.showerror("Erro Inesperado", f"Ocorreu um erro: {e}")


    def plot_levels(self, levels):
        self.ax.clear()
        
        if not levels:
            self.ax.set_title("Nenhum dado para exibir")
            self.canvas.draw()
            return
            
        self.ax.step(range(len(levels)), levels, where='post', linewidth=2)
        
        self.ax.set_title("Sinal de Entrada (Níveis)")
        self.ax.set_ylabel("Nível de Tensão")
        self.ax.set_xticks([]) # Remove os números do eixo X
        self.ax.set_yticks([-3, -1, 1, 3])
        self.ax.margins(x=0.05, y=0.1) 
        self.fig.tight_layout()
        self.canvas.draw()

def mainDecode():    
    root = tk.Tk()
    def on_closing():
        root.destroy()
        sys.exit()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    app = DecoderApp(root)
    root.mainloop()
