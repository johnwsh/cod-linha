import tkinter as tk
from tkinter import scrolledtext, LabelFrame, Entry, Button, Frame, LEFT, RIGHT, X, Y, BOTH, TOP, SUNKEN, W, E, N, S, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from criptAndBinary import encryptMessage, binarize
from twoboneq import lineEncode
import sys

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Codificador de Linha 2B1Q")
        self.root.geometry("800x750")

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

        self.process_button = Button(root, text="Processar e Gerar Gráfico", command=self.process_data)
        self.process_button.pack(pady=5)

        output_frame = LabelFrame(root, text="Resultados", padx=10, pady=10)
        output_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)

        tk.Label(output_frame, text="Mensagem Criptografada (Bytes):").pack(anchor=W)
        self.encrypted_text = scrolledtext.ScrolledText(output_frame, height=4, wrap=tk.WORD)
        self.encrypted_text.pack(fill=X, pady=5)

        tk.Label(output_frame, text="Mensagem em Binário:").pack(anchor=W)
        self.binary_text = scrolledtext.ScrolledText(output_frame, height=6, wrap=tk.WORD)
        self.binary_text.pack(fill=X, pady=5)
        
        tk.Label(output_frame, text="Lista de Níveis (2B1Q):").pack(anchor=W)
        self.levels_text = scrolledtext.ScrolledText(output_frame, height=4, wrap=tk.WORD)
        self.levels_text.pack(fill=X, pady=5)
        
        graph_frame = LabelFrame(root, text="Gráfico dos Níveis de Tensão (2B1Q)", padx=10, pady=10)
        graph_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
        
        self.fig, self.ax = plt.subplots(figsize=(5, 2), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=BOTH, expand=True)
        
    def process_data(self):
        message_str = self.message_entry.get()
        password_str = self.password_entry.get()

        if not message_str or not password_str:
            messagebox.showerror("Erro", "Mensagem e senha não podem estar vazias.")
            return

        message_bytes = message_str.encode('utf-8')
        password_bytes = password_str.encode('utf-8')

        encrypted_message = encryptMessage(message_bytes, password_bytes)
        self.encrypted_text.delete(1.0, tk.END)
        self.encrypted_text.insert(tk.END, str(encrypted_message))

        binarized_message = binarize(encrypted_message)
        self.binary_text.delete(1.0, tk.END)
        self.binary_text.insert(tk.END, binarized_message)

        encoded_levels = lineEncode(binarized_message)
        self.levels_text.delete(1.0, tk.END)
        self.levels_text.insert(tk.END, str(encoded_levels))

        self.plot_levels(encoded_levels)

    def plot_levels(self, levels):
        self.ax.clear()
        
        if not levels:
            self.ax.set_title("Nenhum dado para exibir")
            self.canvas.draw()
            return
            
        self.ax.step(range(len(levels)), levels, where='post', linewidth=2)
        
        self.ax.set_title("Sinal Codificado em 2B1Q")
        self.ax.set_ylabel("Nível de Tensão")
        
        # ### LINHA MODIFICADA ###
        # Remove as marcações (e os números) do eixo x
        self.ax.set_xticks([])
        
        y_ticks = sorted(list(set(levels)))
        if y_ticks:
            self.ax.set_yticks([-3, -1, 1, 3])
        
        self.ax.margins(x=0.05, y=0.1) 
        self.fig.tight_layout()
        self.canvas.draw()

if __name__ == "__main__":
    root = tk.Tk()
    def on_closing():
        root.destroy()
        sys.exit()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    app = App(root)
    root.mainloop()