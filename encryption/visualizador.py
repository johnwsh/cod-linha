import tkinter as tk
from tkinter import messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from twoboneq import lineEncode

# Função para desenhar a forma de onda

def desenhar_onda(levels, frame):
    for widget in frame.winfo_children():
        widget.destroy()
    fig, ax = plt.subplots(figsize=(6,2))
    x = [0]
    y = [0]
    for i, level in enumerate(levels):
        x.extend([i, i+1])
        y.extend([level, level])
    ax.plot(x[1:], y[1:], drawstyle='steps-pre', linewidth=2)
    ax.set_ylim(-4, 4)
    ax.set_yticks([-3, -1, 1, 3])
    ax.set_yticklabels(['-3', '-1', '1', '3'])
    ax.set_xlabel('Símbolos')
    ax.set_ylabel('Nível')
    ax.set_title('Forma de Onda 2B1Q')
    ax.grid(True)
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    plt.close(fig)

def visualizar():
    binario = entry_binario.get()
    if not all(b in '01' for b in binario) or len(binario) % 2 != 0:
        messagebox.showerror('Erro', 'Digite uma sequência binária válida e de tamanho par.')
        return
    levels = lineEncode(binario)
    desenhar_onda(levels, frame_onda)
    label_niveis.config(text=f'Níveis: {levels}')

root = tk.Tk()
root.title('Visualizador 2B1Q')

frame_input = tk.Frame(root)
frame_input.pack(pady=10)

label_binario = tk.Label(frame_input, text='Binário:')
label_binario.pack(side=tk.LEFT)

entry_binario = tk.Entry(frame_input, width=30)
entry_binario.pack(side=tk.LEFT, padx=5)

btn_visualizar = tk.Button(frame_input, text='Visualizar', command=visualizar)
btn_visualizar.pack(side=tk.LEFT, padx=5)

frame_onda = tk.Frame(root, width=600, height=200)
frame_onda.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

label_niveis = tk.Label(root, text='Níveis: ')
label_niveis.pack(pady=5)

root.mainloop()
