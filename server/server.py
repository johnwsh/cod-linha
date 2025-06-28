import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import socket
import json
import threading
import queue
import tkinter as tk
from tkinter import LabelFrame, BOTH
from tkinter import Entry, scrolledtext, Label, Button, X, W
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from encryption.criptAndBinary import decryptMessageFromStr, debinarize
from encryption.twoboneq import lineDecode

# Fila para comunicação entre threads
levels_queue = queue.Queue()

def plot_levels_tk(root, ax, canvas, app_widgets):
    def update_plot():
        try:
            while True:
                levels_list = levels_queue.get_nowait()
                ax.clear()
                ax.step(range(len(levels_list)), levels_list, where='post', linewidth=2)
                ax.set_title("Sinal Recebido (2B1Q)")
                ax.set_ylabel("Nível de Tensão")
                ax.set_xticks([])
                ax.set_yticks([-3, -1, 1, 3])
                ax.margins(x=0.05, y=0.1)
                ax.figure.tight_layout()
                canvas.draw()
                # Atualiza widgets
                app_widgets['levels_box'].delete(1.0, tk.END)
                app_widgets['levels_box'].insert(tk.END, str(levels_list))
                # Decodifica e mostra as outras informações se senha foi fornecida
                password = app_widgets['password_entry'].get()
                try:
                    decoded_bin = lineDecode(levels_list)
                    app_widgets['bin_box'].delete(1.0, tk.END)
                    app_widgets['bin_box'].insert(tk.END, decoded_bin)
                    debin = debinarize(decoded_bin)
                    app_widgets['enc_box'].delete(1.0, tk.END)
                    app_widgets['enc_box'].insert(tk.END, str(debin))
                    if password:
                        dec = decryptMessageFromStr(debin, password)
                        app_widgets['dec_box'].delete(1.0, tk.END)
                        app_widgets['dec_box'].insert(tk.END, dec.decode('utf-8'))
                    else:
                        app_widgets['dec_box'].delete(1.0, tk.END)
                        app_widgets['dec_box'].insert(tk.END, "Digite a senha para decodificar.")
                except Exception as e:
                    app_widgets['dec_box'].delete(1.0, tk.END)
                    app_widgets['dec_box'].insert(tk.END, f"Erro: {e}")
        except queue.Empty:
            pass
        root.after(500, update_plot)
    update_plot()

def handle_client(conn, addr):
    with conn:
        print(f" Conectado por {addr}")
        data_received = conn.recv(4096)
        if not data_received:
            return
        try:
            payload = json.loads(data_received.decode('utf-8'))
            levels_list = payload['levels']
            print("\n--- 📊 DADOS RECEBIDOS ---")
            print(f"Lista de Níveis: {levels_list}")
            # Coloca os níveis na fila para a interface
            levels_queue.put(levels_list)
            # Envia resposta de volta ao cliente
            response = {"status": "OK", "msg": "Níveis recebidos com sucesso!", "qtd_niveis": len(levels_list)}
            conn.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            print(f"Ocorreu um erro durante o processamento: {e}")
            response = {"status": "ERRO", "msg": str(e)}
            conn.sendall(json.dumps(response).encode('utf-8'))

def start_server(host='localhost', port=65432):
    root = tk.Tk()
    root.title("Gráfico dos Níveis Recebidos (Servidor)")
    # Campo de senha
    pw_frame = tk.Frame(root)
    pw_frame.pack(fill=X, padx=10, pady=2)
    Label(pw_frame, text="Senha para decodificação:").pack(side=tk.LEFT)
    password_entry = Entry(pw_frame, width=40)
    password_entry.pack(side=tk.LEFT, padx=5)
    # Caixa para mostrar lista de níveis
    levels_frame = LabelFrame(root, text="Lista de Níveis Recebida", padx=10, pady=5)
    levels_frame.pack(fill=X, padx=10, pady=2)
    levels_box = scrolledtext.ScrolledText(levels_frame, height=2, wrap=tk.WORD)
    levels_box.pack(fill=X)
    # Caixa para mostrar mensagem binarizada
    bin_frame = LabelFrame(root, text="Mensagem Binarizada", padx=10, pady=5)
    bin_frame.pack(fill=X, padx=10, pady=2)
    bin_box = scrolledtext.ScrolledText(bin_frame, height=2, wrap=tk.WORD)
    bin_box.pack(fill=X)
    # Caixa para mostrar mensagem criptografada
    enc_frame = LabelFrame(root, text="Mensagem Criptografada (bytes)", padx=10, pady=5)
    enc_frame.pack(fill=X, padx=10, pady=2)
    enc_box = scrolledtext.ScrolledText(enc_frame, height=2, wrap=tk.WORD)
    enc_box.pack(fill=X)
    # Caixa para mostrar mensagem decodificada
    dec_frame = LabelFrame(root, text="Mensagem Decodificada", padx=10, pady=5)
    dec_frame.pack(fill=X, padx=10, pady=2)
    dec_box = scrolledtext.ScrolledText(dec_frame, height=2, wrap=tk.WORD)
    dec_box.pack(fill=X)
    # Gráfico
    graph_frame = LabelFrame(root, text="Gráfico dos Níveis", padx=10, pady=10)
    graph_frame.pack(padx=10, pady=10, fill=BOTH, expand=True)
    fig, ax = plt.subplots(figsize=(6, 2), dpi=100)
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=BOTH, expand=True)
    plt.close(fig)
    # Widgets para atualização
    app_widgets = {
        'password_entry': password_entry,
        'levels_box': levels_box,
        'bin_box': bin_box,
        'enc_box': enc_box,
        'dec_box': dec_box
    }
    def server_thread():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            print(f"✅ Servidor escutando em {host}:{port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    threading.Thread(target=server_thread, daemon=True).start()
    plot_levels_tk(root, ax, canvas, app_widgets)
    root.mainloop()

start_server(host='26.14.40.24', port=65432)