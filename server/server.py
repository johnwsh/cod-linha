import socket
import json

def start_server(host='localhost', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"✅ Servidor escutando em {host}:{port}")
        
        while True: # Loop para aceitar múltiplas conexões
            conn, addr = s.accept()
            with conn:
                print(f"🔌 Conectado por {addr}")
                data_received = conn.recv(4096) # Recebe até 4KB de dados
                if not data_received:
                    continue

                try:
                    # Carrega os dados JSON recebidos
                    payload = json.loads(data_received.decode('utf-8'))
                    levels_list = payload['levels']
                    
                    print("\n--- 📊 DADOS RECEBIDOS ---")
                    print(f"Lista de Níveis: {levels_list}")

                except Exception as e:
                    print(f"Ocorreu um erro durante o processamento: {e}")


start_server(host='localhost', port=65432)