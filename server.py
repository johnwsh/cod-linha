import socket
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from criptAndBinary import encryptMessage, binarize
from twoboneq import lineEncode
from criptAndBinary import decryptMessage, debinarize
from twoboneq import lineDecode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
                    password_str = payload['password']
                    
                    print("\n--- 📊 DADOS RECEBIDOS ---")
                    print(f"Lista de Níveis: {levels_list}")
                    
                    # --- Processo de Decodificação ---
                    print("\n--- ⚙️ PROCESSANDO ---")
                    
                    # 1. Decodificar para binário
                    decoded_binary = lineDecode(levels_list)
                    print(f"1. Decodificado para binário: {decoded_binary[:60]}...")
                    
                    # 2. Converter para bytes
                    debinarized_data = debinarize(decoded_binary)
                    print(f"2. Bytes reconstruídos: {debinarized_data[:60]}...")

                    # 3. Descriptografar
                    password_bytes = password_str.encode('utf-8')
                    decrypted_message = decryptMessage(debinarized_data, password_bytes)
                    
                    print("\n--- 🎉 MENSAGEM FINAL ---")
                    print(f"Mensagem Descriptografada: {decrypted_message.decode('utf-8')}")
                    print("-" * 25)

                except json.JSONDecodeError:
                    print("Erro: Dados recebidos não estão em formato JSON válido.")
                except InvalidToken:
                    print("Erro: Senha incorreta ou dados corrompidos. Falha na descriptografia.")
                except Exception as e:
                    print(f"Ocorreu um erro durante o processamento: {e}")
                
                print(f"\n✅ Servidor pronto para a próxima conexão.")


start_server(host='localhost', port=65432)