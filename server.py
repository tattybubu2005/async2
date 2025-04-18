import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 8080
# Храним информацию о клиентах (соединение, адрес, публичный ключ)
clients = []
clients_lock = threading.Lock()
server_running = True

def send_message_to_client(conn, client_public_key, message):
    try:
        # Генерация сессионного ключа
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        encrypted_key = cipher_rsa.encrypt(session_key)

        # Шифрование сообщения
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        data = cipher_aes.nonce + ciphertext

        # Отправка данных
        conn.send(len(encrypted_key).to_bytes(4, 'big'))
        conn.send(encrypted_key)
        conn.send(len(data).to_bytes(4, 'big'))
        conn.send(data)
        return True
    except Exception as e:
        print(f"Ошибка при отправке сообщения: {e}")
        return False

def handle_client(conn, addr):
    client_public_key = None
    try:
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()

        # Отправка публичного ключа сервера
        conn.send(public_key.export_key())

        # Получение публичного ключа клиента
        client_public_key = RSA.import_key(conn.recv(1024))
        
        # Добавляем клиента в список с его ключом
        with clients_lock:
            for client in clients:
                if client[0] == conn:
                    client[2] = client_public_key
                    break

        while server_running:
            # Получение зашифрованного ключа
            key_size = int.from_bytes(conn.recv(4), 'big')
            encrypted_key = conn.recv(key_size)

            # Получение зашифрованного сообщения
            msg_size = int.from_bytes(conn.recv(4), 'big')
            encrypted_msg = conn.recv(msg_size)

            # Расшифровка сессионного ключа
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(encrypted_key)

            # Расшифровка сообщения
            nonce = encrypted_msg[:16]
            ciphertext = encrypted_msg[16:]
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            decrypted = cipher_aes.decrypt(ciphertext)
            message = decrypted.decode()

            print(f"Сообщение от {addr}: {message}")

            # Автоматический ответ
            response = f"Получено: {message}"
            send_message_to_client(conn, client_public_key, response)

    except (ConnectionResetError, BrokenPipeError):
        print(f"Клиент {addr} отключился")
    except Exception as e:
        print(f"Ошибка с клиентом {addr}: {e}")
    finally:
        conn.close()
        with clients_lock:
            clients[:] = [c for c in clients if c[0] != conn]
        print(f"Клиент {addr} отключен")

def server_input():
    global server_running
    while server_running:
        command = input("Введите сообщение для всех клиентов (или 'stop' для завершения): ")
        
        if command.lower() == 'stop':
            with clients_lock:
                if len(clients) == 0:
                    server_running = False
                    print("Все клиенты отключены. Сервер завершает работу.")
                else:
                    print(f"Невозможно остановить сервер: подключено {len(clients)} клиентов")
        else:
            # Отправляем сообщение всем клиентам
            with clients_lock:
                for client in clients[:]:  # Копируем список для безопасной итерации
                    conn, addr, client_key = client
                    if client_key:
                        print(f"Отправка сообщения клиенту {addr}")
                        success = send_message_to_client(conn, client_key, command)
                        if not success:
                            try:
                                conn.close()
                            except:
                                pass
                            clients[:] = [c for c in clients if c[0] != conn]
                            print(f"Клиент {addr} удален из-за ошибки связи")

def main():
    global server_running
    sock = socket.socket()
    sock.bind((HOST, PORT))
    sock.listen()
    sock.settimeout(1)  # Таймаут для возможности проверки флага server_running

    # Запуск потока для ввода сообщений сервера
    input_thread = threading.Thread(target=server_input)
    input_thread.daemon = True
    input_thread.start()

    print("Сервер запущен. Ожидание подключений...")
    
    try:
        while server_running:
            try:
                conn, addr = sock.accept()
                with clients_lock:
                    clients.append([conn, addr, None])  # Публичный ключ будет добавлен позже
                print(f"Подключен клиент {addr}")
                threading.Thread(target=handle_client, args=(conn, addr)).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("Получен сигнал прерывания")
    finally:
        print("Закрытие сервера...")
        server_running = False
        
        # Закрываем все соединения
        with clients_lock:
            for conn, addr, _ in clients:
                try:
                    conn.close()
                except:
                    pass
        
        sock.close()
        print("Сервер остановлен")

if __name__ == "__main__":
    main()
