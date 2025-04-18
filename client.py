import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 8080

client_running = True

def receive_messages(sock, private_key, server_public_key):
    global client_running
    try:
        while client_running:
            try:
                # Получение зашифрованного ключа
                key_size = int.from_bytes(sock.recv(4), 'big')
                encrypted_key = sock.recv(key_size)

                # Получение зашифрованного сообщения
                msg_size = int.from_bytes(sock.recv(4), 'big')
                encrypted_msg = sock.recv(msg_size)

                # Расшифровка сессионного ключа
                cipher_rsa = PKCS1_OAEP.new(private_key)
                session_key = cipher_rsa.decrypt(encrypted_key)

                # Расшифровка сообщения
                nonce = encrypted_msg[:16]
                ciphertext = encrypted_msg[16:]
                cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
                decrypted = cipher_aes.decrypt(ciphertext)

                print(f"\nСообщение от сервера: {decrypted.decode()}")
                print("Введите сообщение (exit для выхода): ", end='', flush=True)
            except ConnectionResetError:
                print("\nСоединение с сервером разорвано")
                client_running = False
                break
            except Exception as e:
                print(f"\nОшибка при получении сообщений: {e}")
                client_running = False
                break
    except:
        pass

def main():
    global client_running
    
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    sock = socket.socket()
    try:
        sock.connect((HOST, PORT))
        print(f"Подключено к серверу {HOST}:{PORT}")

        # Обмен ключами
        sock.send(public_key.export_key())
        server_public_key = RSA.import_key(sock.recv(1024))
        print("Обмен ключами выполнен успешно")

        # Запускаем поток для приема сообщений от сервера
        receive_thread = threading.Thread(
            target=receive_messages, 
            args=(sock, private_key, server_public_key)
        )
        receive_thread.daemon = True
        receive_thread.start()

        while client_running:
            message = input("Введите сообщение (exit для выхода): ")
            if message.lower() == "exit":
                break

            # Генерация сессионного ключа
            session_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(server_public_key)
            encrypted_key = cipher_rsa.encrypt(session_key)

            # Шифрование сообщения
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
            data = cipher_aes.nonce + ciphertext

            # Отправка данных
            try:
                sock.send(len(encrypted_key).to_bytes(4, 'big'))
                sock.send(encrypted_key)
                sock.send(len(data).to_bytes(4, 'big'))
                sock.send(data)
            except Exception as e:
                print(f"Ошибка при отправке сообщения: {e}")
                break

    except ConnectionRefusedError:
        print(f"Не удалось подключиться к серверу {HOST}:{PORT}")
    except Exception as e:
        print(f"Ошибка: {e}")
    finally:
        client_running = False
        print("Завершение работы клиента...")
        try:
            sock.close()
        except:
            pass
        print("Клиент остановлен")

if __name__ == "__main__":
    main()
