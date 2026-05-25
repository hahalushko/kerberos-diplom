#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import hashlib
import getpass
import time
import secrets
import ssl
import os
import base64
import hmac
from magma import Magma

# НАСТРОЙКИ
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_CERT = os.path.join(BASE_DIR, "server.crt")
CA_CERT = os.path.join(BASE_DIR, "ca.crt")

# Параметры KDF (должны совпадать с db_server)
PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 16

# Argon2 (опционально)
try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
    print("[Client] Argon2 доступен")
except ImportError:
    ARGON2_AVAILABLE = False
    print("[Client] Argon2 не найден, используем PBKDF2")

# КРИПТО-ФУНКЦИИ
magma = Magma()

def encrypt(data: bytes, key: bytes) -> str:
    key_enc = hashlib.sha256(key).digest()
    key_mac = hashlib.sha256(key + b"hmac").digest()
    ciphertext_b64 = magma.encrypt_cbc(data, key_enc)
    ciphertext = base64.b64decode(ciphertext_b64)
    mac = hmac.new(key_mac, ciphertext, hashlib.sha256).digest()
    combined = ciphertext + mac
    return base64.b64encode(combined).decode('ascii')

def decrypt(data: str, key: bytes) -> bytes:
    key_enc = hashlib.sha256(key).digest()
    key_mac = hashlib.sha256(key + b"hmac").digest()
    combined = base64.b64decode(data)
    if len(combined) < 32:
        raise ValueError("Некорректные данные")
    ciphertext = combined[:-32]
    mac_received = combined[-32:]
    mac_calculated = hmac.new(key_mac, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_calculated):
        raise ValueError("Ошибка HMAC")
    return magma.decrypt_cbc(base64.b64encode(ciphertext).decode('ascii'), key_enc)

def derive_client_key(password: str, salt: bytes) -> bytes:
    # Вычисляет ключ клиента на основе пароля и соли.
    print(f"[Client] Вычисление ключа: пароль ***, соль {salt.hex()[:16]}...")
    if ARGON2_AVAILABLE:
        key = hash_secret_raw(
            password.encode('utf-8'), salt,
            time_cost=3, memory_cost=65536, parallelism=4,
            hash_len=KEY_LENGTH, type=Type.ID
        )
        print("[Client] Использован Argon2id")
    else:
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                   salt, PBKDF2_ITERATIONS, dklen=KEY_LENGTH)
        print(f"[Client] Использован PBKDF2 (итераций {PBKDF2_ITERATIONS})")
    print(f"[Client] Получен ключ: {key.hex()[:16]}...")
    return key

# КЛИЕНТ
class KerberosClient:
    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.client_key = None
        self.salt = None
        self.tgt = None
        self.tgt_ticket_id = None
        self.session_key = None
        self.service_session_key = None
        self.service_ticket = None
        self.role = None
        self.magma = Magma()

        # Пути к клиентскому сертификату (если существует)
        self.client_cert = os.path.join(BASE_DIR, f"{name}.crt")
        self.client_key_file = os.path.join(BASE_DIR, f"{name}.key")

        # Контекст для подключения к AS (без клиентского сертификата)
        self.ssl_context_as = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.ssl_context_as.load_verify_locations(cafile=CA_CERT)
        self.ssl_context_as.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context_as.check_hostname = True

        # Контекст для подключения к TGS и Service (с клиентским сертификатом, если есть)
        self.ssl_context_mtls = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.ssl_context_mtls.load_verify_locations(cafile=CA_CERT)
        self.ssl_context_mtls.verify_mode = ssl.CERT_REQUIRED
        self.ssl_context_mtls.check_hostname = True

        if os.path.exists(self.client_cert) and os.path.exists(self.client_key_file):
            self.ssl_context_mtls.load_cert_chain(certfile=self.client_cert, keyfile=self.client_key_file)
            print(f"[Client] Загружен клиентский сертификат для {name} (mTLS будет использован для TGS/Service)")
        else:
            print(f"[Client] ВНИМАНИЕ: клиентский сертификат для {name} не найден. mTLS не будет работать, если сервер требует сертификат.")

        print(f"[Client] Клиент {name} инициализирован (TLS с проверкой сертификатов)")

    def _encrypt(self, data: bytes, key: bytes) -> str:
        return encrypt(data, key)

    def _decrypt(self, data: str, key: bytes) -> bytes:
        return decrypt(data, key)

    def _send_to_as(self, action, **kwargs):
        # Отправляет запрос к AS (порт 8888) с действием.
        print(f"[Client] Отправка запроса к AS: действие={action}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            with self.ssl_context_as.wrap_socket(sock, server_hostname='localhost') as ssock:
                ssock.connect(('localhost', 8888))
                req = json.dumps({'action': action, **kwargs})
                print(f"[Client] Запрос: {req}")
                ssock.sendall(req.encode('utf-8'))
                resp = ssock.recv(4096).decode('utf-8')
                print(f"[Client] Ответ AS: {resp[:100]}...")
                return json.loads(resp)

    def register(self, role='user'):
        # Регистрация нового пользователя через AS с указанием роли.
        print(f"[Client] === РЕГИСТРАЦИЯ пользователя {self.name} с ролью {role} ===")
        resp = self._send_to_as('register', name=self.name, password=self.password, role=role)
        if resp.get('status') == 'ok':
            self.salt = bytes.fromhex(resp['salt_hex'])
            print(f"[Client] Получена соль: {self.salt.hex()[:16]}...")
            self.client_key = derive_client_key(self.password, self.salt)
            print("Регистрация успешна")
            return True
        else:
            print(f"Ошибка регистрации: {resp.get('reason', resp.get('error'))}")
            return False

    def _get_salt_from_as(self):
        # Запрашивает соль пользователя у AS.
        print(f"[Client] Запрос соли для {self.name} у AS...")
        resp = self._send_to_as('get_salt', name=self.name)
        if resp.get('status') == 'ok':
            self.salt = bytes.fromhex(resp['salt_hex'])
            print(f"[Client] Соль получена: {self.salt.hex()[:16]}...")
            return True
        else:
            print(f"[Client] Не удалось получить соль: {resp.get('reason', resp.get('error'))}")
            return False

    def request_tgt(self, as_host='localhost', as_port=8888):
        # Запрашивает TGT у AS (старый формат без action).
        print(f"[Client] === ЗАПРОС TGT для {self.name} ===")

        if not self.salt:
            if not self._get_salt_from_as():
                print("Не удалось получить соль пользователя")
                return False
        self.client_key = derive_client_key(self.password, self.salt)

        timestamp = time.time()
        nonce = secrets.token_hex(8)
        auth_data = f"{timestamp}:{self.name}:{nonce}".encode('utf-8')
        authenticator = self._encrypt(auth_data, self.client_key)
        print(f"[Client] Аутентификатор создан (timestamp={timestamp}, nonce={nonce})")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            with self.ssl_context_as.wrap_socket(sock, server_hostname=as_host) as ssock:
                ssock.connect((as_host, as_port))
                req = json.dumps({'name': self.name, 'authenticator': authenticator})
                print(f"[Client] Отправка запроса TGT к AS...")
                ssock.sendall(req.encode('utf-8'))
                resp = ssock.recv(4096).decode('utf-8')
                print(f"[Client] Ответ AS получен")
                data = json.loads(resp)
                if 'error' in data:
                    print(f"Ошибка AS: {data['error']}")
                    return False
                self.encrypted_session_key = data['encrypted_session_key']
                self.tgt = data['tgt']
                self.session_key = self._decrypt(self.encrypted_session_key, self.client_key)
                print(f"[Client] Сессионный ключ расшифрован: {self.session_key.hex()[:16]}...")
                print("TGT и сессионный ключ получены")
                return True

    def get_role(self):
        # Запрашивает роль пользователя у AS.
        print(f"[Client] Запрос роли для {self.name}...")
        resp = self._send_to_as('get_role', name=self.name)
        if resp.get('status') == 'ok':
            self.role = resp['role']
            print(f"[Client] Роль пользователя {self.name}: {self.role}")
            return True
        else:
            print(f"Ошибка получения роли: {resp.get('reason', resp.get('error'))}")
            return False

    def request_service_ticket(self, service_name, tgs_host='localhost', tgs_port=8889):
        # Запрашивает Service Ticket у TGS с использованием mTLS.
        print(f"[Client] === ЗАПРОС SERVICE TICKET для сервиса {service_name} ===")
        if not self.tgt or not self.session_key:
            raise Exception("Нет TGT или сессионного ключа")

        timestamp = time.time()
        nonce = secrets.token_hex(8)
        auth_data = f"{timestamp}:{self.name}:{nonce}".encode('utf-8')
        authenticator = self._encrypt(auth_data, self.session_key)
        print(f"[Client] Аутентификатор для TGS создан (nonce={nonce})")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            with self.ssl_context_mtls.wrap_socket(sock, server_hostname=tgs_host) as ssock:
                ssock.connect((tgs_host, tgs_port))
                req = json.dumps({
                    'tgt': self.tgt,
                    'authenticator': authenticator,
                    'service_name': service_name
                })
                print(f"[Client] Отправка запроса к TGS...")
                ssock.sendall(req.encode('utf-8'))
                resp = ssock.recv(4096).decode('utf-8')
                print(f"[Client] Ответ TGS получен")
                data = json.loads(resp)
                if 'error' in data:
                    print(f"Ошибка TGS: {data['error']}")
                    return None
                self.service_ticket = data['service_ticket']
                enc_ssk = data['encrypted_service_session_key']
                self.service_session_key = self._decrypt(enc_ssk, self.session_key)
                print(f"[Client] Сессионный ключ для сервиса расшифрован: {self.service_session_key.hex()[:16]}...")
                print("Service Ticket и ключ получены")
                return self.service_ticket

    def access_service(self, service_ticket, service_host='localhost', service_port=8890):
        # Обращается к сервису с взаимной аутентификацией, используя mTLS.
        print(f"[Client] === ДОСТУП К СЕРВИСУ ===")
        if not self.service_session_key:
            raise Exception("Нет сессионного ключа для сервиса")

        timestamp = time.time()
        nonce = secrets.token_hex(8)
        auth_data = f"{timestamp}:{self.name}:{nonce}".encode('utf-8')
        authenticator = self._encrypt(auth_data, self.service_session_key)
        print(f"[Client] Аутентификатор для сервиса создан (nonce={nonce})")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            with self.ssl_context_mtls.wrap_socket(sock, server_hostname=service_host) as ssock:
                ssock.connect((service_host, service_port))
                req = json.dumps({
                    'service_ticket': service_ticket,
                    'authenticator': authenticator
                })
                print(f"[Client] Отправка запроса к сервису...")
                ssock.sendall(req.encode('utf-8'))
                resp = ssock.recv(4096).decode('utf-8')
                print(f"[Client] Ответ сервиса получен")
                data = json.loads(resp)
                if data.get('status') == 'access_granted':
                    verifier = data.get('verifier')
                    if verifier:
                        try:
                            verifier_plain = self._decrypt(verifier, self.service_session_key).decode('utf-8')
                            print(f"[Client] Расшифрованный верификатор: {verifier_plain}")
                            parts = verifier_plain.split(':')
                            if len(parts) == 4:
                                v_time, v_client, v_nonce, v_service = parts
                                if abs(time.time() - float(v_time)) < 60 and v_client == self.name:
                                    print("Взаимная аутентификация сервиса успешна")
                                else:
                                    print("Верификатор сервиса не прошёл проверку (имя или время)")
                            else:
                                print("Неверный формат верификатора")
                        except Exception as e:
                            print(f"Ошибка проверки верификатора: {e}")
                    else:
                        print("Верификатор отсутствует, взаимная аутентификация не выполнена")
                    print("Доступ к сервису разрешён")
                    return True
                else:
                    error_msg = data.get('error', 'Неизвестная ошибка')
                    print(f"Доступ запрещён: {error_msg}")
                    return False

# ОСНОВНОЙ ЦИКЛ С ПОДДЕРЖКОЙ ПРОДОЛЖИТЕЛЬНОЙ СЕССИИ
def main():
    while True:
        print("\n=== Kerberos Authentication ===")
        print("1 - Login")
        print("2 - Register")
        print("3 - Exit")
        choice = input("Выберите действие: ").strip()

        if choice == '1':
            name = input("Username: ")
            password = getpass.getpass("Password: ")
            client = KerberosClient(name, password)
            if not client.request_tgt():
                input("\nНажмите Enter для продолжения...")
                continue
            if not client.get_role():
                input("\nНажмите Enter для продолжения...")
                continue

            # Определяем доступные сервисы в зависимости от роли
            available_services = []
            if client.role == 'user':
                available_services = ["MailServer"]
            elif client.role == 'admin':
                available_services = ["FileServer", "MailServer"]
            else:
                available_services = ["FileServer"]

            print(f"\nВаша роль: {client.role}")
            print("Доступные сервисы:")
            for idx, svc in enumerate(available_services, 1):
                print(f"{idx} - {svc}")

            svc_choice = input("Выберите сервис: ").strip()
            try:
                svc_idx = int(svc_choice) - 1
                if 0 <= svc_idx < len(available_services):
                    service_name = available_services[svc_idx]
                    service_ports = {
                        "FileServer": 8890,
                        "MailServer": 8891,
                    }
                    port = service_ports.get(service_name, 8890)

                    # Получаем Service Ticket
                    service_ticket = client.request_service_ticket(service_name)
                    if not service_ticket:
                        input("\nНажмите Enter для продолжения...")
                        continue

                    # Доступ к сервису
                    client.access_service(service_ticket, service_port=port)

                    # ПРОДОЛЖЕНИЕ СЕССИИ: возможность повторных запросов без перелогина
                    while True:
                        print("\n--- Продолжение сессии ---")
                        print("1 - Повторно запросить Service Ticket (используя тот же TGT)")
                        print("2 - Получить доступ к сервису (с уже имеющимся Service Ticket)")
                        print("3 - Выбрать другой сервис (новый Service Ticket)")
                        print("4 - Выйти из сессии (завершить)")
                        sub_choice = input("Ваш выбор: ").strip()

                        if sub_choice == '1':
                            # Запрашиваем новый Service Ticket (TGT остаётся тот же)
                            new_ticket = client.request_service_ticket(service_name)
                            if new_ticket:
                                service_ticket = new_ticket
                                print("Новый Service Ticket получен. Теперь можно выполнить пункт 2 для доступа.")
                        elif sub_choice == '2':
                            # Используем текущий Service Ticket
                            if service_ticket:
                                client.access_service(service_ticket, service_port=port)
                            else:
                                print("Нет Service Ticket. Сначала получите его (пункт 1).")
                        elif sub_choice == '3':
                            # Сменить сервис: нужно заново выбрать сервис и запросить ST
                            print("\nДоступные сервисы:")
                            for idx, svc in enumerate(available_services, 1):
                                print(f"{idx} - {svc}")
                            new_svc_choice = input("Выберите сервис: ").strip()
                            try:
                                new_svc_idx = int(new_svc_choice) - 1
                                if 0 <= new_svc_idx < len(available_services):
                                    service_name = available_services[new_svc_idx]
                                    port = service_ports.get(service_name, 8890)
                                    new_ticket = client.request_service_ticket(service_name)
                                    if new_ticket:
                                        service_ticket = new_ticket
                                        print("Service Ticket для нового сервиса получен.")
                                    else:
                                        print("Не удалось получить Service Ticket.")
                                else:
                                    print("Неверный выбор.")
                            except ValueError:
                                print("Неверный ввод.")
                        elif sub_choice == '4':
                            print("Завершение сессии.")
                            break
                        else:
                            print("Неверный выбор.")
                else:
                    print("Неверный выбор сервиса.")
            except ValueError:
                print("Неверный ввод.")
            input("\nНажмите Enter для продолжения...")

        elif choice == '2':
            name = input("Username: ")
            password = getpass.getpass("Password: ")
            role_choice = input("Выберите роль:\n1 - user (обычный пользователь)\n2 - admin (администратор)\nВаш выбор (1/2): ").strip()
            role = "admin" if role_choice == "2" else "user"
            client = KerberosClient(name, password)
            if client.register(role):
                print("Теперь вы можете войти с этими учётными данными.")
                print("Для использования mTLS получите клиентский сертификат у администратора.")
            input("\nНажмите Enter для продолжения...")

        elif choice == '3':
            break
        else:
            print("Неверный выбор.")
            input("Нажмите Enter для продолжения...")

if __name__ == '__main__':
    main()