#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import hashlib
import time
import threading
import ssl
import os
import base64
import hmac
import secrets
from magma import Magma

# НАСТРОЙКИ
SERVICE_TICKET_LIFETIME = 600
AUTH_TIMEOUT = 300
CLEANUP_INTERVAL = 600
MAX_NONCE_CACHE_SIZE = 10000

# Пути к сертификатам
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_CERT = os.path.join(BASE_DIR, "service_server.crt")
SERVER_KEY = os.path.join(BASE_DIR, "service_server.key")
CA_CERT = os.path.join(BASE_DIR, "ca.crt")
SERVICE_CLIENT_CERT = os.path.join(BASE_DIR, "service_client.crt")
SERVICE_CLIENT_KEY = os.path.join(BASE_DIR, "service_client.key")

# DB для централизованного отзыва
DB_HOST = 'localhost'
DB_PORT = 9090

MASTER_KEY_ENV = "DB_MASTER_KEY"
MASTER_KEY_FILE = "master.key"

# КРИПТО-ФУНКЦИИ
magma = Magma()

def get_master_key() -> bytes:
    env_key = os.environ.get(MASTER_KEY_ENV)
    if env_key:
        print("[Service] Мастер-ключ из переменной окружения")
        return base64.b64decode(env_key)
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) == 32:
                print(f"[Service] Мастер-ключ из файла {MASTER_KEY_FILE}")
                return key
    raise RuntimeError("Мастер-ключ не найден")

MASTER_KEY = get_master_key()

def decrypt_with_master(encrypted_b64: str) -> bytes:
    print("[Service] Расшифровка ключа мастер-ключом...")
    key_enc = hashlib.sha256(MASTER_KEY).digest()
    key_mac = hashlib.sha256(MASTER_KEY + b"hmac").digest()
    combined = base64.b64decode(encrypted_b64)
    if len(combined) < 32:
        raise ValueError("Некорректные данные")
    ciphertext = combined[:-32]
    mac_received = combined[-32:]
    mac_calculated = hmac.new(key_mac, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_calculated):
        raise ValueError("Ошибка HMAC")
    plain = magma.decrypt_cbc(base64.b64encode(ciphertext).decode('ascii'), key_enc)
    print("[Service] Ключ успешно расшифрован")
    return plain

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

# ПОЛУЧЕНИЕ КЛЮЧА СЕРВИСА
def _db_request_raw(action, **kwargs):
    # Универсальный запрос к DB с использованием клиентского сертификата сервиса.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.check_hostname = False
    if os.path.exists(SERVICE_CLIENT_CERT) and os.path.exists(SERVICE_CLIENT_KEY):
        context.load_cert_chain(certfile=SERVICE_CLIENT_CERT, keyfile=SERVICE_CLIENT_KEY)
        print("[Service] Загружен клиентский сертификат для подключения к DB")
    else:
        print("[Service] Клиентский сертификат не найден, продолжаем без него")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        with context.wrap_socket(sock, server_hostname='localhost') as ssock:
            ssock.connect((DB_HOST, DB_PORT))
            req = json.dumps({'action': action, **kwargs})
            print(f"[Service] Отправка запроса к DB: {req}")
            ssock.sendall(req.encode('utf-8'))
            resp = json.loads(ssock.recv(4096).decode('utf-8'))
            print(f"[Service] Ответ DB: статус={resp.get('status')}")
            return resp

def get_service_key_from_db(service_name: str) -> bytes:
    print(f"[Service] Запрос ключа сервиса {service_name} к DB...")
    resp = _db_request_raw('get_service_key', service_name=service_name)
    if resp['status'] == 'ok':
        enc_key = resp['encrypted_service_key']
        service_key = decrypt_with_master(enc_key)
        print(f"[Service] Ключ сервиса {service_name} получен: {service_key.hex()[:16]}...")
        return service_key
    else:
        raise ValueError(resp.get('reason', 'Сервис не найден'))

def load_or_generate_service_key(service_name: str) -> bytes:
    key_file = f"{service_name}.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
            if len(key) == 16:
                print(f"[Service] Ключ сервиса {service_name} загружен из файла {key_file}")
                return key
    key = get_service_key_from_db(service_name)
    with open(key_file, "wb") as f:
        f.write(key)
    if os.name != 'nt':
        os.chmod(key_file, 0o600)
    print(f"[Service] Ключ сервиса {service_name} сохранён в {key_file}")
    return key

# УПРАВЛЕНИЕ ОТЗОВОМ (ЦЕНТРАЛИЗОВАННОЕ)
class RevocationManager:
    # Менеджер отзыва билетов, использующий DB как единое хранилище.
    def __init__(self, db_host, db_port):
        self.db_host = db_host
        self.db_port = db_port
        self.cache = {}          # {ticket_id: (last_check_time, is_revoked)}
        self.cache_ttl = 60      # кэшировать статус на 60 секунд
        self._lock = threading.Lock()
        print(f"[Service] Инициализирован централизованный RevocationManager (DB={db_host}:{db_port})")

    def _db_request(self, action, **kwargs):
        return _db_request_raw(action, **kwargs)

    def is_revoked(self, ticket_id: str) -> bool:
        # Проверяет, отозван ли билет, с кэшированием.
        with self._lock:
            now = time.time()
            if ticket_id in self.cache:
                last_check, revoked = self.cache[ticket_id]
                if now - last_check < self.cache_ttl:
                    return revoked
            try:
                resp = self._db_request('check_revoked', ticket_id=ticket_id)
                revoked = (resp.get('status') == 'revoked')
                self.cache[ticket_id] = (now, revoked)
                return revoked
            except Exception as e:
                print(f"[Service] Ошибка при проверке отзыва билета {ticket_id}: {e}")
                return False

    def revoke(self, ticket_id: str, expires: int):
        # Отзывает билет (вызывается администратором).
        try:
            self._db_request('revoke_ticket', ticket_id=ticket_id, expires=expires)
            with self._lock:
                self.cache.pop(ticket_id, None)
            print(f"[Service] Билет {ticket_id} отозван через DB")
        except Exception as e:
            print(f"[Service] Ошибка при отзыве билета {ticket_id}: {e}")
            raise

# СЕРВИС
class Service:
    def __init__(self, service_name, service_key, ca_file=CA_CERT):
        self.service_name = service_name
        self.service_key = service_key
        self.ca_file = ca_file
        self.magma = Magma()
        self.used_nonces = {}
        self._lock = threading.Lock()
        self.revocation = RevocationManager(DB_HOST, DB_PORT)   # централизованный менеджер отзыва
        self._start_cleanup_thread()
        print(f"[Service] Инициализация сервиса '{service_name}' завершена")

    def _start_cleanup_thread(self):
        def cleanup_worker():
            while True:
                time.sleep(CLEANUP_INTERVAL)
                with self._lock:
                    now = time.time()
                    to_delete = [k for k, (_, _, ts) in self.used_nonces.items()
                                 if now - ts > SERVICE_TICKET_LIFETIME]
                    if len(self.used_nonces) > MAX_NONCE_CACHE_SIZE:
                        sorted_items = sorted(self.used_nonces.items(), key=lambda x: x[1][2])
                        to_delete += [k for k, _ in sorted_items[:len(self.used_nonces) - MAX_NONCE_CACHE_SIZE]]
                    for k in to_delete:
                        del self.used_nonces[k]
                    if to_delete:
                        print(f"[Service][{self.service_name}] Очистка nonce: удалено {len(to_delete)}")
        threading.Thread(target=cleanup_worker, daemon=True).start()
        print(f"[Service][{self.service_name}] Фоновый поток очистки nonce запущен")

    def _decrypt(self, data: str, key: bytes) -> bytes:
        return decrypt(data, key)

    def _encrypt(self, data: bytes, key: bytes) -> str:
        return encrypt(data, key)

    def verify_request(self, encrypted_ticket, encrypted_authenticator, client_ip, client_cert_cn=None):
        try:
            print(f"[Service][{self.service_name}] === НАЧАЛО ПРОВЕРКИ ЗАПРОСА ===")
            plain_ticket = self._decrypt(encrypted_ticket, self.service_key).decode('utf-8')
            print(f"[Service][{self.service_name}] Расшифрованный билет: {plain_ticket}")
            if not plain_ticket.startswith('ST:'):
                return False, None

            parts = plain_ticket.split(':')
            if len(parts) != 7:
                print(f"[Service][{self.service_name}] Неверный формат билета: {len(parts)} полей (ожидается 7)")
                return False, None

            _, client_name, service_name, expires_str, ssk_hex, ticket_id, ticket_ip = parts
            expires = int(expires_str)
            print(f"[Service][{self.service_name}] Клиент: {client_name}, сервис: {service_name}, срок: {expires}, ID: {ticket_id[:16]}..., IP из билета: {ticket_ip}")

            if ticket_ip != client_ip:
                print(f"[Service][{self.service_name}] IP не совпадает: IP билета={ticket_ip}, текущий IP={client_ip}")
                return False, None

            # Проверка отзыва Service Ticket через централизованный механизм
            if self.revocation.is_revoked(ticket_id):
                print(f"[Service][{self.service_name}] БИЛЕТ ОТОЗВАН: {ticket_id}")
                return False, None
            print(f"[Service][{self.service_name}] Билет не отозван")

            if service_name != self.service_name:
                print(f"[Service][{self.service_name}] Имя сервиса не совпадает: {service_name} != {self.service_name}")
                return False, None

            current_time = time.time()
            if current_time > expires:
                print(f"[Service][{self.service_name}] Билет просрочен (истёк {expires}, сейчас {int(current_time)})")
                return False, None
            print(f"[Service][{self.service_name}] Билет действителен по времени")

            service_session_key = bytes.fromhex(ssk_hex)
            print(f"[Service][{self.service_name}] Сессионный ключ сервиса: {service_session_key.hex()[:16]}...")

            plain_auth = self._decrypt(encrypted_authenticator, service_session_key).decode('utf-8')
            print(f"[Service][{self.service_name}] Расшифрованный аутентификатор: {plain_auth}")
            auth_parts = plain_auth.split(':')
            if len(auth_parts) != 3:
                print(f"[Service][{self.service_name}] Неверный формат аутентификатора: {len(auth_parts)} полей")
                return False, None

            timestamp_str, auth_client_name, nonce = auth_parts
            timestamp = float(timestamp_str)

            if auth_client_name != client_name:
                print(f"[Service][{self.service_name}] Имя клиента не совпадает: {auth_client_name} != {client_name}")
                return False, None

            if abs(current_time - timestamp) > AUTH_TIMEOUT:
                print(f"[Service][{self.service_name}] Аутентификатор просрочен: разница {current_time - timestamp:.2f} сек")
                return False, None

            with self._lock:
                key = f"{client_name}:{nonce}"
                if key in self.used_nonces:
                    print(f"[Service][{self.service_name}] REPLAY АТАКА: nonce {nonce} уже использован")
                    return False, None
                self.used_nonces[key] = (client_name, nonce, current_time)
                print(f"[Service][{self.service_name}] Nonce {nonce} сохранён")

            if client_cert_cn and client_cert_cn != client_name:
                print(f"[Service][{self.service_name}] CN сертификата ({client_cert_cn}) не совпадает с именем клиента ({client_name})")
                return False, None

            verifier_nonce = os.urandom(8).hex()
            verifier_data = f"{current_time}:{client_name}:{verifier_nonce}:{self.service_name}".encode('utf-8')
            verifier = self._encrypt(verifier_data, service_session_key)
            print(f"[Service][{self.service_name}] Сгенерирован верификатор для {client_name}")

            print(f"[Service][{self.service_name}] ДОСТУП РАЗРЕШЁН для {client_name} к {self.service_name}")
            return True, verifier

        except Exception as e:
            print(f"[Service][{self.service_name}] Исключение при проверке: {e}")
            return False, None

    def run(self, host='localhost', port=8890):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        context.load_verify_locations(cafile=self.ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        print(f"[Service][{self.service_name}] TLS контекст создан с требованием клиентского сертификата (mTLS)")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                print(f"[Service][{self.service_name}] Запущен на {host}:{port} (TLS, mTLS включён)")
                while True:
                    conn, addr = ssock.accept()
                    client_ip = addr[0]
                    print(f"[Service][{self.service_name}] Принято соединение от {addr}")

                    # Извлекаем сертификат клиента
                    client_cert = conn.getpeercert()
                    client_cn = None
                    if client_cert:
                        subject = dict(x[0] for x in client_cert['subject'])
                        client_cn = subject.get('commonName')
                        print(f"[Service][{self.service_name}] Клиент предъявил сертификат с CN={client_cn}")
                    else:
                        print(f"[Service][{self.service_name}] ОШИБКА: клиент не предъявил сертификат, но он требуется")
                        conn.close()
                        continue

                    # Обработка запроса в отдельном потоке (чтобы не блокировать accept)
                    threading.Thread(target=self.handle_client, args=(conn, client_ip, client_cn), daemon=True).start()

    def handle_client(self, conn, client_ip, client_cn):
        try:
            data = conn.recv(4096).decode('utf-8')
            print(f"[Service][{self.service_name}] Получен запрос: {data[:200]}")
            req = json.loads(data)
            ticket = req.get('service_ticket')
            authenticator = req.get('authenticator')

            if not ticket or not authenticator:
                resp = json.dumps({'status': 'access_denied', 'error': 'Не хватает данных'})
                print(f"[Service][{self.service_name}] Ошибка: отсутствуют ticket или authenticator")
            else:
                granted, verifier = self.verify_request(ticket, authenticator, client_ip, client_cn)
                if granted:
                    resp = json.dumps({'status': 'access_granted', 'verifier': verifier})
                    print(f"[Service][{self.service_name}] Ответ: доступ разрешён, верификатор отправлен")
                else:
                    resp = json.dumps({'status': 'access_denied', 'error': 'Недействительный билет или аутентификатор'})
                    print(f"[Service][{self.service_name}] Ответ: доступ запрещён")
            conn.sendall(resp.encode('utf-8'))
            print(f"[Service][{self.service_name}] Ответ отправлен клиенту")
        except Exception as e:
            print(f"[Service][{self.service_name}] Исключение при обработке клиента: {e}")
        finally:
            conn.close()

# ЗАПУСК ОБОИХ СЕРВИСОВ
def start_service(service_name, port):
    service_key = load_or_generate_service_key(service_name)
    service = Service(service_name, service_key, ca_file=CA_CERT)
    service.run(port=port)

if __name__ == '__main__':
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print("[Service] ОШИБКА: отсутствуют server.crt или server.key")
        exit(1)

    # Запускаем FileServer на порту 8890
    t1 = threading.Thread(target=start_service, args=("FileServer", 8890), daemon=True)
    t1.start()
    print("[Main] Сервис FileServer запущен на порту 8890")

    # Запускаем MailServer на порту 8891
    t2 = threading.Thread(target=start_service, args=("MailServer", 8891), daemon=True)
    t2.start()
    print("[Main] Сервис MailServer запущен на порту 8891")

    # Держим главный поток живым
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Main] Завершение работы")