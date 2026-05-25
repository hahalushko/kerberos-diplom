#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import hashlib
import time
import threading
import ssl
import base64
import hmac
import secrets
import os
from magma import Magma

DB_HOST = 'localhost'
DB_PORT = 9090
AUTH_TIMEOUT = 300
TGT_LIFETIME = 3600
CLEANUP_INTERVAL = 600                  # очистка nonce
MAX_NONCE_CACHE_SIZE = 10000

# Пути к сертификатам
SERVER_CERT = "as_server.crt"
SERVER_KEY = "as_server.key"
CA_CERT = "ca.crt"
AS_CERT = "as_client.crt"               # сертификат AS для подключения к DB
AS_KEY = "as_client.key"

# Мастер-ключ (должен совпадать с DB)
MASTER_KEY_ENV = "DB_MASTER_KEY"
MASTER_KEY_FILE = "master.key"

# Файл для хранения ключа TGS
TGS_KEY_FILE = "tgs_key.bin"

# КРИПТО-ФУНКЦИИ
magma = Magma()

def get_master_key() -> bytes:
    env_key = os.environ.get(MASTER_KEY_ENV)
    if env_key:
        print("[AS] Мастер-ключ из переменной окружения")
        return base64.b64decode(env_key)
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) == 32:
                print(f"[AS] Мастер-ключ из файла {MASTER_KEY_FILE}")
                return key
    raise RuntimeError("Мастер-ключ не найден")

MASTER_KEY = get_master_key()

def decrypt_with_master(encrypted_b64: str) -> bytes:
    # Расшифровывает ключ клиента мастер-ключом.
    print("[AS] Расшифровка ключа мастер-ключом...")
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
    print("[AS] Ключ успешно расшифрован")
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

# ЗАГРУЗКА / ГЕНЕРАЦИЯ КЛЮЧА TGS 
def load_or_generate_tgs_key() -> bytes:
    # Загружает 32-байтовый ключ TGS из файла или генерирует новый.
    if os.path.exists(TGS_KEY_FILE):
        with open(TGS_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) == 32:
                print("[AS] Ключ TGS загружен из файла")
                return key
    # Генерация нового ключа
    new_key = secrets.token_bytes(32)
    with open(TGS_KEY_FILE, "wb") as f:
        f.write(new_key)
    if os.name != 'nt':
        os.chmod(TGS_KEY_FILE, 0o600)
    print(f"[AS] Сгенерирован новый ключ TGS и сохранён в {TGS_KEY_FILE}")
    return new_key

TGS_KEY = load_or_generate_tgs_key()

# РАБОТА С БАЗОЙ ДАННЫХ
def _db_request_raw(action, **kwargs):
    # Универсальный запрос к DB с использованием клиентского сертификата AS.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.check_hostname = False
    if os.path.exists(AS_CERT) and os.path.exists(AS_KEY):
        context.load_cert_chain(certfile=AS_CERT, keyfile=AS_KEY)
        print("[AS] Загружен клиентский сертификат для подключения к DB")
    else:
        print("[AS] Клиентский сертификат не найден, продолжаем без него")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        with context.wrap_socket(sock, server_hostname=DB_HOST) as ssock:
            ssock.connect((DB_HOST, DB_PORT))
            req = json.dumps({'action': action, **kwargs})
            print(f"[AS] Отправка запроса к DB: {req}")
            ssock.sendall(req.encode('utf-8'))
            resp = json.loads(ssock.recv(4096).decode('utf-8'))
            print(f"[AS] Ответ DB: статус={resp.get('status')}")
            return resp

def get_client_key_from_db(name: str) -> bytes:
    # Запрашивает у DB зашифрованный ключ клиента, расшифровывает мастер-ключом.
    print(f"[AS] Запрос ключа клиента {name} к DB...")
    resp = _db_request_raw('get_client_key', name=name)
    if resp['status'] == 'ok':
        enc_key = resp['encrypted_client_key']
        client_key = decrypt_with_master(enc_key)
        print(f"[AS] Ключ клиента {name} получен: {client_key.hex()[:16]}...")
        return client_key
    else:
        raise ValueError(resp.get('reason', 'Пользователь не найден'))

def register_user_in_db(name: str, password: str, role: str = 'user') -> bytes:
    # Регистрирует пользователя через DB, возвращает соль.
    print(f"[AS] Регистрация пользователя {name} с ролью {role} через DB...")
    resp = _db_request_raw('register', name=name, password=password, role=role)
    if resp['status'] == 'ok':
        salt = bytes.fromhex(resp['salt_hex'])
        print(f"[AS] Пользователь {name} зарегистрирован, соль: {salt.hex()[:16]}...")
        return salt
    else:
        raise ValueError(resp.get('reason', 'Ошибка регистрации'))

def get_salt_from_db(name: str) -> bytes:
    # Получает соль пользователя из DB.
    print(f"[AS] Запрос соли для {name}...")
    resp = _db_request_raw('get_salt', name=name)
    if resp['status'] == 'ok':
        salt = bytes.fromhex(resp['salt_hex'])
        print(f"[AS] Соль получена: {salt.hex()[:16]}...")
        return salt
    else:
        raise ValueError(resp.get('reason', 'Пользователь не найден'))

def get_role_from_db(name: str) -> str:
    # Получает роль пользователя из DB.
    print(f"[AS] Запрос роли для {name}...")
    resp = _db_request_raw('get_role', name=name)
    if resp['status'] == 'ok':
        role = resp['role']
        print(f"[AS] Роль пользователя {name}: {role}")
        return role
    else:
        raise ValueError(resp.get('reason', 'Пользователь не найден'))

# УПРАВЛЕНИЕ ОТЗОВОМ (ЦЕНТРАЛИЗОВАННОЕ)
class RevocationManager:
    # Менеджер отзыва билетов, использующий DB как единое хранилище.
    def __init__(self, db_host, db_port):
        self.db_host = db_host
        self.db_port = db_port
        self.cache = {}          # {ticket_id: (last_check_time, is_revoked)}
        self.cache_ttl = 60      # кэшировать статус на 60 секунд
        self._lock = threading.Lock()
        print(f"[AS] Инициализирован централизованный RevocationManager (DB={db_host}:{db_port})")

    def _db_request(self, action, **kwargs):
        # Выполняет запрос к DB (обёртка над глобальной функцией с теми же сертификатами).
        return _db_request_raw(action, **kwargs)

    def is_revoked(self, ticket_id: str) -> bool:
        # Проверяет, отозван ли билет, с кэшированием.
        with self._lock:
            now = time.time()
            # Проверяем кэш
            if ticket_id in self.cache:
                last_check, revoked = self.cache[ticket_id]
                if now - last_check < self.cache_ttl:
                    return revoked
            # Запрос к DB
            try:
                resp = self._db_request('check_revoked', ticket_id=ticket_id)
                if resp.get('status') == 'revoked':
                    revoked = True
                else:
                    revoked = False
                self.cache[ticket_id] = (now, revoked)
                return revoked
            except Exception as e:
                print(f"[AS] Ошибка при проверке отзыва билета {ticket_id}: {e}")
                return False

    def revoke(self, ticket_id: str, expires: int):
        # Отзывает билет (вызывается администратором).
        try:
            self._db_request('revoke_ticket', ticket_id=ticket_id, expires=expires)
            with self._lock:
                self.cache.pop(ticket_id, None)
            print(f"[AS] Билет {ticket_id} отозван через DB")
        except Exception as e:
            print(f"[AS] Ошибка при отзыве билета {ticket_id}: {e}")
            raise

# AS СЕРВЕР
class AS:
    def __init__(self, tgs_key, db_host, db_port,
                 certfile=SERVER_CERT, keyfile=SERVER_KEY, ca_file=CA_CERT):
        self.tgs_key = tgs_key
        self.db_host = db_host
        self.db_port = db_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.ca_file = ca_file
        self.magma = Magma()
        self.tgs_key_32 = hashlib.sha256(tgs_key).digest()
        self.used_nonces = {}
        self._lock = threading.Lock()
        self.revocation = RevocationManager(db_host, db_port)   # централизованный менеджер отзыва
        self._start_cleanup_thread()
        print("[AS] Инициализация завершена")

    def _start_cleanup_thread(self):
        def cleanup_worker():
            while True:
                time.sleep(CLEANUP_INTERVAL)
                with self._lock:
                    now = time.time()
                    to_delete = [k for k, (_, _, ts) in self.used_nonces.items()
                                 if now - ts > AUTH_TIMEOUT]
                    if len(self.used_nonces) > MAX_NONCE_CACHE_SIZE:
                        sorted_items = sorted(self.used_nonces.items(), key=lambda x: x[1][2])
                        to_delete += [k for k, _ in sorted_items[:len(self.used_nonces) - MAX_NONCE_CACHE_SIZE]]
                    for k in to_delete:
                        del self.used_nonces[k]
                    if to_delete:
                        print(f"[AS] Очистка кэша nonce: удалено {len(to_delete)}")
        threading.Thread(target=cleanup_worker, daemon=True).start()
        print("[AS] Фоновый поток очистки nonce запущен")

    def _encrypt(self, data: bytes, key: bytes) -> str:
        return encrypt(data, key)

    def _decrypt(self, data: str, key: bytes) -> bytes:
        return decrypt(data, key)

    def issue_tgt(self, client_name, authenticator, client_ip):
        print(f"[AS] === НАЧАЛО ВЫДАЧИ TGT для {client_name} (IP={client_ip}) ===")
        client_key = get_client_key_from_db(client_name)
        print("[AS] Ключ клиента получен, проверяем аутентификатор...")

        try:
            plain_auth = self._decrypt(authenticator, client_key).decode('utf-8')
            print(f"[AS] Расшифрованный аутентификатор: {plain_auth}")
            parts = plain_auth.split(':')
            if len(parts) != 3:
                raise ValueError("Формат: timestamp:client_name:nonce")
            timestamp_str, auth_name, nonce = parts
            timestamp = float(timestamp_str)

            if auth_name != client_name:
                raise ValueError(f"Имя в аутентификаторе {auth_name} != {client_name}")
            now = time.time()
            if abs(now - timestamp) > AUTH_TIMEOUT:
                raise ValueError(f"Аутентификатор просрочен: разница {now - timestamp:.2f} сек")

            with self._lock:
                key = f"{client_name}:{nonce}"
                if key in self.used_nonces:
                    raise ValueError("Replay атака (nonce уже использован)")
                self.used_nonces[key] = (client_name, nonce, now)
                print(f"[AS] Nonce {nonce} сохранён, предотвращение replay")

        except Exception as e:
            print(f"[AS] Ошибка аутентификатора: {e}")
            raise ValueError(f"Ошибка аутентификатора: {e}")

        session_key = secrets.token_bytes(16)
        ticket_id = secrets.token_hex(16)
        expires = int(time.time() + TGT_LIFETIME)
        print(f"[AS] Сгенерирован сессионный ключ: {session_key.hex()[:16]}...")
        print(f"[AS] TGT будет действовать до {expires}, ticket_id={ticket_id[:16]}...")

        tgt_data = f"TGT:{client_name}:{expires}:{session_key.hex()}:{ticket_id}:{client_ip}".encode('utf-8')
        encrypted_tgt = self._encrypt(tgt_data, self.tgs_key)
        encrypted_session_key = self._encrypt(session_key, client_key)

        print("[AS] TGT и зашифрованный сессионный ключ отправлены клиенту")
        return encrypted_session_key, encrypted_tgt

    def handle_register(self, name, password, role='user'):
        # Обработка запроса регистрации от клиента.
        print(f"[AS] === РЕГИСТРАЦИЯ пользователя {name} с ролью {role} ===")
        try:
            salt = register_user_in_db(name, password, role)
            return {'status': 'ok', 'salt_hex': salt.hex()}
        except Exception as e:
            return {'status': 'fail', 'reason': str(e)}

    def handle_get_salt(self, name):
        # Обработка запроса соли от клиента.
        print(f"[AS] === ЗАПРОС СОЛИ для {name} ===")
        try:
            salt = get_salt_from_db(name)
            return {'status': 'ok', 'salt_hex': salt.hex()}
        except Exception as e:
            return {'status': 'fail', 'reason': str(e)}

    def handle_get_role(self, name):
        # Обработка запроса роли от клиента.
        print(f"[AS] === ЗАПРОС РОЛИ для {name} ===")
        try:
            role = get_role_from_db(name)
            return {'status': 'ok', 'role': role}
        except Exception as e:
            return {'status': 'fail', 'reason': str(e)}

    def handle_revoke_ticket(self, ticket_id, expires):
        # Обработка запроса отзыва билета (только для администраторов).
        print(f"[AS] === ОТЗЫВ БИЛЕТА {ticket_id} ===")
        try:
            self.revocation.revoke(ticket_id, expires)
            return {'status': 'ok'}
        except Exception as e:
            return {'status': 'fail', 'reason': str(e)}

    def run(self, host='localhost', port=8888):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        context.verify_mode = ssl.CERT_OPTIONAL
        print(f"[AS] TLS контекст создан, сертификат {self.certfile}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen()
            with context.wrap_socket(sock, server_side=True) as ssock:
                print(f"[AS] Сервер запущен на {host}:{port} (TLS)")
                while True:
                    conn, addr = ssock.accept()
                    client_ip = addr[0]
                    print(f"[AS] Принято соединение от {addr}")
                    with conn:
                        try:
                            data = conn.recv(4096).decode('utf-8')
                            print(f"[AS] Получен запрос: {data[:200]}")
                            req = json.loads(data)
                            action = req.get('action')
                            if action == 'register':
                                name = req.get('name')
                                password = req.get('password')
                                role = req.get('role', 'user')
                                if not name or not password:
                                    resp = {'error': 'Не указано имя или пароль'}
                                else:
                                    resp = self.handle_register(name, password, role)
                            elif action == 'get_salt':
                                name = req.get('name')
                                if not name:
                                    resp = {'error': 'Не указано имя'}
                                else:
                                    resp = self.handle_get_salt(name)
                            elif action == 'get_role':
                                name = req.get('name')
                                if not name:
                                    resp = {'error': 'Не указано имя'}
                                else:
                                    resp = self.handle_get_role(name)
                            elif action == 'revoke_ticket':
                                ticket_id = req.get('ticket_id')
                                expires = req.get('expires')
                                if not ticket_id or not expires:
                                    resp = {'error': 'Не указан ticket_id или expires'}
                                else:
                                    resp = self.handle_revoke_ticket(ticket_id, expires)
                            else:
                                # Старый формат запроса TGT (name + authenticator)
                                client_name = req.get('name')
                                authenticator = req.get('authenticator')
                                if client_name and authenticator:
                                    enc_session_key, tgt = self.issue_tgt(client_name, authenticator, client_ip)
                                    resp = json.dumps({
                                        'encrypted_session_key': enc_session_key,
                                        'tgt': tgt
                                    })
                                    conn.sendall(resp.encode('utf-8'))
                                    print("[AS] Ответ (TGT) отправлен клиенту")
                                    continue
                                else:
                                    resp = {'error': 'Неизвестный запрос'}
                            # Отправка ответа для action-запросов
                            conn.sendall(json.dumps(resp).encode('utf-8'))
                            print("[AS] Ответ отправлен клиенту")
                        except Exception as e:
                            print(f"[AS] Исключение: {e}")
                            conn.sendall(json.dumps({'error': str(e)}).encode('utf-8'))

if __name__ == '__main__':
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print("[AS] ОШИБКА: отсутствуют server.crt или server.key")
        exit(1)
    as_server = AS(TGS_KEY, DB_HOST, DB_PORT)
    as_server.run()