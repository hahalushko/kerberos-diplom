#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import hashlib
import time
import threading
import ssl
import secrets
import base64
import hmac
import os
from magma import Magma

# НАСТРОЙКИ
DB_HOST = 'localhost'
DB_PORT = 9090
AUTH_TIMEOUT = 300
SERVICE_TICKET_LIFETIME = 600
CLEANUP_INTERVAL = 600
MAX_NONCE_CACHE_SIZE = 10000

# Пути к сертификатам
SERVER_CERT = "tgs_server.crt"
SERVER_KEY = "tgs_server.key"
CA_CERT = "ca.crt"
TGS_CERT = "tgs_client.crt"             # Сертификат TGS для подключения к DB
TGS_KEYFILE = "tgs_client.key"

# Мастер-ключ (должен совпадать с DB)
MASTER_KEY_ENV = "DB_MASTER_KEY"
MASTER_KEY_FILE = "master.key"

# Файл для хранения ключа TGS (общий с AS)
TGS_KEY_FILE = "tgs_key.bin"

# КРИПТО-ФУНКЦИИ
magma = Magma()

def get_master_key() -> bytes:
    env_key = os.environ.get(MASTER_KEY_ENV)
    if env_key:
        print("[TGS] Мастер-ключ из переменной окружения")
        return base64.b64decode(env_key)
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) == 32:
                print(f"[TGS] Мастер-ключ из файла {MASTER_KEY_FILE}")
                return key
    raise RuntimeError("Мастер-ключ не найден")

MASTER_KEY = get_master_key()

def decrypt_with_master(encrypted_b64: str) -> bytes:
    print("[TGS] Расшифровка ключа мастер-ключом...")
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
    print("[TGS] Ключ успешно расшифрован")
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
    if os.path.exists(TGS_KEY_FILE):
        with open(TGS_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) == 32:
                print("[TGS] Ключ TGS загружен из файла")
                return key
    new_key = secrets.token_bytes(32)
    with open(TGS_KEY_FILE, "wb") as f:
        f.write(new_key)
    if os.name != 'nt':
        os.chmod(TGS_KEY_FILE, 0o600)
    print(f"[TGS] Сгенерирован новый ключ TGS и сохранён в {TGS_KEY_FILE}")
    return new_key

TGS_KEY = load_or_generate_tgs_key()

# РАБОТА С БАЗОЙ ДАННЫХ
def _db_request_raw(action, **kwargs):
    # Универсальный запрос к DB с использованием клиентского сертификата TGS.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.check_hostname = False
    if os.path.exists(TGS_CERT) and os.path.exists(TGS_KEYFILE):
        context.load_cert_chain(certfile=TGS_CERT, keyfile=TGS_KEYFILE)
        print("[TGS] Загружен клиентский сертификат для подключения к DB")
    else:
        print("[TGS] Клиентский сертификат не найден, продолжаем без него")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        with context.wrap_socket(sock, server_hostname=DB_HOST) as ssock:
            ssock.connect((DB_HOST, DB_PORT))
            req = json.dumps({'action': action, **kwargs})
            print(f"[TGS] Отправка запроса к DB: {req}")
            ssock.sendall(req.encode('utf-8'))
            resp = json.loads(ssock.recv(4096).decode('utf-8'))
            print(f"[TGS] Ответ DB: статус={resp.get('status')}")
            return resp

def get_service_key_from_db(service_name: str) -> bytes:
    # Запрашивает у DB зашифрованный ключ сервиса, расшифровывает мастер-ключом.
    print(f"[TGS] Запрос ключа сервиса {service_name} к DB...")
    resp = _db_request_raw('get_service_key', service_name=service_name)
    if resp['status'] == 'ok':
        enc_key = resp['encrypted_service_key']
        service_key = decrypt_with_master(enc_key)
        print(f"[TGS] Ключ сервиса {service_name} получен: {service_key.hex()[:16]}...")
        return service_key
    else:
        raise ValueError(resp.get('reason', 'Сервис не найден'))

def get_user_role_from_db(name: str) -> str:
    # Запрашивает роль пользователя из DB.
    print(f"[TGS] Запрос роли пользователя {name}...")
    resp = _db_request_raw('get_role', name=name)
    if resp['status'] == 'ok':
        return resp['role']
    else:
        raise ValueError(resp.get('reason', 'Роль не найдена'))

# УПРАВЛЕНИЕ ОТЗОВОМ (ЦЕНТРАЛИЗОВАННОЕ)
class RevocationManager:
    # Менеджер отзыва билетов, использующий DB как единое хранилище.
    def __init__(self, db_host, db_port):
        self.db_host = db_host
        self.db_port = db_port
        self.cache = {}          # {ticket_id: (last_check_time, is_revoked)}
        self.cache_ttl = 60      # кэшировать статус на 60 секунд
        self._lock = threading.Lock()
        print(f"[TGS] Инициализирован централизованный RevocationManager (DB={db_host}:{db_port})")

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
                print(f"[TGS] Ошибка при проверке отзыва билета {ticket_id}: {e}")
                return False

    def revoke(self, ticket_id: str, expires: int):
        # Отзывает билет (вызывается администратором).
        try:
            self._db_request('revoke_ticket', ticket_id=ticket_id, expires=expires)
            with self._lock:
                self.cache.pop(ticket_id, None)
            print(f"[TGS] Билет {ticket_id} отозван через DB")
        except Exception as e:
            print(f"[TGS] Ошибка при отзыве билета {ticket_id}: {e}")
            raise

# TGS СЕРВЕР
class TGS:
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
        print("[TGS] Инициализация завершена")

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
                        print(f"[TGS] Очистка nonce: удалено {len(to_delete)}")
        threading.Thread(target=cleanup_worker, daemon=True).start()
        print("[TGS] Фоновый поток очистки nonce запущен")

    def _encrypt(self, data: bytes, key: bytes) -> str:
        return encrypt(data, key)

    def _decrypt(self, data: str, key: bytes) -> bytes:
        return decrypt(data, key)

    def issue_service_ticket(self, encrypted_tgt, authenticator, service_name, client_ip, client_cert_cn=None):
        print("[TGS] === НАЧАЛО ВЫДАЧИ SERVICE TICKET ===")

        # 1. Расшифровка TGT (формат с IP: 6 полей)
        print("[TGS] Расшифровка TGT...")
        plain_tgt = self._decrypt(encrypted_tgt, self.tgs_key).decode('utf-8')
        print(f"[TGS] Расшифрованный TGT: {plain_tgt}")
        if not plain_tgt.startswith('TGT:'):
            raise ValueError("Неверный TGT")
        parts = plain_tgt.split(':')
        if len(parts) != 6:
            raise ValueError("Неверный формат TGT, ожидается 6 полей (с IP)")
        _, client_name_tgt, expires_str, session_key_hex, tgt_id, tgt_ip = parts
        expires = int(expires_str)
        print(f"[TGS] Клиент: {client_name_tgt}, срок TGT: {expires}, TGT_ID: {tgt_id[:16]}..., IP из TGT: {tgt_ip}")

        # Проверка IP клиента
        if tgt_ip != client_ip:
            raise ValueError(f"IP не совпадает: TGT IP={tgt_ip}, текущий IP={client_ip}")

        # Проверка отзыва TGT через централизованный механизм
        if self.revocation.is_revoked(tgt_id):
            raise ValueError("TGT отозван")
        print("[TGS] TGT не отозван")

        current_time = time.time()
        if current_time > expires:
            raise ValueError(f"TGT просрочен (истёк {expires}, сейчас {int(current_time)})")
        print("[TGS] TGT действителен")

        session_key = bytes.fromhex(session_key_hex)
        print(f"[TGS] Сессионный ключ из TGT: {session_key.hex()[:16]}...")

        # 2. Расшифровка аутентификатора
        print("[TGS] Расшифровка аутентификатора...")
        plain_auth = self._decrypt(authenticator, session_key).decode('utf-8')
        print(f"[TGS] Расшифрованный аутентификатор: {plain_auth}")
        auth_parts = plain_auth.split(':')
        if len(auth_parts) != 3:
            raise ValueError("Аутентификатор должен быть timestamp:client_name:nonce")
        timestamp_str, auth_name, nonce = auth_parts
        timestamp = float(timestamp_str)

        if auth_name != client_name_tgt:
            raise ValueError(f"Имя в аутентификаторе {auth_name} != {client_name_tgt}")

        if abs(current_time - timestamp) > AUTH_TIMEOUT:
            raise ValueError(f"Аутентификатор просрочен: разница {current_time - timestamp:.2f} сек")

        with self._lock:
            key = f"{client_name_tgt}:{nonce}"
            if key in self.used_nonces:
                raise ValueError("Replay атака (nonce уже использован)")
            self.used_nonces[key] = (client_name_tgt, nonce, current_time)
        print(f"[TGS] Nonce {nonce} принят")

        # 3. Проверка клиентского сертификата (если предоставлен)
        if client_cert_cn:
            if client_cert_cn != client_name_tgt:
                raise ValueError(f"Имя в сертификате ({client_cert_cn}) не совпадает с именем пользователя ({client_name_tgt})")
            print("[TGS] Сертификат клиента проверен, CN совпадает")
        else:
            print("[TGS] ВНИМАНИЕ: клиент не предъявил сертификат, но TGS настроен на его требование. Отказ.")
            raise ValueError("Клиентский сертификат обязателен")

        # 4. Получение роли пользователя и проверка доступа к сервису
        try:
            user_role = get_user_role_from_db(client_name_tgt)
            print(f"[TGS] Роль пользователя {client_name_tgt}: {user_role}")
        except Exception as e:
            raise ValueError(f"Не удалось получить роль пользователя: {e}")

        # Проверка прав доступа
        if user_role == 'admin':
            print(f"[TGS] Администратору разрешён доступ к сервису {service_name}")
        elif user_role == 'user':
            if service_name != 'MailServer':
                raise ValueError(f"Обычному пользователю запрещён доступ к сервису {service_name}. Разрешён только MailServer.")
            print(f"[TGS] Обычному пользователю разрешён доступ к {service_name}")
        else:
            raise ValueError(f"Неизвестная роль {user_role}")

        # 5. Получение ключа сервиса из DB
        service_key = get_service_key_from_db(service_name)

        # 6. Генерация нового сессионного ключа для сервиса и ticket_id
        service_session_key = secrets.token_bytes(16)
        st_id = secrets.token_hex(16)
        st_expires = int(current_time + SERVICE_TICKET_LIFETIME)
        print(f"[TGS] Сгенерирован ключ для сервиса: {service_session_key.hex()[:16]}...")
        print(f"[TGS] Service Ticket ID: {st_id[:16]}..., истекает {st_expires}")

        # 7. Создание Service Ticket (с IP-адресом клиента - 7 полей)
        st_data = f"ST:{client_name_tgt}:{service_name}:{st_expires}:{service_session_key.hex()}:{st_id}:{client_ip}".encode('utf-8')
        encrypted_st = self._encrypt(st_data, service_key)

        # 8. Шифрование service_session_key для клиента
        encrypted_service_session_key = self._encrypt(service_session_key, session_key)

        print("[TGS] Service Ticket и ключ отправлены клиенту")
        return encrypted_st, encrypted_service_session_key

    def run(self, host='localhost', port=8889):
        # Создаём TLS контекст с требованием клиентского сертификата (mTLS)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        context.load_verify_locations(cafile=self.ca_file)
        context.verify_mode = ssl.CERT_REQUIRED   # Требуем сертификат от клиента
        context.check_hostname = False            # Отключаем проверку имени хоста
        print("[TGS] TLS контекст создан с требованием клиентского сертификата (mTLS)")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen()
            with context.wrap_socket(sock, server_side=True) as ssock:
                print(f"[TGS] Сервер запущен на {host}:{port} (TLS, mTLS включён)")
                while True:
                    try:
                        conn, addr = ssock.accept()
                    except ssl.SSLError as e:
                        print(f"[TGS] Ошибка SSL при подключении: {e}")
                        continue
                    except Exception as e:
                        print(f"[TGS] Ошибка при accept: {e}")
                        continue
                    client_ip = addr[0]
                    print(f"[TGS] Принято соединение от {addr}")

                    # Получаем сертификат клиента
                    client_cert = conn.getpeercert()
                    client_cn = None
                    if client_cert:
                        subject = dict(x[0] for x in client_cert['subject'])
                        client_cn = subject.get('commonName')
                        print(f"[TGS] Клиент предъявил сертификат с CN={client_cn}")
                    else:
                        print("[TGS] ОШИБКА: клиент не предъявил сертификат, но он требуется")
                        conn.close()
                        continue

                    with conn:
                        data = conn.recv(4096).decode('utf-8')
                        print(f"[TGS] Получен запрос: {data[:200]}")
                        try:
                            req = json.loads(data)
                            tgt = req.get('tgt')
                            authenticator = req.get('authenticator')
                            service_name = req.get('service_name')
                            if tgt and authenticator and service_name:
                                st, enc_ssk = self.issue_service_ticket(tgt, authenticator, service_name, client_ip, client_cn)
                                resp = json.dumps({
                                    'service_ticket': st,
                                    'encrypted_service_session_key': enc_ssk
                                })
                                conn.sendall(resp.encode('utf-8'))
                                print("[TGS] Ответ отправлен клиенту")
                            else:
                                conn.sendall(json.dumps({'error': 'Не хватает полей'}).encode('utf-8'))
                                print("[TGS] Отсутствуют необходимые поля")
                        except Exception as e:
                            print(f"[TGS] Исключение: {e}")
                            conn.sendall(json.dumps({'error': str(e)}).encode('utf-8'))

if __name__ == '__main__':
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print("[TGS] ОШИБКА: отсутствуют server.crt или server.key")
        exit(1)
    tgs = TGS(TGS_KEY, DB_HOST, DB_PORT)
    tgs.run()