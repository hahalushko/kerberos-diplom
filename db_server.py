#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import ssl
import hashlib
import secrets
import os
import base64
import time
import threading
from typing import Dict, Tuple
from magma import Magma

# НАСТРОЙКИ 
SERVER_CERT = "db_server.crt"
SERVER_KEY = "db_server.key"
CA_CERT = "ca.crt"

MASTER_KEY_ENV = "DB_MASTER_KEY"
MASTER_KEY_FILE = "master.key"

PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 16

# Файлы для хранения данных
SERVICE_KEYS_FILE = "service_keys.json"
CLIENT_DB_FILE = "client_db.json"
REVOKED_TICKETS_FILE = "revoked_tickets.json"

REVOKED_CLEANUP_INTERVAL = 600   # 10 минут

SERVICE_NAMES = ["FileServer", "MailServer"]

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
    print("[DB] Argon2 доступен")
except ImportError:
    ARGON2_AVAILABLE = False
    print("[DB] Argon2 не найден, используем PBKDF2")

magma = Magma()

# РАБОТА С МАСТЕР-КЛЮЧОМ
def get_master_key() -> bytes:
    env_key = os.environ.get(MASTER_KEY_ENV)
    if env_key:
        print("[DB] Мастер-ключ загружен из переменной окружения")
        return base64.b64decode(env_key)
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            key = f.read()
            if len(key) == 32:
                print(f"[DB] Мастер-ключ загружен из файла {MASTER_KEY_FILE}")
                return key
    print("[DB] Генерация нового мастер-ключа...")
    new_key = secrets.token_bytes(32)
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(new_key)
    if os.name != 'nt':
        os.chmod(MASTER_KEY_FILE, 0o600)
    print(f"[DB] Мастер-ключ сохранён в {MASTER_KEY_FILE}")
    return new_key

MASTER_KEY = get_master_key()

def encrypt_key(plain_key: bytes) -> str:
    print(f"[DB] Шифрование ключа (длина {len(plain_key)} байт)")
    return magma.encrypt_cbc_with_hmac(plain_key, MASTER_KEY)

def decrypt_key(encrypted_b64: str) -> bytes:
    print("[DB] Расшифровка ключа мастер-ключом")
    return magma.decrypt_cbc_with_hmac(encrypted_b64, MASTER_KEY)

def derive_client_key(password: str, salt: bytes) -> bytes:
    print(f"[DB] Вычисление ключа клиента (пароль ***, соль {salt.hex()[:16]}...)")
    if ARGON2_AVAILABLE:
        key = hash_secret_raw(
            password.encode('utf-8'), salt,
            time_cost=3, memory_cost=65536, parallelism=4,
            hash_len=KEY_LENGTH, type=Type.ID
        )
        print("[DB] Использован Argon2id")
    else:
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                   salt, PBKDF2_ITERATIONS, dklen=KEY_LENGTH)
        print(f"[DB] Использован PBKDF2 (итераций {PBKDF2_ITERATIONS})")
    return key

# УПРАВЛЕНИЕ КЛЮЧАМИ СЕРВИСОВ
def load_service_keys() -> Dict[str, str]:
    # Загружает зашифрованные ключи сервисов из JSON-файла.
    if os.path.exists(SERVICE_KEYS_FILE):
        with open(SERVICE_KEYS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_service_keys(keys: Dict[str, str]):
    # Сохраняет зашифрованные ключи сервисов в JSON-файл.
    with open(SERVICE_KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    if os.name != 'nt':
        os.chmod(SERVICE_KEYS_FILE, 0o600)
    print(f"[DB] Ключи сервисов сохранены в {SERVICE_KEYS_FILE}")

# УПРАВЛЕНИЕ БАЗОЙ ПОЛЬЗОВАТЕЛЕЙ
# username -> (encrypted_client_key, salt_hex, role)
client_db: Dict[str, Tuple[str, str, str]] = {}

def load_client_db():
    # Загружает базу пользователей из JSON-файла.
    global client_db
    if os.path.exists(CLIENT_DB_FILE):
        with open(CLIENT_DB_FILE, "r") as f:
            data = json.load(f)
            # Преобразуем обратно в кортежи
            client_db = {name: (entry['enc_key'], entry['salt'], entry['role'])
                         for name, entry in data.items()}
        print(f"[DB] Загружено {len(client_db)} пользователей из {CLIENT_DB_FILE}")
    else:
        client_db = {}
        print("[DB] Файл базы пользователей не найден, создаётся новый")

def save_client_db():
    # Сохраняет базу пользователей в JSON-файл.
    data = {}
    for name, (enc_key, salt, role) in client_db.items():
        data[name] = {'enc_key': enc_key, 'salt': salt, 'role': role}
    with open(CLIENT_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)
    if os.name != 'nt':
        os.chmod(CLIENT_DB_FILE, 0o600)
    print(f"[DB] Сохранено {len(client_db)} пользователей в {CLIENT_DB_FILE}")

# УПРАВЛЕНИЕ ОТОЗВАННЫМИ БИЛЕТАМИ
# {ticket_id: expires_timestamp}
revoked_tickets: Dict[str, int] = {}

def load_revoked_tickets():
    # Загружает список отозванных билетов из JSON-файла.
    global revoked_tickets
    if os.path.exists(REVOKED_TICKETS_FILE):
        with open(REVOKED_TICKETS_FILE, "r") as f:
            revoked_tickets = json.load(f)
        print(f"[DB] Загружено {len(revoked_tickets)} отозванных билетов")
    else:
        revoked_tickets = {}
        print("[DB] Файл отозванных билетов не найден, создаётся новый")

def save_revoked_tickets():
    # Сохраняет список отозванных билетов в JSON-файл.
    with open(REVOKED_TICKETS_FILE, "w") as f:
        json.dump(revoked_tickets, f)
    if os.name != 'nt':
        os.chmod(REVOKED_TICKETS_FILE, 0o600)
    print(f"[DB] Сохранено {len(revoked_tickets)} отозванных билетов")

def cleanup_expired_revoked():
    # Удаляет записи об отозванных билетах, срок действия которых истёк.
    global revoked_tickets
    now = time.time()
    to_delete = [tid for tid, exp in revoked_tickets.items() if exp < now]
    if to_delete:
        for tid in to_delete:
            del revoked_tickets[tid]
        save_revoked_tickets()
        print(f"[DB] Очистка отозванных билетов: удалено {len(to_delete)} устаревших")

def start_revoked_cleanup_thread():
    # Запускает фоновый поток для периодической очистки отозванных билетов.
    def cleanup_worker():
        while True:
            time.sleep(REVOKED_CLEANUP_INTERVAL)
            cleanup_expired_revoked()
    thread = threading.Thread(target=cleanup_worker, daemon=True)
    thread.start()
    print("[DB] Фоновый поток очистки отозванных билетов запущен")

# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ ПРОВЕРКИ АДМИНИСТРАТОРА
def is_admin_from_conn(conn) -> bool:
    # Проверяет, что клиент предъявил сертификат и его CN имеет роль admin.
    try:
        cert = conn.getpeercert()
        if not cert:
            return False
        # Извлекаем CN
        subject = dict(x[0] for x in cert['subject'])
        cn = subject.get('commonName')
        if not cn:
            return False
        # Проверяем наличие пользователя в client_db и его роль
        if cn in client_db:
            _, _, role = client_db[cn]
            return role == 'admin'
    except Exception as e:
        print(f"[DB] Ошибка при проверке прав администратора: {e}")
    return False

# БАЗА ДАННЫХ (ЗАГРУЗКА НАЧАЛЬНЫХ ДАННЫХ)
load_client_db()
service_keys: Dict[str, str] = load_service_keys()

# Генерация случайных ключей для сервисов, если их ещё нет
for svc in SERVICE_NAMES:
    if svc not in service_keys:
        key_bytes = secrets.token_bytes(16)          # 128-битный ключ
        encrypted = encrypt_key(key_bytes)
        service_keys[svc] = encrypted
        print(f"[DB] Сгенерирован новый случайный ключ для сервиса '{svc}'")
    else:
        print(f"[DB] Ключ для сервиса '{svc}' уже существует, загружен из файла")

save_service_keys(service_keys)

# Загрузка отозванных билетов
load_revoked_tickets()
start_revoked_cleanup_thread()

# СЕРВЕР
class DatabaseServer:
    def __init__(self, certfile=SERVER_CERT, keyfile=SERVER_KEY, cafile=CA_CERT,
                 require_client_cert=False):

        self.certfile = certfile
        self.keyfile = keyfile
        self.cafile = cafile
        self.require_client_cert = require_client_cert
        print(f"[DB] Инициализация: сертификат={certfile}, ключ={keyfile}, CA={cafile}")
        if require_client_cert:
            print("[DB] Режим: клиентский сертификат ОБЯЗАТЕЛЕН")
        else:
            print("[DB] Режим: клиентский сертификат НЕ ТРЕБУЕТСЯ (только для отладки)")

    def run(self, host='localhost', port=9090):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        context.load_verify_locations(cafile=self.cafile)

        if self.require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL
            print("[DB] ВНИМАНИЕ: проверка клиентских сертификатов отключена (небезопасно для production)")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                print(f"[DB] Сервер запущен на {host}:{port} (TLS)")
                while True:
                    try:
                        conn, addr = ssock.accept()
                    except ssl.SSLError as e:
                        print(f"[DB] Ошибка SSL при подключении: {e}")
                        continue
                    except Exception as e:
                        print(f"[DB] Ошибка при accept: {e}")
                        continue
                    conn.settimeout(10)
                    print(f"[DB] Новое соединение от {addr}")
                    with conn:
                        try:
                            data = conn.recv(4096).decode('utf-8')
                            print(f"[DB] Получены данные: {data[:200]}{'...' if len(data)>200 else ''}")
                            req = json.loads(data)
                            action = req.get('action')
                            print(f"[DB] Действие: {action}")

                            # ДЕЙСТВИЯ НЕ ТРЕБУЮЩИЕ АДМИНСКИХ ПРАВ
                            if action == 'get_salt':
                                name = req.get('name')
                                print(f"[DB] Запрос соли для пользователя '{name}'")
                                if name in client_db:
                                    _, salt_hex, _ = client_db[name]
                                    resp = {'status': 'ok', 'salt_hex': salt_hex}
                                    print(f"[DB] Соль найдена: {salt_hex[:16]}...")
                                else:
                                    resp = {'status': 'fail', 'reason': 'user not found'}
                                    print(f"[DB] Пользователь '{name}' не найден")

                            elif action == 'get_client_key':
                                name = req.get('name')
                                print(f"[DB] Запрос зашифрованного ключа клиента '{name}'")
                                if name in client_db:
                                    enc_key, salt_hex, role = client_db[name]
                                    resp = {
                                        'status': 'ok',
                                        'encrypted_client_key': enc_key,
                                        'salt_hex': salt_hex,
                                        'role': role
                                    }
                                    print(f"[DB] Ключ, соль и роль отправлены для {name}")
                                else:
                                    resp = {'status': 'fail', 'reason': 'user not found'}
                                    print(f"[DB] Пользователь '{name}' не найден")

                            elif action == 'register':
                                name = req.get('name')
                                password = req.get('password')
                                role = req.get('role', 'user')
                                print(f"[DB] Регистрация пользователя '{name}' с ролью '{role}'")
                                if not password:
                                    resp = {'status': 'fail', 'reason': 'password required'}
                                    print("[DB] Пароль не указан")
                                elif name in client_db:
                                    resp = {'status': 'fail', 'reason': 'user already exists'}
                                    print(f"[DB] Пользователь '{name}' уже существует")
                                else:
                                    salt = secrets.token_bytes(16)
                                    salt_hex = salt.hex()
                                    print(f"[DB] Сгенерирована соль: {salt_hex[:16]}...")
                                    client_key = derive_client_key(password, salt)
                                    print(f"[DB] Ключ клиента получен: {client_key.hex()[:16]}...")
                                    enc_key = encrypt_key(client_key)
                                    client_db[name] = (enc_key, salt_hex, role)
                                    save_client_db()   # сохраняем изменения
                                    resp = {
                                        'status': 'ok',
                                        'salt_hex': salt_hex
                                    }
                                    print(f"[DB] Пользователь '{name}' зарегистрирован, ключ сохранён, роль={role}")

                            elif action == 'get_role':
                                name = req.get('name')
                                print(f"[DB] Запрос роли пользователя '{name}'")
                                if name in client_db:
                                    _, _, role = client_db[name]
                                    resp = {'status': 'ok', 'role': role}
                                    print(f"[DB] Роль '{role}' для {name}")
                                else:
                                    resp = {'status': 'fail', 'reason': 'user not found'}
                                    print(f"[DB] Пользователь '{name}' не найден")

                            elif action == 'get_service_key':
                                service_name = req.get('service_name')
                                print(f"[DB] Запрос ключа сервиса '{service_name}'")
                                if service_name in service_keys:
                                    resp = {
                                        'status': 'ok',
                                        'encrypted_service_key': service_keys[service_name]
                                    }
                                    print(f"[DB] Ключ сервиса '{service_name}' отправлен")
                                else:
                                    resp = {'status': 'fail', 'reason': 'service not found'}
                                    print(f"[DB] Сервис '{service_name}' не найден")

                            elif action == 'revoke_ticket':
                                ticket_id = req.get('ticket_id')
                                expires = req.get('expires')
                                if not ticket_id or not expires:
                                    resp = {'status': 'fail', 'reason': 'missing ticket_id or expires'}
                                    print("[DB] Ошибка revoke: не указан ticket_id или expires")
                                else:
                                    revoked_tickets[ticket_id] = expires
                                    save_revoked_tickets()
                                    resp = {'status': 'ok'}
                                    print(f"[DB] Билет {ticket_id} отозван до {expires}")

                            elif action == 'check_revoked':
                                ticket_id = req.get('ticket_id')
                                if not ticket_id:
                                    resp = {'status': 'fail', 'reason': 'missing ticket_id'}
                                else:
                                    expires = revoked_tickets.get(ticket_id)
                                    if expires is None:
                                        resp = {'status': 'not_revoked'}
                                    else:
                                        if expires < time.time():
                                            # Запись устарела, удаляем
                                            del revoked_tickets[ticket_id]
                                            save_revoked_tickets()
                                            resp = {'status': 'not_revoked'}
                                            print(f"[DB] Билет {ticket_id} удалён из отозванных (истёк срок)")
                                        else:
                                            resp = {'status': 'revoked', 'expires': expires}
                                            print(f"[DB] Билет {ticket_id} находится в списке отозванных до {expires}")

                            # АДМИНИСТРАТИВНЫЕ ДЕЙСТВИЯ (ТРЕБУЮТ ПРАВА ADMIN)
                            elif action == 'admin_list_users':
                                if not is_admin_from_conn(conn):
                                    resp = {'status': 'fail', 'reason': 'Admin rights required'}
                                else:
                                    users = [{'name': name, 'role': role} for name, (_, _, role) in client_db.items()]
                                    resp = {'status': 'ok', 'users': users}
                                    print(f"[DB] Администратор запросил список пользователей")

                            elif action == 'admin_change_role':
                                if not is_admin_from_conn(conn):
                                    resp = {'status': 'fail', 'reason': 'Admin rights required'}
                                else:
                                    target = req.get('target_name')
                                    new_role = req.get('new_role')
                                    if target not in client_db:
                                        resp = {'status': 'fail', 'reason': 'User not found'}
                                    elif new_role not in ('user', 'admin'):
                                        resp = {'status': 'fail', 'reason': 'Invalid role'}
                                    else:
                                        enc_key, salt, _ = client_db[target]
                                        client_db[target] = (enc_key, salt, new_role)
                                        save_client_db()
                                        resp = {'status': 'ok'}
                                        print(f"[DB] Администратор изменил роль {target} на {new_role}")

                            elif action == 'admin_delete_user':
                                if not is_admin_from_conn(conn):
                                    resp = {'status': 'fail', 'reason': 'Admin rights required'}
                                else:
                                    target = req.get('target_name')
                                    if target not in client_db:
                                        resp = {'status': 'fail', 'reason': 'User not found'}
                                    else:
                                        del client_db[target]
                                        save_client_db()
                                        resp = {'status': 'ok'}
                                        print(f"[DB] Администратор удалил пользователя {target}")

                            elif action == 'admin_list_services':
                                if not is_admin_from_conn(conn):
                                    resp = {'status': 'fail', 'reason': 'Admin rights required'}
                                else:
                                    services = list(service_keys.keys())
                                    resp = {'status': 'ok', 'services': services}
                                    print(f"[DB] Администратор запросил список сервисов")

                            else:
                                resp = {'status': 'fail', 'reason': 'unknown action'}
                                print(f"[DB] Неизвестное действие: {action}")

                            conn.sendall(json.dumps(resp).encode('utf-8'))
                            print(f"[DB] Ответ отправлен, статус: {resp.get('status')}")

                        except socket.timeout:
                            print(f"[DB] Таймаут соединения с {addr}")
                        except json.JSONDecodeError as e:
                            print(f"[DB] Ошибка JSON от {addr}: {e}")
                            try:
                                conn.sendall(json.dumps({'status': 'error', 'reason': 'invalid json'}).encode('utf-8'))
                            except:
                                pass
                        except Exception as e:
                            print(f"[DB] Исключение: {e}")
                            try:
                                conn.sendall(json.dumps({'status': 'error', 'reason': str(e)}).encode('utf-8'))
                            except:
                                pass

if __name__ == '__main__':
    if not os.path.exists(CA_CERT):
        print("[DB] ОШИБКА: отсутствует файл ca.crt")
        exit(1)
    if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
        print("[DB] ОШИБКА: отсутствует сертификат сервера server.crt или ключ server.key")
        exit(1)

    db_server = DatabaseServer(require_client_cert=True)
    db_server.run()