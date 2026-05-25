#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json
import ssl
import argparse
import sys
import time
import os

DB_HOST = 'localhost'
DB_PORT = 9090
CA_CERT = "ca.crt"
ADMIN_CERT = "admin.crt"      # сертификат администратора
ADMIN_KEY = "admin.key"        # ключ администратора


# ФУНКЦИИ ВЗАИМОДЕЙСТВИЯ С СЕРВЕРАМИ
def send_db_request(action, **kwargs):
    # Отправляет запрос к DB с использованием сертификата администратора.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile=CA_CERT)
    context.load_cert_chain(certfile=ADMIN_CERT, keyfile=ADMIN_KEY)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        with context.wrap_socket(sock, server_hostname=DB_HOST) as ssock:
            ssock.connect((DB_HOST, DB_PORT))
            req = json.dumps({'action': action, **kwargs})
            print(f"[Admin] Отправка запроса к DB: {req}")
            ssock.sendall(req.encode('utf-8'))
            resp_data = ssock.recv(8192).decode('utf-8')
            print(f"[Admin] Ответ DB: {resp_data[:200]}...")
            return json.loads(resp_data)

# КОМАНДЫ УПРАВЛЕНИЯ
def cmd_list_users():
    # Показать всех пользователей и их роли.
    resp = send_db_request('admin_list_users')
    if resp.get('status') == 'ok':
        users = resp.get('users', [])
        if not users:
            print("Нет зарегистрированных пользователей.")
        else:
            print("Список пользователей:")
            print(f"{'Имя':<20} {'Роль':<10}")
            print("-" * 30)
            for u in users:
                print(f"{u['name']:<20} {u['role']:<10}")
    else:
        print(f"Ошибка: {resp.get('reason', 'неизвестная ошибка')}")

def cmd_change_role(username, new_role):
    # Изменить роль пользователя.
    if new_role not in ('user', 'admin'):
        print("Ошибка: роль должна быть 'user' или 'admin'")
        return
    resp = send_db_request('admin_change_role', target_name=username, new_role=new_role)
    if resp.get('status') == 'ok':
        print(f"Роль пользователя '{username}' изменена на '{new_role}'.")
    else:
        print(f"Ошибка: {resp.get('reason', 'неизвестная ошибка')}")

def cmd_delete_user(username):
    # Удалить пользователя.
    confirm = input(f"Вы действительно хотите удалить пользователя '{username}'? (y/N): ")
    if confirm.lower() != 'y':
        print("Операция отменена.")
        return
    resp = send_db_request('admin_delete_user', target_name=username)
    if resp.get('status') == 'ok':
        print(f"Пользователь '{username}' удалён.")
    else:
        print(f"Ошибка: {resp.get('reason', 'неизвестная ошибка')}")

def cmd_list_services():
    # Показать зарегистрированные сервисы.
    resp = send_db_request('admin_list_services')
    if resp.get('status') == 'ok':
        services = resp.get('services', [])
        if not services:
            print("Нет зарегистрированных сервисов.")
        else:
            print("Зарегистрированные сервисы:")
            for s in services:
                print(f"  - {s}")
    else:
        print(f"Ошибка: {resp.get('reason', 'неизвестная ошибка')}")

def cmd_revoke_ticket(ticket_id, expires):
    # Отозвать билет по ID и времени истечения.
    if not ticket_id:
        print("Ошибка: необходимо указать ticket_id")
        return
    if not expires:
        print("Ошибка: необходимо указать expires (timestamp)")
        return
    resp = send_db_request('revoke_ticket', ticket_id=ticket_id, expires=expires)
    if resp.get('status') == 'ok':
        print(f"Билет {ticket_id} успешно отозван.")
    else:
        print(f"Ошибка: {resp.get('reason', 'неизвестная ошибка')}")


# ОСНОВНОЙ ПАРСЕР
def main():
    parser = argparse.ArgumentParser(
        description='Административный клиент Kerberos',
        epilog='Примеры:\n'
               '  python admin_client.py list-users\n'
               '  python admin_client.py change-role bob admin\n'
               '  python admin_client.py delete-user alice\n'
               '  python admin_client.py list-services\n'
               '  python admin_client.py revoke-ticket --ticket-id abc123 --expires 1712345678'
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='Доступные команды')

    # list-users
    subparsers.add_parser('list-users', help='Показать всех пользователей')

    # change-role
    p_change = subparsers.add_parser('change-role', help='Изменить роль пользователя')
    p_change.add_argument('username', help='Имя пользователя')
    p_change.add_argument('role', choices=['user', 'admin'], help='Новая роль')

    # delete-user
    p_del = subparsers.add_parser('delete-user', help='Удалить пользователя')
    p_del.add_argument('username', help='Имя пользователя')

    # list-services
    subparsers.add_parser('list-services', help='Показать все сервисы')

    # revoke-ticket
    p_revoke = subparsers.add_parser('revoke-ticket', help='Отозвать билет')
    p_revoke.add_argument('--ticket-id', required=True, help='Идентификатор билета')
    p_revoke.add_argument('--expires', type=int, required=True, help='Время истечения (unix timestamp)')

    args = parser.parse_args()

    if args.command == 'list-users':
        cmd_list_users()
    elif args.command == 'change-role':
        cmd_change_role(args.username, args.role)
    elif args.command == 'delete-user':
        cmd_delete_user(args.username)
    elif args.command == 'list-services':
        cmd_list_services()
    elif args.command == 'revoke-ticket':
        cmd_revoke_ticket(args.ticket_id, args.expires)
    else:
        parser.print_help()

if __name__ == '__main__':
    # Проверка наличия сертификата администратора
    if not os.path.exists(ADMIN_CERT) or not os.path.exists(ADMIN_KEY):
        print(f"[Admin] ОШИБКА: отсутствуют файлы сертификата администратора: {ADMIN_CERT} и {ADMIN_KEY}")
        print("Пожалуйста, получите сертификат администратора и поместите его в текущую директорию.")
        sys.exit(1)
    if not os.path.exists(CA_CERT):
        print(f"[Admin] ОШИБКА: отсутствует CA сертификат {CA_CERT}")
        sys.exit(1)

    main()


# Просмотр пользователей
# python admin_client.py list-users

# Смена роли пользователя john на admin
# python admin_client.py change-role john admin

# Удаление пользователя alice (с подтверждением)
# python admin_client.py delete-user alice

# Список сервисов
# python admin_client.py list-services

# Отзыв билета
# python admin_client.py revoke-ticket --ticket-id a1b2c3d4e5f6... --expires 1712345678