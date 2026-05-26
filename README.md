# Kerberos System with Magma cipher

## Требования
- Python 3.9+
- OpenSSL (для генерации сертификатов, но они уже есть в репозитории)

## Установка
1. Клонируйте репозиторий
2. Установите зависимости: `pip install -r requirements.txt`

## Запуск (в отдельных терминалах)
1. `python db_server.py` (порт 9090)
2. `python as_server.py` (порт 8888)
3. `python tgs_server.py` (порт 8889)
4. `python service_server.py` (порты 8890, 8891)
5. `python client.py` – интерактивный клиент

## Администрирование
`python admin_client.py list-users`

### Просмотр пользователей
`python admin_client.py list-users`

### Смена роли пользователя john на admin
`python admin_client.py change-role john admin`

### Удаление пользователя alice (с подтверждением)
`python admin_client.py delete-user alice`

### Список сервисов
`python admin_client.py list-services`

### Отзыв билета
`python admin_client.py revoke-ticket --ticket-id a1b2c3d4e5f6... --expires 1712345678`

## Примечание
Все сертификаты (`.crt`) уже включены в репозиторий. Ключи (`.key`) необходимо поместить в ту же папку. Для тестирования вы можете использовать ключи из архива, предоставленного студентом.

## Устранение типичных проблем

### Ошибка HMAC при доступе к сервису (access denied)
Если сервис возвращает `Ошибка HMAC` или `Недействительный билет`, вероятно, локальный ключ сервиса устарел.
**Решение:** удалите файлы `FileServer.key` и `MailServer.key` и перезапустите `service_server.py` – они будут пересозданы с актуальными ключами из DB.

### Admin rights required
Убедитесь, что:
- Вы зарегистрировали пользователя `admin` с ролью `admin` через клиент.
- В папке с `admin_client.py` лежат файлы `admin.crt` и `admin.key` с CN=admin.
- Запускаете команду из той же папки, где находятся эти файлы.

### Ошибка `[Errno 2] No such file or directory: 'ca.crt'`
Все сертификаты (`.crt`) и ключи (`.key`) должны лежать в одной папке со скриптами.
