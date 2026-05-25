# magma.py
import secrets
import base64
import hmac
import hashlib


class Magma:
    # S-блоки
    S_BOXES = [
        # S0
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        # S1
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        # S2
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        # S3
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        # S4
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        # S5
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        # S6
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        # S7
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
    ]

    def _t11(self, x: int) -> int:
        return ((x << 11) | (x >> 21)) & 0xFFFFFFFF

    def _s_transform(self, x: int) -> int:
        result = 0
        for i in range(8):
            # Извлекаем 4 бита
            nibble = (x >> (4 * i)) & 0xF
            # Применяем соответствующий S-блок
            substituted = self.S_BOXES[i][nibble]
            result |= (substituted << (4 * i))
        return result & 0xFFFFFFFF

    def _encrypt_block(self, block: bytes, key: list) -> bytes:
        if len(block) != 8:
            raise ValueError("Block must be 8 bytes")

        # Разделяем блок на две 32-битные части
        left = int.from_bytes(block[:4], 'little')
        right = int.from_bytes(block[4:], 'little')

        # 32 раунда шифрования
        for i in range(32):
            if i < 24:
                round_key = key[i % 8]
            else:
                round_key = key[7 - (i % 8)]

            # Основной шаг шифрования
            temp = left
            left = right
            right = self._t11(self._s_transform((right + round_key) & 0xFFFFFFFF)) ^ temp

        # Финальная перестановка
        result_left = right
        result_right = left

        # Собираем блок обратно
        return result_left.to_bytes(4, 'little') + result_right.to_bytes(4, 'little')

    def _decrypt_block(self, block: bytes, key: list) -> bytes:
        if len(block) != 8:
            raise ValueError("Block must be 8 bytes")

        # Разделяем блок на две 32-битные части
        left = int.from_bytes(block[:4], 'little')
        right = int.from_bytes(block[4:], 'little')

        # 32 раунда дешифрования
        for i in range(32):
            if i < 8:
                round_key = key[i % 8]
            else:
                round_key = key[7 - (i % 8)]

            # Основной шаг дешифрования
            temp = left
            left = right
            right = self._t11(self._s_transform((right + round_key) & 0xFFFFFFFF)) ^ temp

        # Финальная перестановка
        result_left = right
        result_right = left

        # Собираем блок обратно
        return result_left.to_bytes(4, 'little') + result_right.to_bytes(4, 'little')

    def _generate_key_schedule(self, key: bytes) -> list:
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits)")

        # Разбиваем ключ на 8 32-битных слов
        key_schedule = []
        for i in range(0, 32, 4):
            key_schedule.append(int.from_bytes(key[i:i + 4], 'little'))

        return key_schedule

    def pad_data(self, data: bytes) -> bytes:
        padding_len = 8 - (len(data) % 8)
        if padding_len == 0:
            padding_len = 8
        return data + bytes([padding_len] * padding_len)

    def unpad_data(self, data: bytes) -> bytes:
        if len(data) == 0:
            return data
        padding_len = data[-1]
        if padding_len > 8 or padding_len < 1:
            return data
        # Проверяем, что все байты padding одинаковы
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            return data
        return data[:-padding_len]

    def encrypt_cbc(self, data: bytes, key: bytes) -> str:
        # Генерируем случайный IV
        iv = secrets.token_bytes(8)

        # Дополняем данные
        padded_data = self.pad_data(data)

        # Генерируем расписание ключей
        key_schedule = self._generate_key_schedule(key)

        # Шифруем в режиме CBC
        encrypted_blocks = []
        prev_block = iv

        for i in range(0, len(padded_data), 8):
            block = padded_data[i:i + 8]
            # XOR с предыдущим зашифрованным блоком (или IV для первого блока)
            xored_block = bytes(a ^ b for a, b in zip(block, prev_block))
            # Шифруем блок
            encrypted_block = self._encrypt_block(xored_block, key_schedule)
            encrypted_blocks.append(encrypted_block)
            prev_block = encrypted_block

        # Объединяем IV и зашифрованные блоки
        result = iv + b''.join(encrypted_blocks)
        return base64.b64encode(result).decode('ascii')

    def decrypt_cbc(self, encrypted_data: str, key: bytes) -> bytes:
        try:
            # Декодируем из base64
            decoded_data = base64.b64decode(encrypted_data)

            # Извлекаем IV
            iv = decoded_data[:8]
            encrypted_blocks = decoded_data[8:]

            # Генерируем расписание ключей
            key_schedule = self._generate_key_schedule(key)

            # Дешифруем в режиме CBC
            decrypted_blocks = []
            prev_block = iv

            for i in range(0, len(encrypted_blocks), 8):
                block = encrypted_blocks[i:i + 8]
                # Дешифруем блок
                decrypted_block = self._decrypt_block(block, key_schedule)
                # XOR с предыдущим зашифрованным блоком (или IV для первого блока)
                xored_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
                decrypted_blocks.append(xored_block)
                prev_block = block

            # Объединяем и удаляем дополнение
            result = b''.join(decrypted_blocks)
            return self.unpad_data(result)

        except Exception as e:
            print(f"Magma decryption error: {e}")
            raise
    def encrypt_cbc_with_hmac(self, data: bytes, key: bytes) -> str:
        # Шифрует CBC и добавляет HMAC-SHA256. Возвращает base64.
        key_enc = hashlib.sha256(key).digest()        # ключ для шифрования
        key_mac = hashlib.sha256(key + b"hmac").digest()  # ключ для HMAC
        ciphertext_b64 = self.encrypt_cbc(data, key_enc)
        ciphertext = base64.b64decode(ciphertext_b64)
        mac = hmac.new(key_mac, ciphertext, hashlib.sha256).digest()
        combined = ciphertext + mac
        return base64.b64encode(combined).decode('ascii')

    def decrypt_cbc_with_hmac(self, encrypted_b64: str, key: bytes) -> bytes:
        # Проверяет HMAC и расшифровывает CBC.
        key_enc = hashlib.sha256(key).digest()
        key_mac = hashlib.sha256(key + b"hmac").digest()
        combined = base64.b64decode(encrypted_b64)
        if len(combined) < 32:
            raise ValueError("Invalid data: too short")
        ciphertext = combined[:-32]
        mac_received = combined[-32:]
        mac_calculated = hmac.new(key_mac, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_received, mac_calculated):
            raise ValueError("HMAC verification failed")
        return self.decrypt_cbc(base64.b64encode(ciphertext).decode('ascii'), key_enc)