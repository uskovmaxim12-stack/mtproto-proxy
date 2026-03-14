import requests
import re
import base64
import struct
import time
from socket import socket, AF_INET, SOCK_STREAM

# --- Список источников прокси (каналы/сайты, где публикуют ссылки) ---
SOURCES = [
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/proxies/mtproto",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/refs/heads/main/all_proxies.txt",
]

# --- Функция для проверки живой прокси ---
def check_proxy(host, port, timeout=3):
    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except:
        return False

# --- Функция для декодирования секрета Fake-TLS ---
def decode_fake_tls_secret(secret):
    if secret.startswith('ee'):
        try:
            decoded = base64.b64decode(secret[2:] + '==')
            host = decoded.decode('utf-8', errors='ignore').strip('\x00')
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', host):
                return host.lower()
        except:
            pass
    return None

# --- Сбор сырых ссылок ---
print("🔍 Сбор ссылок из источников...")
raw_links = []
for url in SOURCES:
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            lines = response.text.split('\n')
            for line in lines:
                line = line.strip()
                # Ищем ссылки вида tg://proxy?server=...&port=...&secret=...
                match = re.search(r'(tg://proxy\?server=([^&]+)&port=(\d+)&secret=([^\s]+))', line)
                if match:
                    raw_links.append({
                        'full': match.group(1),
                        'server': match.group(2),
                        'port': match.group(3),
                        'secret': match.group(4)
                    })
        print(f"  {url}: {len(raw_links)} всего найдено")
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")

print(f"✅ Собрано сырых ссылок: {len(raw_links)}")

# --- Фильтрация для РФ ---
ru_proxies = []
good_domains = ['yandex.ru', 'vk.com', 'mail.ru', 'gosuslugi.ru', 'sber.ru', 'ok.ru', 'avito.ru', 'ozon.ru', 'wildberries.ru']

for proxy in raw_links:
    server = proxy['server']
    port = proxy['port']
    secret = proxy['secret']
    decoded_host = decode_fake_tls_secret(secret)

    # Проверяем, маскируется ли прокси под нужный домен
    if decoded_host and any(good_domain in decoded_host for good_domain in good_domains):
        # Если маскируется, проверяем живой ли он
        if check_proxy(server, port):
            ru_proxies.append(proxy['full'])
            print(f"  ✅ Рабочий: {proxy['full'][:60]}...")
        else:
            print(f"  ❌ Не отвечает: {server}:{port}")
    # Если секрет не ee..., но прокси рабочий — тоже сохраним как запасной вариант
    elif check_proxy(server, port):
        ru_proxies.append(proxy['full'])
        print(f"  ✅ Рабочий (обычный): {proxy['full'][:60]}...")

# --- Сохраняем результат в файл ---
print(f"\n📦 Найдено рабочих прокси для РФ: {len(ru_proxies)}")

with open('proxy_ru.txt', 'w', encoding='utf-8') as f:
    for proxy in ru_proxies:
        f.write(proxy + '\n')

print("✅ Готово! Файл proxy_ru.txt создан.")
