from scapy.all import sniff
from scapy.interfaces import get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSRR
from collections import defaultdict
import time
import logging
import requests
import ipaddress
import socket
from datetime import datetime

def save_telegram_chat_id(chat_id):
    """
    Сохраняет Telegram Chat ID в файл.
    """
    with open("telegram_chat_id.txt", "w") as file:
        file.write(chat_id)

def load_telegram_chat_id():
    """
    Загружает Telegram Chat ID из файла или запрашивает его ввод в консоли, если файл пуст.
    """
    try:
        with open("telegram_chat_id.txt", "r") as file:
            chat_id = file.read().strip()
            if not chat_id:
                raise ValueError("Файл telegram_chat_id.txt пуст.")
            return chat_id
    except (FileNotFoundError, ValueError):
        # Запросить Chat ID через консоль
        chat_id = input("Введите ваш Telegram Chat ID: ").strip()
        if not chat_id:
            raise ValueError("Telegram Chat ID не введен.")
        save_telegram_chat_id(chat_id)
        return chat_id

try:
    TELEGRAM_CHAT_ID = load_telegram_chat_id()
    print(f"Загружен TELEGRAM_CHAT_ID: {TELEGRAM_CHAT_ID}")
except ValueError as e:
    print(f"Ошибка: {e}")
    exit(1)



# Логирование
logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Словарь для отслеживания состояния SYN-запросов
syn_requests = defaultdict(lambda: {'unique_ports': set(), 'packet_count': 0, 'last_time': 0})
SYN_SCAN_PORT_THRESHOLD = 3  # Минимум уникальных портов для сканирования
SYN_SCAN_PACKET_THRESHOLD = 50  # Порог количества пакетов для исключения флуда
SYN_SCAN_TIME_WINDOW = 10  # Интервал для анализа (в секундах)
SYN_SCAN_RESET_INTERVAL = 60  # Время для сброса старых записей
# Порог для срабатывания
TCP_SCAN_THRESHOLD = 3
# Статистика попыток подключения
tcp_connect_requests = defaultdict(lambda: {'syn_count': 0, 'syn_ack_count': 0, 'ack_count': 0, 'last_time': 0})
TCP_CONNECT_THRESHOLD = 3  # Минимальное количество соединений для детектирования
# Статистика для UDP-сканирования
udp_scan_data = defaultdict(lambda: {'ports': set(), 'icmp_responses': 0, 'last_time': 0})
# Порог срабатывания
UDP_SCAN_THRESHOLD = 3  # Минимальное количество портов для детектирования
# Статистика для FIN-сканирования
fin_scan_data = defaultdict(lambda: {'ports': set(), 'rst_responses': 0, 'last_time': 0})
# Пороговые значения
FIN_SCAN_THRESHOLD = 2  # Минимальное количество портов для детектирования
# Статистика для ACK-сканирования
ack_scan_data = defaultdict(lambda: {'ports': set(), 'rst_responses': 0, 'last_time': 0})
# Пороговые значения
ACK_SCAN_THRESHOLD = 3  # Минимальное количество портов для детектирования
NO_RESPONSE_TIME = 5  # Время ожидания ответа (секунды)
TIME_WINDOW = 60
# Порог времени для сброса запросов
RESET_INTERVAL = 60
####DDoS####
###SYN-FLOOD###
SYN_threshold = 50  # Количество SYN-пакетов, после которого фиксируется атака
time_interval = 5    # Интервал времени для анализа (в секундах)

syn_counts = defaultdict(int)
start_time = time.time()
# Белый список IP (например, локальная сеть или известные адреса)
WHITELIST_IPS = {"192.168.227.1", "34.117.59.81", "88.218.171.125"}

# Функция для отправки сообщений в Telegram
def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            logging.error(f"Ошибка отправки в Telegram: {response.text}")
    except Exception as e:
        logging.error(f"Ошибка подключения к Telegram: {e}")

# Глобальная таблица для IP-MAC соответствий
ip_mac_table = defaultdict(set)

# Кэш для проверки IP-адресов
ip_cache = {}

def check_ip_with_virustotal(ip_address, ttl=3600):
    """
    Проверяет репутацию IP-адреса через VirusTotal API с использованием локального кэша.
    :param ip_address: Проверяемый IP-адрес.
    :param ttl: Время жизни записи в кэше (в секундах).
    :return: Кортеж (is_safe, details), где is_safe — статус безопасности, details — информация анализа.
    """
    global ip_cache

    # Проверяем наличие в кэше
    current_time = time.time()
    if ip_address in ip_cache:
        cached_result, cached_time, cached_details = ip_cache[ip_address]
        if current_time - cached_time < ttl:
            logging.info(f"IP {ip_address} найден в кэше. Статус: {'безопасен' if cached_result else 'подозрителен'}")
            return cached_result, cached_details
        else:
            # Удаляем устаревшую запись
            del ip_cache[ip_address]

    # Если в кэше нет, выполняем запрос к API
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Извлечение данных анализа
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Логика определения подозрительности
        is_safe = not (malicious > 5 or suspicious > 5 or reputation < 0)

        # Дополнительные данные анализа
        details = {
            "reputation": reputation,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

        # Сохраняем результат в кэш
        ip_cache[ip_address] = (is_safe, current_time, details)

        logging.info(f"VirusTotal: IP {ip_address}, Репутация: {reputation}, Зловредные: {malicious}, Подозрительные: {suspicious}")
        return is_safe, details
    except requests.exceptions.RequestException as e:
        logging.error(f"Ошибка при запросе к VirusTotal для IP {ip_address}: {e}")
        return True, {}  # Предполагаем безопасность при сбое API



def detect_dns_spoof(packet, send_telegram_alert):
    """
    Функция для детектирования DNS Spoofing.
    :param packet: Объект пакета Scapy.
    :param send_telegram_alert: Функция для отправки уведомлений.
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 1:  # Проверяем, является ли это DNS-ответом
        if not hasattr(packet[DNS], 'qd') or packet[DNS].qd is None:
            logging.warning("DNS пакет без запроса (qd)")
            return None

        query_name = packet[DNS].qd.qname.decode("utf-8").rstrip(".")
        if packet[DNS].an:  # Если есть ответ (Answer Section)
            response_ips = [
                packet[DNS].an[i].rdata
                for i in range(packet[DNS].ancount)
                if isinstance(packet[DNS].an[i], DNSRR)
            ]

            logging.info(f"DNS ответ для {query_name}: {response_ips}")

            for ip in response_ips:
                # Проверяем репутацию каждого IP через VirusTotal
                is_safe, details = check_ip_with_virustotal(ip)

                if not is_safe:
                    # Формируем сообщение с дополнительной информацией
                    message = (
                        f"Обнаружен DNS Spoofing!\n"
                        f"Домен: {query_name}\n"
                        f"Подозрительный IP: {ip}\n"
                        f"Репутация: {details.get('reputation', 'неизвестно')}\n"
                        f"Зловредные: {details.get('malicious', 0)}\n"
                        f"Подозрительные: {details.get('suspicious', 0)}\n"
                        f"Безопасные: {details.get('harmless', 0)}\n"
                        f"Неопределённые: {details.get('undetected', 0)}"
                    )
                    logging.warning(message)
                    print(f"[ALERT] {message}")  # Вывод сообщения на экран
                    send_telegram_alert(message)  # Отправляем сообщение в Telegram
                    return f"[ALERT] {message}"  # Возвращаем сообщение об атаке

    return None  # Возвращаем None, если атака не обнаружена


def detect_arp_spoofing(packet, send_telegram_alert):
    """
    Проверяет, является ли данный ARP-пакет частью атаки ARP Spoofing.
    """
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        # Если IP уже в таблице, проверяем MAC-адрес
        if src_ip in ip_mac_table:
            if src_mac not in ip_mac_table[src_ip]:
                alert_message = (f"[ALERT] Обнаружена атака ARP Spoofing!\n"
                                 f"IP {src_ip} ранее был связан с MAC {ip_mac_table[src_ip]}, "
                                 f"но теперь связан с MAC {src_mac}")
                logging.warning(alert_message)
                print(alert_message)
                send_telegram_alert(alert_message)
                return alert_message
        else:
            # Добавляем новое соответствие IP-MAC
            ip_mac_table[src_ip].add(src_mac)
    return None


# Проверка локального IP
def is_local_ip(ip):
    return ipaddress.ip_address(ip).is_private

SYN_threshold = 50  # Количество SYN-пакетов, после которого фиксируется атака
time_interval = 5    # Интервал времени для анализа (в секундах)

syn_counts = defaultdict(int)
start_time = time.time()


def detect_syn_flood(packet, current_time, send_telegram_alert):
    global syn_counts, start_time

    alert_message = None  # Используем None вместо пустой строки

    if packet.haslayer('TCP') and packet['TCP'].flags == 'S':  # Проверяем SYN-флаг
        target_ip = packet['IP'].dst
        source_ip = packet['IP'].src
        syn_counts[(source_ip, target_ip)] += 1

    # Если время анализа истекло, проверяем результаты
    if time.time() - start_time > time_interval:
        total_syn_packets = sum(syn_counts.values())
        unique_ips = len({src for src, _ in syn_counts.keys()})

        if total_syn_packets > SYN_threshold and unique_ips > 1:  # Простой порог
            alert_message = (f"[ALERT] Обнаружена возможная SYN-флуд атака! "
                             f"Пакеты: {total_syn_packets}, Уникальные IP: {unique_ips}")
            print(alert_message)  # Для отладки или реального мониторинга
            logging.warning(alert_message)
            send_telegram_alert(alert_message)

        # Обнуляем статистику
        syn_counts.clear()
        start_time = time.time()

    return alert_message  # Возвращаем сообщение об атаке или None

UDP_FLOOD_THRESHOLD = 50  # Минимальное количество UDP-пакетов за интервал
TIME_WINDOW = 1  # Интервал анализа в секундах
RESET_INTERVAL = 60  # Время для сброса записей

udp_traffic = defaultdict(lambda: {'packet_count': 0, 'unique_sources': set(), 'last_time': 0})

def detect_udp_flood(packet, current_time, send_telegram_alert):
    """
    Обнаружение UDP-Flood атак с обработкой устаревших записей.
    """
    alert_message = None

    if packet.haslayer(UDP) and (packet.haslayer(IP) or packet.haslayer(IPv6)):
        dst_ip = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
        src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src

        # Обновляем данные о трафике
        entry = udp_traffic[dst_ip]
        entry['packet_count'] += 1
        entry['unique_sources'].add(src_ip)
        entry['last_time'] = current_time

        # # DEBUG: Проверяем поступление пакетов
        # print(f"[DEBUG] UDP: {src_ip} -> {dst_ip}, Всего пакетов: {entry['packet_count']}")

        # Проверка порога для UDP-Flood
        if entry['packet_count'] >= UDP_FLOOD_THRESHOLD and current_time - entry['last_time'] <= TIME_WINDOW:
            unique_sources = len(entry['unique_sources'])
            alert_message = (
                f"[ALERT] Обнаружена UDP-Flood атака на {dst_ip} "
                f"({entry['packet_count']} пакетов от {unique_sources} источников)."
            )
            print(alert_message)
            logging.warning(alert_message)
            send_telegram_alert(alert_message)
            del udp_traffic[dst_ip]

    # Сброс устаревших записей
    for key in list(udp_traffic):
        if current_time - udp_traffic[key]['last_time'] > RESET_INTERVAL:
            del udp_traffic[key]

    return alert_message

http_traffic = defaultdict(lambda: {'packet_count': 0, 'unique_sources': set(), 'last_time': 0})
HTTP_FLOOD_THRESHOLD = 50  # Минимум 100 пакетов
TIME_WINDOW = 10  # Время в секундах для анализа
RESET_INTERVAL = 60  # Сброс через 60 секунд

def detect_http_flood(packet, current_time, send_telegram_alert):
    """
    Обнаружение HTTP-Flood атак с обработкой устаревших записей.
    """
    alert_message = None

    if packet.haslayer(TCP) and packet.haslayer(IP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        tcp_flags = packet.sprintf("%TCP.flags%")

        # Проверяем порты HTTP/HTTPS
        if dport in [80, 443] and tcp_flags == "PA":
            entry = http_traffic[dst_ip]
            entry['packet_count'] += 1
            entry['unique_sources'].add(src_ip)
            entry['last_time'] = current_time

            # # DEBUG: Проверяем поступление пакетов
            # print(f"[DEBUG] HTTP/HTTPS: {src_ip}:{sport} -> {dst_ip}:{dport}, Всего пакетов: {entry['packet_count']}")
            # Проверка порога для HTTP-Flood
            if (
                entry['packet_count'] >= HTTP_FLOOD_THRESHOLD
                and current_time - entry['last_time'] <= TIME_WINDOW
            ):
                unique_sources = len(entry['unique_sources'])
                alert_message = (
                    f"[ALERT] Обнаружена HTTP-Flood атака на {dst_ip}:{dport} "
                    f"({entry['packet_count']} пакетов от {unique_sources} источников)."
                )
                print(alert_message)
                logging.warning(alert_message)
                send_telegram_alert(alert_message)
                del http_traffic[dst_ip]

    # Сброс устаревших записей
    for key in list(http_traffic):
        if current_time - http_traffic[key]['last_time'] > RESET_INTERVAL:
            del http_traffic[key]

    return alert_message  # Возвращаем сообщение об атаке или None

def detect_syn_scan(packet, current_time, send_telegram_alert):
    """
    Обнаружение SYN-сканирования с учётом различий с SYN-флудом.
    """
    alert_message = None  # Инициализация возвращаемого сообщения

    if packet.haslayer(TCP) and (packet.haslayer(IP) or packet.haslayer(IPv6)):
        src_ip = packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        dst_ip = packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
        dport = packet[TCP].dport
        tcp_flags = packet.sprintf("%TCP.flags%")

        if tcp_flags == "S":
            entry = syn_requests[src_ip]
            entry['unique_ports'].add(dport)
            entry['packet_count'] += 1
            entry['last_time'] = current_time
            print(f"[DEBUG] SYN-запрос: {src_ip} -> {dst_ip}:{dport}.")

            # Проверка порога для сканирования
            unique_ports = len(entry['unique_ports'])
            total_packets = entry['packet_count']
            if (
                unique_ports >= SYN_SCAN_PORT_THRESHOLD and
                total_packets < SYN_SCAN_PACKET_THRESHOLD and
                current_time - entry['last_time'] <= SYN_SCAN_TIME_WINDOW
            ):
                alert_message = (
                    f"[ALERT] Обнаружено SYN/TCP connect-сканирование от {src_ip}. "
                    f"Просканированные порты: {entry['unique_ports']}."
                )
                print(alert_message)
                logging.warning(alert_message)
                send_telegram_alert(alert_message)
                # Сброс записей после обнаружения
                del syn_requests[src_ip]

        # Сброс старых записей
        for key in list(syn_requests):
            if current_time - syn_requests[key]['last_time'] > SYN_SCAN_RESET_INTERVAL:
                del syn_requests[key]

    return alert_message  # Возвращаем сообщение об атаке или None

def detect_udp_scan(packet, current_time, send_telegram_alert):
    """
    Обнаружение UDP-сканирования портов.
    :param packet: Пакет Scapy
    :param current_time: Текущее время
    :param send_alert: Функция для отправки уведомлений
    """
    alert_message = None

    if packet.haslayer(UDP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = packet[UDP].dport

        # Запись о новых попытках отправки UDP-пакетов
        entry = udp_scan_data[src_ip]
        entry['ports'].add(dport)
        entry['last_time'] = current_time

    elif packet.haslayer(ICMP) and packet.haslayer(IP):
        icmp_type = packet[ICMP].type
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ответы ICMP Destination Unreachable (тип 3)
        if icmp_type == 3:
            for key in udp_scan_data:
                if dst_ip == key:  # Считаем это ответом на UDP-запрос от источника
                    udp_scan_data[key]['icmp_responses'] += 1
                    break

    # Проверка активности на сканирование
    for src_ip, entry in list(udp_scan_data.items()):
        if len(entry['ports']) >= UDP_SCAN_THRESHOLD and current_time - entry['last_time'] <= TIME_WINDOW:
            alert_message = (f"[ALERT] Обнаружено UDP-сканирование от {src_ip}. "
                             f"Просканированные порты: {entry['ports']}, ICMP-ответов: {entry['icmp_responses']}")
            print(alert_message)
            logging.warning(alert_message)
            send_telegram_alert(alert_message)
            # Сброс после детектирования
            del udp_scan_data[src_ip]
            return alert_message  # Возврат сообщения об обнаружении

        # Удаление старых записей
        if current_time - entry['last_time'] > RESET_INTERVAL:
            del udp_scan_data[src_ip]

    return alert_message  # Возврат None, если атака не обнаружена

def detect_fin_scan(packet, current_time, send_telegram_alert):
    """
    Обнаружение FIN-сканирования портов.
    :param packet: Пакет Scapy
    :param current_time: Текущее время
    :param send_alert: Функция для отправки уведомлений
    """
    alert_message = None  # Инициализация возвращаемого сообщения

    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = packet[TCP].dport
        tcp_flags = packet.sprintf("%TCP.flags%")
        entry = fin_scan_data[src_ip]

        # Обработка FIN-пакетов
        if tcp_flags == "F":
            entry['ports'].add(dport)
            entry['last_time'] = current_time

        # Обработка RST-ответов
        elif tcp_flags == "R" or tcp_flags == "RA":
            for key in fin_scan_data:
                if dst_ip == key:
                    fin_scan_data[key]['rst_responses'] += 1
                    break

        # Проверка на сканирование
        if len(entry['ports']) >= FIN_SCAN_THRESHOLD and current_time - entry['last_time'] <= TIME_WINDOW:
            alert_message = (f"[ALERT] Обнаружено FIN-сканирование от {src_ip}. "
                             f"Просканированные порты: {entry['ports']}, Ответы RST: {entry['rst_responses']}")
            print(alert_message)
            logging.warning(alert_message)
            send_telegram_alert(alert_message)
            # Сброс после детектирования
            del fin_scan_data[src_ip]
            return alert_message  # Возврат сообщения об обнаружении

        # Удаление старых записей
        for key in list(fin_scan_data):
            if current_time - fin_scan_data[key]['last_time'] > RESET_INTERVAL:
                del fin_scan_data[key]

        return alert_message  # Возврат None, если атака не обнаружена

def detect_ack_scan(packet, current_time, send_telegram_alert):
    """
    Обнаружение ACK-сканирования портов.

    :param packet: Пакет Scapy
    :param current_time: Текущее время (time.time())
    :param send_alert: Функция для отправки уведомлений
    """
    alert_message = None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return  # Пропустить пакеты без слоёв TCP/IP

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dport = packet[TCP].dport
    tcp_flags = packet.sprintf("%TCP.flags%")

    # Пропустить IP-адреса из белого списка
    if src_ip in WHITELIST_IPS:
        return

    # Получить данные для анализа (инициализация, если ключ отсутствует)
    if src_ip not in ack_scan_data:
        ack_scan_data[src_ip] = {'ports': set(), 'rst_responses': 0, 'last_time': 0}
    entry = ack_scan_data[src_ip]

    # Обработка ACK-пакетов
    if tcp_flags == "A":
        entry['ports'].add(dport)
        entry['last_time'] = current_time

    # Обработка RST-ответов
    elif tcp_flags == "R":
        for key, data in ack_scan_data.items():
            if dst_ip == key:
                data['rst_responses'] += 1
                break

    # Проверка на сканирование
    if len(entry['ports']) >= ACK_SCAN_THRESHOLD and current_time - entry['last_time'] <= TIME_WINDOW:
        alert_message = (f"[ALERT] Обнаружено ACK-сканирование от {src_ip}. "
                         f"Просканированные порты: {entry['ports']}, Ответы RST: {entry['rst_responses']}")
        print(alert_message)
        logging.warning(alert_message)
        send_telegram_alert(alert_message)
        # Сброс записи после детектирования
        ack_scan_data.pop(src_ip, None)
        return alert_message

    # Удаление старых записей
    stale_ips = [key for key, data in ack_scan_data.items() if current_time - data['last_time'] > RESET_INTERVAL]
    for key in stale_ips:
        del ack_scan_data[key]

    return alert_message

def get_geo_info(ip):
    if is_local_ip(ip):
        return "Локальный IP"
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token")
        data = response.json()
        if 'error' in data:
            return "Информация недоступна"
        city = data.get('city', 'Неизвестно')
        region = data.get('region', 'Неизвестно')
        country = data.get('country', 'Неизвестно')
        return f"{city}, {region}, {country}"
    except Exception as e:
        logging.error(f"Ошибка при получении геолокации для {ip}: {e}")
        return "Неизвестно"

def format_port(port):
    if port == 80:
        return "80 (http)"
    elif port == 443:
        return "443 (https)"
    elif port == 22:
        return "22 (ssh)"
    else:
        return str(port)

# Обработчик пакетов
def packet_handler(packet):
    current_time = time.time()
    geo_info = "Неизвестно"
    geo_dst = "Неизвестно"
    packet_type = "Неизвестный пакет"
    tcp_flags = "Не применимо"
    result_messages = []

    try:
        # Обработка IP-адресов (IPv4 и IPv6)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_type = "IPv4"
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            packet_type = "IPv6"
        else:
            src_ip = dst_ip = None
    except Exception as e:
        logging.error(f"Ошибка извлечения IP: {e}")
        src_ip, dst_ip = None, None

    attack_messages = []

    # Определение типа пакета
    if packet.haslayer(TCP):
        packet_type += " TCP"
        tcp_flags = packet.sprintf("%TCP.flags%")
    elif packet.haslayer(UDP):
        packet_type += " UDP"
    elif packet.haslayer(ARP):
        packet_type = "ARP"
        arp_spoof_msg = detect_arp_spoofing(packet, send_telegram_alert)
        if arp_spoof_msg:
            result_messages.append(arp_spoof_msg)
    elif packet.haslayer(DNS):
        packet_type = "DNS"
    elif packet.haslayer(ICMP):
        packet_type = "ICMP"

    # MAC-адреса
    src_mac = packet[Ether].src if packet.haslayer(Ether) else "Неизвестно"
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "Неизвестно"

    # Порты
    src_port = format_port(packet[TCP].sport) if packet.haslayer(TCP) else (format_port(packet[UDP].sport) if packet.haslayer(UDP) else "N/A")
    dst_port = format_port(packet[TCP].dport) if packet.haslayer(TCP) else (format_port(packet[UDP].dport) if packet.haslayer(UDP) else "N/A")

    try:
        if src_ip and dst_ip:
            geo_info = get_geo_info(src_ip)
            geo_dst = get_geo_info(dst_ip)
            # Логирование и вывод информации
            log_message = (f"Тип пакета: {packet_type} | TCP Флаги: {tcp_flags} | "
                           f"IP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
                           f"MAC: {src_mac} -> {dst_mac} | Геолокация: {geo_info} -> {geo_dst}")
            result_messages.append(log_message)
            logging.info(log_message)

            # SYN-сканирование
            syn_scan_msg = detect_syn_scan(packet, current_time, send_telegram_alert)
            if syn_scan_msg:
                result_messages.append(syn_scan_msg)

            # UDP-сканирование
            udp_scan_msg = detect_udp_scan(packet, current_time, send_telegram_alert)
            if udp_scan_msg:
                result_messages.append(udp_scan_msg)

            # FIN-сканирование
            fin_scan_msg = detect_fin_scan(packet, current_time, send_telegram_alert)
            if fin_scan_msg:
                result_messages.append(fin_scan_msg)

            # ACK-сканирование
            ack_scan_msg = detect_ack_scan(packet, current_time, send_telegram_alert)
            if ack_scan_msg:
                result_messages.append(ack_scan_msg)

            # DDoS-атаки
            syn_flood_msg = detect_syn_flood(packet, current_time, send_telegram_alert)
            if syn_flood_msg:
                result_messages.append(syn_flood_msg)

            udp_flood_msg = detect_udp_flood(packet, current_time, send_telegram_alert)
            if udp_flood_msg:
                result_messages.append(udp_flood_msg)

            http_flood_msg = detect_http_flood(packet, current_time, send_telegram_alert)
            if http_flood_msg:
                result_messages.append(http_flood_msg)

            # ARP Spoofing
            # arp_spoof_msg = detect_arp_spoofing(packet)
            # if arp_spoof_msg:
            #     result_messages.append(arp_spoof_msg)

            # DNS Spoofing
            dns_spoof_msg = detect_dns_spoof(packet, send_telegram_alert)
            if dns_spoof_msg:
                result_messages.append(dns_spoof_msg)

    except Exception as e:
            logging.error(f"Ошибка обработки пакета: {e}")
            result_messages.append(f"Ошибка обраобтки пакета: {e}")

    return "\n".join(
        datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ") + message
        for message in result_messages
    )

def start_sniffing():
     print("Начинаем мониторинг сетевого трафика...")
     sniff(prn=packet_handler, store=False, timeout=300)

if __name__ == "__main__":
     start_sniffing()
