import re
import ipaddress
import base64
import codecs
from datetime import datetime
from typing import Dict, List


def check_luhn(card_number):
    digits = [int(d) for d in card_number]
    checksum = 0
    is_second = False
    for i in range(len(digits) - 1, -1, -1):
        d = digits[i]
        if is_second:
            d = d * 2
            if d > 9:
                d = d - 9
        checksum += d
        is_second = not is_second
    return checksum % 10 == 0


def find_and_validate_credit_cards(text):
    result = {'valid': [], 'invalid': []}
    try:
        card_pattern = re.compile(r'(?:\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b)')
        mixed_pattern = re.compile(r'\b[0-9A-Za-zА-Яа-я-]{15,20}\b')
        found_tokens = set()
        for match in card_pattern.finditer(text):
            raw_card = match.group(0)
            found_tokens.add(raw_card)
            clean_card = re.sub(r'\D', '', raw_card)
            if 13 <= len(clean_card) <= 19:
                if check_luhn(clean_card):
                    result['valid'].append(raw_card)
                else:
                    result['invalid'].append(raw_card)
        for match in mixed_pattern.finditer(text):
            token = match.group(0)
            if token in found_tokens:
                continue
            digits_count = sum(c.isdigit() for c in token)
            if digits_count > 10 and re.search(r'[a-zA-Zа-яА-Я]', token):
                result['invalid'].append(token)
    except Exception as e:
        print(f"Ошибка в поиске карт: {e}")
    return result

def find_secrets(text):
    """Поиск API-ключей, паролей и токенов"""
    result = {'api_keys': [], 'passwords': [], 'tokens': []}
    patterns = [
        (r'sk_(?:live|test)_[a-zA-Z0-9]{24,}', 'api_keys'),
        (r'pk_(?:live|test)_[a-zA-Z0-9]{24,}', 'api_keys'),
        (r'gh[p|o]_[a-zA-Z0-9]{36}', 'api_keys'),
        (r'AIzaSy[a-zA-Z0-9_-]{30,}', 'api_keys'),
        (r'AKIA[0-9A-Z]{16}', 'api_keys'),
        (r'mongodb(?:\+srv)?://[^\s]+', 'api_keys'),
        (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'tokens'),
    ]
    for pattern, category in patterns:
        result[category].extend(re.findall(pattern, text, re.IGNORECASE))

    pwd_pattern = r'(?:password|passwd|pwd|пароль)[\s:=]+[\'"]?([^\s\'"]{4,})'
    for match in re.finditer(pwd_pattern, text, re.I):
        pwd = match.group(1).strip(',;')
        if 4 <= len(pwd) <= 100 and not pwd.isdigit():
            result['passwords'].append(pwd)

    for key in result:
        result[key] = sorted(set(result[key]))
    return result


def find_system_info(text):
    """Поиск IP, файлов и email"""
    result = {'ips': [], 'files': [], 'emails': []}

    ipv4 = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    for ip in set(re.findall(ipv4, text)):
        try:
            addr = ipaddress.IPv4Address(ip)
            if not addr.is_multicast and not addr.is_loopback:
                result['ips'].append(ip)
        except ValueError:
            pass
    result['ips'].sort()

    special_files = [r'\.env\b', r'\bid_rsa\b', r'/etc/[\w.-]+']
    for pattern in special_files:
        result['files'].extend(re.findall(pattern, text, re.I))

    exts = r'(?:txt|log|csv|json|xml|ini|py|pdf|exe|sql|xlsx|bak|env|key|conf|yml|db)'
    general_files = re.findall(rf'(?<![@\w])([\w./\\-]+\.{exts})(?![\w.-])', text, re.I)
    for f in general_files:
        if not re.match(r'^\d{2,4}\.\d{2}\.\d{2,4}$', f):
            if not re.match(r'^\d+\.\d+\.\d+$', f):
                if '.' not in f.split('/')[-1].split('\\')[-1].split('.')[0]:
                    result['files'].append(f)
    result['files'] = sorted(set(result['files']))

    email_re = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    result['emails'] = sorted(set(e.lower() for e in re.findall(email_re, text)))
    return result


def try_decode_base64(s):
    s = s.strip()
    if len(s) < 4 or not re.match(r'^[A-Za-z0-9+/]+=*$', s):
        return ""
    if s.startswith('eyJ') and '.' in s:
        return ""
    try:
        decoded = base64.b64decode(s, validate=False).decode('utf-8', errors='strict')
        if decoded and re.search(r'[A-Za-z]', decoded):
            return decoded
    except:
        pass
    return ""


def try_decode_hex(s):
    clean = re.sub(r'(0x|\\x|\s)', '', s)
    if not clean or len(clean) % 2 != 0 or not re.match(r'^[0-9A-Fa-f]+$', clean):
        return ""
    try:
        decoded = bytes.fromhex(clean).decode('utf-8')
        if decoded and all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded):
            return decoded
    except:
        pass
    return ""


def decode_messages(text):
    """Поиск и декодирование скрытых сообщений"""
    result = {'base64': [], 'hex': [], 'rot13': []}
    seen = {'base64': set(), 'hex': set(), 'rot13': set()}

    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue

        for b64 in re.findall(r'[A-Za-z0-9+/]{12,}={0,2}', line):
            if b64 in seen['base64'] or '.' in b64 or b64.startswith('eyJ'):
                continue
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', b64):
                continue
            seen['base64'].add(b64)
            decoded = try_decode_base64(b64)
            if decoded:
                result['base64'].append({'encoded': b64, 'decoded': decoded})

        for hx in re.findall(r'0x[0-9A-Fa-f]{8,}', line):
            if hx in seen['hex']:
                continue
            seen['hex'].add(hx)
            decoded = try_decode_hex(hx)
            if decoded:
                result['hex'].append({'encoded': hx, 'decoded': decoded})

        for hx in re.findall(r'(?:\\x[0-9A-Fa-f]{2}){4,}', line):
            if hx in seen['hex']:
                continue
            seen['hex'].add(hx)
            decoded = try_decode_hex(hx)
            if decoded:
                result['hex'].append({'encoded': hx, 'decoded': decoded})

        match = re.search(r'ROT13:\s*(.+)$', line, re.IGNORECASE)
        if match:
            encoded_part = match.group(1).strip()
            encoded_part = re.sub(r'^\d{2}:\d{2}\s*[-:–]\s*', '', encoded_part).strip()
            if encoded_part and re.search(r'[A-Za-z]', encoded_part):
                if encoded_part not in seen['rot13']:
                    seen['rot13'].add(encoded_part)
                    decoded = codecs.decode(encoded_part, 'rot_13')
                    if decoded != encoded_part:
                        result['rot13'].append({'encoded': encoded_part, 'decoded': decoded})
    return result


def find_artifacts(text,valid_data):
    """Поиск невалидных данных (артефактов)"""
    artifacts = []

    for ip in re.findall(r'\b\d{1,4}(?:\.\d{1,4}){3}\b', text):
        if ip in valid_data:
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            artifacts.append(f"[INVALID_IP] {ip}")

    for email in re.findall(r'\b\S+@\S+\b', text):
        if email in valid_data:
            continue
        parts = email.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            artifacts.append(f"[INVALID_EMAIL] {email}")
        elif '.' not in parts[1] or parts[1].startswith('.') or parts[1].endswith('.'):
            artifacts.append(f"[INVALID_EMAIL] {email}")
        elif len(parts[1].split('.')[-1]) < 2:
            artifacts.append(f"[INVALID_EMAIL] {email}")

    for b64 in re.findall(r'[A-Za-z0-9+/]{12,}={0,2}', text):
        if b64 in valid_data or (b64.startswith('eyJ') and '.' in b64):
            continue
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', b64) or re.match(r'^[A-Za-z]+$', b64):
            continue
        try:
            base64.b64decode(b64, validate=True)
        except:
            artifacts.append(f"[INVALID_BASE64] {b64}")

    for hx in re.findall(r'0x[0-9A-Fa-f]+', text):
        if hx in valid_data:
            continue
        clean = hx.replace('0x', '')
        if len(clean) % 2 != 0:
            artifacts.append(f"[INVALID_HEX] {hx}")

    for hx in re.findall(r'(?:\\x[0-9A-Fa-f]{2})+', text):
        if hx in valid_data:
            continue
        clean = hx.replace('\\x', '')
        if len(clean) % 2 != 0:
            artifacts.append(f"[INVALID_HEX] {hx}")

    return sorted(set(artifacts))


def analyze_logs(text):
    result = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }
    sql_pattern = re.compile(r"(UNION|SELECT|DROP|INSERT|DELETE|--|' OR '1'='1)", re.I)
    xss_pattern = re.compile(r"(<script>|</script>|javascript:|onerror=)", re.I)
    agent_pattern = re.compile(r"(sqlmap|curl|wget|nikto)", re.I)
    failed_pattern = re.compile(r"(401|authentication failed|invalid password)", re.I)
    try:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if sql_pattern.search(line):
                result['sql_injections'].append(line)
            if xss_pattern.search(line):
                result['xss_attempts'].append(line)
            if agent_pattern.search(line):
                result['suspicious_user_agents'].append(line)
            if failed_pattern.search(line):
                result['failed_logins'].append(line)
    except Exception as e:
        print(f"Ошибка анализа логов: {e}")
    return result


def check_inn_checksum(inn_str):
    try:
        digits = [int(d) for d in inn_str]
        length = len(digits)
        if length == 10:
            weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
            checksum = sum(w * d for w, d in zip(weights, digits[:-1])) % 11
            if checksum == 10:
                checksum = 0
            return checksum == digits[-1]
        elif length == 12:
            weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            checksum1 = sum(w * d for w, d in zip(weights1, digits[:-2])) % 11
            if checksum1 == 10:
                checksum1 = 0
            checksum2 = sum(w * d for w, d in zip(weights2, digits[:-1])) % 11
            if checksum2 == 10:
                checksum2 = 0
            return checksum1 == digits[-2] and checksum2 == digits[-1]
        return False
    except Exception:
        return False


def normalize_and_validate(text):
    result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []}
    }
    # 1. PHONES
    try:
        phone_candidates = re.finditer(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}', text)
        for match in phone_candidates:
            raw_phone = match.group(0)
            clean_phone = re.sub(r'[^\d+]', '', raw_phone)
            is_valid = False
            if re.match(r'^(\+7|8)\d{10}$', clean_phone):
                is_valid = True
            elif re.match(r'^\+\d{9,14}$', clean_phone):
                if clean_phone.startswith('+0'):
                    is_valid = False
                else:
                    is_valid = True
            digits_only = re.sub(r'\D', '', clean_phone)
            if (len(digits_only) in [10, 12] and '+' not in raw_phone and
                    '(' not in raw_phone and '-' not in raw_phone):
                if not (digits_only.startswith('79') or digits_only.startswith('89')):
                    continue
            if is_valid:
                result['phones']['valid'].append(raw_phone)
            else:
                if len(digits_only) > 6:
                    result['phones']['invalid'].append(raw_phone)
    except Exception as e:
        print(f"Ошибка валидации телефонов: {e}")
    # 2. INN
    try:
        inn_candidates = re.finditer(r'\b\d{10}\b|\b\d{12}\b', text)
        for match in inn_candidates:
            raw_inn = match.group(0)
            if raw_inn.startswith('00') or raw_inn == '0' * len(raw_inn):
                result['inn']['invalid'].append(raw_inn)
                continue
            if check_inn_checksum(raw_inn):
                result['inn']['valid'].append(raw_inn)
            else:
                result['inn']['invalid'].append(raw_inn)
    except Exception as e:
        print(f"Ошибка валидации ИНН: {e}")
    # 3. DATES
    dates = re.findall(r'\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b', text)
    for date in dates:
        try:
            normalized = datetime.strptime(date,
                                           "%d.%m.%Y" if '.' in date else "%d-%m-%Y" if '-' in date else "%d/%m/%Y")
            result['dates']['normalized'].append(date)
        except:
            try:
                normalized = datetime.strptime(date,
                                               "%m.%d.%Y" if '.' in date else "%m-%d-%Y" if '-' in date else "%m/%d/%Y")
                result['dates']['normalized'].append(date)
            except:
                result['dates']['invalid'].append(date)
    return result


def main():
    input_file = "text.txt"
    artifacts_file = "artifacts.txt"

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            text = file.read()
        print(f"--- Запуск анализа файла {input_file} ---\n")

        # 1. Cards
        cards_result = find_and_validate_credit_cards(text)
        print(f"[{len(cards_result['valid'])}] ВАЛИДНЫЕ КАРТЫ (Luhn OK):")
        for c in cards_result['valid']:
            print(f"  {c}")

        # 2. Logins
        logs_result = analyze_logs(text)
        print(f"\n[{sum(len(v) for v in logs_result.values())}] НАЙДЕННЫЕ УГРОЗЫ В ЛОГАХ:")
        for category, items in logs_result.items():
            if items:
                print(f"   > {category}:")
                for item in items:
                    print(f"    - {item}")

        # 3. Data (INN, Phones, Dates)
        norm_result = normalize_and_validate(text)
        print(f"\n[{len(norm_result['inn']['valid'])}] ВАЛИДНЫЕ ИНН:")
        for inn in norm_result['inn']['valid']:
            print(f"  {inn}")
        print(f"\n[{len(norm_result['phones']['valid'])}] ВАЛИДНЫЕ ТЕЛЕФОНЫ:")
        for ph in norm_result['phones']['valid']:
            print(f"  {ph}")
        print(f"\n[{len(norm_result['dates']['normalized'])}] ВАЛИДНЫЕ ДАТЫ (нормализованные):")
        for date in norm_result['dates']['normalized']:
            print(f"  {date}")


        secrets = find_secrets(text)
        system_info = find_system_info(text)
        decoded = decode_messages(text)

        print(f"\n[{sum(len(v) for v in secrets.values())}] НАЙДЕННЫЕ СЕКРЕТЫ:")
        for cat, items in secrets.items():
            if items:
                print(f"  {cat}: {', '.join(items)}")

        print(f"\n[{len(system_info['ips'])}] IP-АДРЕСА:")
        if system_info['ips']:
            print(f"  {', '.join(system_info['ips'])}")

        print(f"\n[{len(system_info['files'])}] ФАЙЛЫ:")
        if system_info['files']:
            print(f"  {', '.join(system_info['files'])}")

        print(f"\n[{len(system_info['emails'])}] EMAIL:")
        if system_info['emails']:
            print(f"  {', '.join(system_info['emails'])}")

        print(f"\n[{sum(len(v) for v in decoded.values())}] РАСШИФРОВАННЫЕ СООБЩЕНИЯ:")
        for cat, items in decoded.items():
            if items:
                for i in items:
                    enc = i['encoded'][:40] + "..." if len(i['encoded']) > 40 else i['encoded']
                    print(f"  {cat}: {enc} -> {i['decoded'][:30]}")

        unique_artifacts = set()

        unique_artifacts.update(cards_result['invalid'])
        unique_artifacts.update(norm_result['inn']['invalid'])
        unique_artifacts.update(norm_result['phones']['invalid'])
        unique_artifacts.update(norm_result['dates']['invalid'])
        for k, v in logs_result.items():
            unique_artifacts.update(v)

        valid_data = set()
        for lst in secrets.values():
            valid_data.update(lst)
        for lst in system_info.values():
            valid_data.update(lst)
        for lst in decoded.values():
            valid_data.update(item['encoded'] for item in lst)

        new_artifacts = find_artifacts(text, valid_data)
        unique_artifacts.update(new_artifacts)

        print(f"\n------------------------------------------------")
        print(f"Количество уникальных артефактов (сохранено в файл): {len(unique_artifacts)}")

        with open(artifacts_file, "w", encoding="utf-8") as f_out:
            f_out.write("--- REPORT: INVALID ARTIFACTS & SUSPICIOUS DATA ---\n")
            f_out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for item in sorted(unique_artifacts):
                f_out.write(f"{item}\n")

        print(f"Файл {artifacts_file} успешно записан.")

    except FileNotFoundError:
        print(f"ОШИБКА: Файл {input_file} не найден. Пожалуйста, создайте его.")
    except Exception as e:
        print(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")


if __name__ == "__main__":
    main()
