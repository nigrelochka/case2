import re
from datetime import datetime

def check_luhn(card_number):
    """
    Проверка номера карты по алгоритму Луна.
    Принимает строку, состоящую только из цифр.
    """
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

# --- Роль 1: Финансовый сыщик ---

def find_and_validate_credit_cards(text):
    """
    Находит номера карт и проверяет их алгоритмом Луна.
    Также ищет 'подозрительные' номера с буквами.
    """
    result = {'valid': [], 'invalid': []}

    try:
        # Регулярка для потенциальных карт:
        # 1. Обычные цифры с разделителями (13-19 цифр)
        card_pattern = re.compile(r'(?:\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,4}\b)')

        # 2. Смешанные с буквами (для отлова артефактов типа 22024567АБСВ4765)
        mixed_pattern = re.compile(r'\b[0-9A-Za-zА-Яа-я-]{15,20}\b')

        found_tokens = set()

        # Сначала ищем четкие структуры
        for match in card_pattern.finditer(text):
            raw_card = match.group(0)
            found_tokens.add(raw_card)
            # Очищаем только для проверки алгоритмом, но сохраняем raw_card
            clean_card = re.sub(r'\D', '', raw_card)

            if 13 <= len(clean_card) <= 19:
                if check_luhn(clean_card):
                    result['valid'].append(raw_card)
                else:
                    result['invalid'].append(raw_card)

        # Теперь ищем мусорные данные, похожие на карты, но с буквами
        for match in mixed_pattern.finditer(text):
            token = match.group(0)
            if token in found_tokens:
                continue

            # Проверяем, похоже ли это на карту (много цифр, но есть буквы)
            digits_count = sum(c.isdigit() for c in token)
            if digits_count > 10 and re.search(r'[a-zA-Zа-яА-Я]', token):
                # Это "похоже" на карту, но с буквами -> invalid
                result['invalid'].append(token)

    except Exception as e:
        print(f"Ошибка в поиске карт: {e}")

    return result


# --- Роль 5: Аналитик логов ---

def analyze_logs(text):
    """
    Анализирует логи веб-сервера на предмет атак.
    Использует скомпилированные регулярные выражения.
    """
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
    """
    Проверка контрольных цифр ИНН по алгоритму ФНС.
    """
    try:
        digits = [int(d) for d in inn_str]
        length = len(digits)

        if length == 10:
            # Юрлица
            weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
            checksum = sum(w * d for w, d in zip(weights, digits[:-1])) % 11
            if checksum == 10:
                checksum = 0
            return checksum == digits[-1]

        elif length == 12:
            # Физлица
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

# --- Роль 6: Инженер качества данных ---

def normalize_and_validate(text):
    """
    Приводит данные к единому формату и проверяет их (Телефоны, Даты, ИНН).
    """
    result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []}
    }

    # --- 1. ТЕЛЕФОНЫ ---
    try:
        phone_candidates = re.finditer(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}', text)

        for match in phone_candidates:
            raw_phone = match.group(0)
            clean_phone = re.sub(r'[^\d+]', '', raw_phone)

            is_valid = False

            # Проверка Российских номеров
            if re.match(r'^(\+7|8)\d{10}$', clean_phone):
                is_valid = True
            # Международные форматы
            elif re.match(r'^\+\d{9,14}$', clean_phone):
                if clean_phone.startswith('+0'):
                    is_valid = False
                else:
                    is_valid = True

            # Фильтрация от ИНН/Карт
            digits_only = re.sub(r'\D', '', clean_phone)
            if len(digits_only) in [10, 12] and '+' not in raw_phone and '(' not in raw_phone and '-' not in raw_phone:
                if not (digits_only.startswith('79') or digits_only.startswith('89')):
                    continue

            if is_valid:
                result['phones']['valid'].append(raw_phone)  # Сохраняем исходный вид для вывода
            else:
                if len(digits_only) > 6:
                    result['phones']['invalid'].append(raw_phone)

    except Exception as e:
        print(f"Ошибка валидации телефонов: {e}")

    # --- 2. ИНН ---
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

    # # --- 3. ДАТЫ ---

    dates = re.findall(r'\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b', text)

    for date in dates:
        try:
            # Пробуем формат ДД.ММ.ГГГГ
            normalized = datetime.strptime(date,
                                           "%d.%m.%Y" if '.' in date
                                           else "%d-%m-%Y"
                                           if '-' in date
                                           else "%d/%m/%Y")
            result['dates']['normalized'].append(date)  # сохраняем исходную дату
        except:
            try:
                # Пробуем формат ММ.ДД.ГГГГ
                normalized = datetime.strptime(date,
                                               "%m.%d.%Y" if '.' in date
                                               else "%m-%d-%Y"
                                               if '-' in date
                                               else "%m/%d/%Y")
                result['dates']['normalized'].append(date)  # сохраняем исходную дату
            except:
                result['dates']['invalid'].append(date)

    return result


def main():
    """
    Основная логика запуска. Читает файл, запускает проверки, пишет отчеты.
    """
    # Используем junk.txt как в условии
    input_file = "Текстовый документ.txt"
    artifacts_file = "artifacts.txt"

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            text = file.read()

        print(f"--- Запуск анализа файла {input_file} ---\n")

        # 1. Карты
        cards_result = find_and_validate_credit_cards(text)
        print(f"[{len(cards_result['valid'])}] ВАЛИДНЫЕ КАРТЫ (Luhn OK):")
        for c in cards_result['valid']:
            print(f"  {c}")

        # 2. Логи
        logs_result = analyze_logs(text)
        print(f"\n[{sum(len(v) for v in logs_result.values())}] НАЙДЕННЫЕ УГРОЗЫ В ЛОГАХ:")
        for category, items in logs_result.items():
            if items:
                print(f"  > {category}:")
                for item in items:
                    print(f"    - {item}")

        # 3. Данные
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

        # --- Сбор всех уникальных артефактов (INVALID) ---
        unique_artifacts = set()

        unique_artifacts.update(cards_result['invalid'])
        unique_artifacts.update(norm_result['inn']['invalid'])
        unique_artifacts.update(norm_result['phones']['invalid'])
        unique_artifacts.update(norm_result['dates']['invalid'])

        # Добавляем атаки из логов как артефакты
        for k, v in logs_result.items():
            unique_artifacts.update(v)

        print(f"\n------------------------------------------------")
        print(f"Количество уникальных артефактов (сохранено в файл): {len(unique_artifacts)}")

        with open(artifacts_file, "w", encoding="utf-8") as f_out:
            f_out.write("--- REPORT: INVALID ARTIFACTS & SUSPICIOUS DATA ---\n")
            for item in sorted(unique_artifacts):
                f_out.write(f"{item}\n")

        print(f"Файл {artifacts_file} успешно записан.")

    except FileNotFoundError:
        print(f"ОШИБКА: Файл {input_file} не найден. Пожалуйста, создайте его.")
    except Exception as e:
        print(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")


if __name__ == "__main__":
    main()
