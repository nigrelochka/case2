
def main():
    # --- ИЗМЕНЕНО: список файлов для анализа ---
    input_files = ["text1.txt", "text2.txt", "text3.txt", "text4.txt"] # Добавьте сюда свои файлы
    artifacts_file = "artifacts.txt"

    # --- ИЗМЕНЕНО: переменные для хранения общих результатов ---
    all_cards_result = {'valid': [], 'invalid': []}
    all_logs_result = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }
    all_norm_result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []}
    }
    all_secrets = {'api_keys': [], 'passwords': [], 'tokens': []}
    all_system_info = {'ips': [], 'files': [], 'emails': []}
    all_decoded = {'base64': [], 'hex': [], 'rot13': []}
    all_unique_artifacts = set()

    print(f"--- Запуск анализа файлов {', '.join(input_files)} ---\n")

    # --- ЦИКЛ ПО ВСЕМ ФАЙЛАМ ---
    for input_file in input_files:
        try:
            with open(input_file, "r", encoding="utf-8") as file:
                text = file.read()
            print(f"--- Анализ файла {input_file} ---")

            # 1. Cards
            cards_result = find_and_validate_credit_cards(text)
            # --- ИЗМЕНЕНО: суммируем результаты ---
            all_cards_result['valid'].extend(cards_result['valid'])
            all_cards_result['invalid'].extend(cards_result['invalid'])

            # 2. Logins
            logs_result = analyze_logs(text)
            # --- ИЗМЕНЕНО: суммируем результаты ---
            for key in all_logs_result:
                all_logs_result[key].extend(logs_result[key])

            # 3. Data (INN, Phones, Dates)
            norm_result = normalize_and_validate(text)
            # --- ИЗМЕНЕНО: суммируем результаты ---
            for key in all_norm_result:
                if isinstance(all_norm_result[key], dict):
                    for sub_key in all_norm_result[key]:
                         all_norm_result[key][sub_key].extend(norm_result[key][sub_key])
                else:
                     all_norm_result[key].extend(norm_result[key])

            # 4. Secrets
            secrets = find_secrets(text)
            # --- ИЗМЕНЕНО: суммируем результаты ---
            for key in all_secrets:
                all_secrets[key].extend(secrets[key])

            # 5. System Info
            system_info = find_system_info(text)
            # --- ИЗМЕНЕНО: суммируем результаты ---
            for key in all_system_info:
                all_system_info[key].extend(system_info[key])

            # 6. Decoded Messages
            decoded = decode_messages(text)
            # --- ИЗМЕНЕНО: суммируем результаты ---
            for key in all_decoded:
                all_decoded[key].extend(decoded[key])


            # --- ВЫВОД РЕЗУЛЬТАТОВ ПО ТЕКУЩЕМУ ФАЙЛУ (опционально) ---
            print(f"  [{len(cards_result['valid'])}] ВАЛИДНЫЕ КАРТЫ (Luhn OK): {cards_result['valid'][:3]}...") # Показываем первые 3
            print(f"  [{len(secrets['api_keys'])}] API-ключи: {secrets['api_keys'][:3]}...") # Показываем первые 3
            print(f"  [{len(system_info['ips'])}] IP-адреса: {system_info['ips'][:3]}...") # Показываем первые 3
            print(f"  [{len(decoded['base64'])}] Base64 сообщения: {len(decoded['base64'])} найдено")
            print(f"  [{len(logs_result['sql_injections'])}] SQL-инъекции: {len(logs_result['sql_injections'])} найдено")
            print(f"  --- Конец анализа {input_file} ---\n")


        except FileNotFoundError:
            print(f"ОШИБКА: Файл {input_file} не найден. Пропускаю.")
        except Exception as e:
            print(f"КРИТИЧЕСКАЯ ОШИБКА при чтении {input_file}: {e}")

    # --- УДАЛЕНИЕ ДУБЛИКАТОВ ИЗ ОБЪЕДИНЁННЫХ РЕЗУЛЬТАТОВ ---
    # Для списков в словарях
    for key in all_cards_result:
        all_cards_result[key] = list(set(all_cards_result[key]))
    for key in all_logs_result:
        all_logs_result[key] = list(set(all_logs_result[key]))
    for key in all_norm_result:
        if isinstance(all_norm_result[key], dict):
            for sub_key in all_norm_result[key]:
                all_norm_result[key][sub_key] = list(set(all_norm_result[key][sub_key]))
        else:
             all_norm_result[key] = list(set(all_norm_result[key]))
    for key in all_secrets:
        all_secrets[key] = list(set(all_secrets[key]))
    for key in all_system_info:
        all_system_info[key] = list(set(all_system_info[key]))
    for key in all_decoded:
        # Для decoded, где элементы словари, нужно хранить уникальные строки
        unique_decoded_items = set()
        for item in all_decoded[key]:
            # Создаём уникальный ключ из словаря
            unique_key = (item['encoded'], item['decoded'])
            unique_decoded_items.add(unique_key)
        # Восстанавливаем список словарей из уникальных ключей
        all_decoded[key] = [{'encoded': k[0], 'decoded': k[1]} for k in unique_decoded_items]


    # --- ВЫВОД ОБОБЩЁННЫХ РЕЗУЛЬТАТОВ ---
    print("="*60)
    print("ОБОБЩЁННЫЕ РЕЗУЛЬТАТЫ ПО ВСЕМ ФАЙЛАМ:")
    print("="*60)

    print(f"\n[{len(all_cards_result['valid'])}] ВАЛИДНЫЕ КАРТЫ (Luhn OK):")
    for c in all_cards_result['valid']:
        print(f"  {c}")

    print(f"\n[{sum(len(v) for v in all_logs_result.values())}] НАЙДЕННЫЕ УГРОЗЫ В ЛОГАХ:")
    for category, items in all_logs_result.items():
        if items:
            print(f"   > {category}: {len(items)} найдено")

    print(f"\n[{len(all_norm_result['inn']['valid'])}] ВАЛИДНЫЕ ИНН:")
    for inn in all_norm_result['inn']['valid']:
        print(f"  {inn}")
    print(f"\n[{len(all_norm_result['phones']['valid'])}] ВАЛИДНЫЕ ТЕЛЕФОНЫ:")
    for ph in all_norm_result['phones']['valid']:
        print(f"  {ph}")
    print(f"\n[{len(all_norm_result['dates']['normalized'])}] ВАЛИДНЫЕ ДАТЫ (нормализованные):")
    for date in all_norm_result['dates']['normalized']:
        print(f"  {date}")

    print(f"\n[{sum(len(v) for v in all_secrets.values())}] НАЙДЕННЫЕ СЕКРЕТЫ:")
    for cat, items in all_secrets.items():
        if items:
            print(f"  {cat}: {len(items)} найдено")

    print(f"\n[{len(all_system_info['ips'])}] IP-АДРЕСА:")
    if all_system_info['ips']:
        print(f"  {', '.join(all_system_info['ips'])}")

    print(f"\n[{len(all_system_info['files'])}] ФАЙЛЫ:")
    if all_system_info['files']:
        print(f"  {', '.join(all_system_info['files'])}")

    print(f"\n[{len(all_system_info['emails'])}] EMAIL:")
    if all_system_info['emails']:
        print(f"  {', '.join(all_system_info['emails'])}")

    print(f"\n[{sum(len(v) for v in all_decoded.values())}] РАСШИФРОВАННЫЕ СООБЩЕНИЯ:")
    for cat, items in all_decoded.items():
        if items:
            print(f"  {cat}: {len(items)} найдено")


    # --- СОЗДАНИЕ ОБЩЕГО СПИСКА АРТЕФАКТОВ ---
    # Используем объединённые результаты для поиска артефактов
    valid_data = set()
    for lst in all_secrets.values():
        valid_data.update(lst)
    for lst in all_system_info.values():
        valid_data.update(lst)
    for item_list in all_decoded.values():
         for item in item_list:
             valid_data.add(item['encoded'])

    # Проходим по каждому файлу снова, чтобы найти артефакты в каждом
    for input_file in input_files:
        try:
            with open(input_file, "r", encoding="utf-8") as file:
                text = file.read()
            # Ищем артефакты в текущем файле, исключая валидные данные из всех файлов
            new_artifacts = find_artifacts(text, valid_data)
            all_unique_artifacts.update(new_artifacts)
        except FileNotFoundError:
            print(f"ОШИБКА: Файл {input_file} не найден при поиске артефактов.")
        except Exception as e:
            print(f"КРИТИЧЕСКАЯ ОШИБКА при поиске артефактов в {input_file}: {e}")

    # Также добавляем невалидные данные из нормализации и логов в артефакты
    all_unique_artifacts.update(all_cards_result['invalid'])
    all_unique_artifacts.update(all_norm_result['inn']['invalid'])
    all_unique_artifacts.update(all_norm_result['phones']['invalid'])
    all_unique_artifacts.update(all_norm_result['dates']['invalid'])
    for k, v in all_logs_result.items():
        all_unique_artifacts.update(v)


    print(f"\n------------------------------------------------")
    print(f"Количество уникальных артефактов (сохранено в файл): {len(all_unique_artifacts)}")

    # --- ЗАПИСЬ ВСЕХ АРТЕФАКТОВ В ОДИН ФАЙЛ ---
    try:
        with open(artifacts_file, "w", encoding="utf-8") as f_out:
            f_out.write("--- REPORT: INVALID ARTIFACTS & SUSPICIOUS DATA ---\n")
            f_out.write(f"Files analyzed: {', '.join(input_files)}\n")
            f_out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for item in sorted(all_unique_artifacts):
                f_out.write(f"{item}\n")

        print(f"Файл {artifacts_file} успешно записан.")

    except Exception as e:
        print(f"КРИТИЧЕСКАЯ ОШИБКА при записи в {artifacts_file}: {e}")


if __name__ == "__main__":
    main()
