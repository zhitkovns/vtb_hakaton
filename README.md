## **СТРУКТУРА ПРОЕКТА API SECURITY SCANNER**

```
api-security-scanner/
├── pom.xml
├── README.md
├── run_scan.ps1
├── scanner.env.example
├── .gitignore
├── reports/                                            # Генерируемые отчеты
├── target/
│   └── reports/
│       ├── {BankName}-SecurityReport-YYYYMMDD-HHMMSS.json
│       └── {BankName}-SecurityReport-YYYYMMDD-HHMMSS.pdf
└── src/
    └── main/
        └── java/
            └── securityscanner/
                ├── auditor/                            # Основная логика сканирования
                │   └── APISecurityAuditor.java
                ├── core/                               # Базовые компоненты
                │   ├── ExecutionContext.java           # Контекст выполнения
                │   ├── PluginRegistry.java             # Реестр плагинов
                │   ├── SecurityPlugin.java             # Интерфейс плагинов
                │   ├── BaseSecurityPlugin.java         # Базовая реализация
                │   ├── ResponseValidator.java          # Валидатор ответов
                │   └── model/
                │       └── Finding.java                # Модель уязвимости
                ├── generator/                          # Генерация тестовых сценариев
                │   └── ScenarioGenerator.java
                ├── http/                               # HTTP клиент
                │   └── RequestExecutor.java
                ├── parser/                             # Парсер OpenAPI
                │   └── OpenAPIParserSimple.java
                ├── plugins/                            # Плагины безопасности
                │   ├── APIHealthPlugin.java            # Проверка здоровья API
                │   ├── AuthenticationPlugin.java       # Аутентификация
                │   ├── BolaPlugin.java                 # BOLA/IDOR
                │   ├── BrokenFunctionAuthPlugin.java   # Функциональная авторизация
                │   ├── BusinessFlowPlugin.java         # Бизнес-процессы
                │   ├── InjectionPlugin.java            # Инъекции
                │   ├── InventoryManagementPlugin.java  # Управление инвентарем
                │   ├── ObjectPropertyAuthPlugin.java   # Авторизация свойств
                │   ├── ResourceConsumptionPlugin.java  # Потребление ресурсов
                │   ├── SecurityMisconfigPlugin.java    # Конфигурация
                │   ├── SSRFPlugin.java                 # SSRF атаки
                │   └── UnsafeConsumptionPlugin.java    # Потребление API
                ├── report/                             # Генерация отчетов
                │   └── ReportWriter.java
                └── runner/                             # Точка входа
                    └── BankingAPIScanner.java

```

---

# API Security Scanner

Автоматизированный сканер безопасности API для банковских систем с поддержкой Open Banking API.

## Технические требования

- Java 17 или выше
- Maven 3.6+
- Доступ к тестовым стендам банков (vbank, abank, sbank)

## Конфигурация

### Файл окружения

Создайте файл `scanner.env` (или он создаться автоматически при запуске скрипта, попросив сначала ввести необходимые данные) в корне проекта на основе `scanner.env.example`:

```properties
SELECTED_BANK=sbank          # Выбранный банк: vbank, abank, sbank
CLIENT_ID=team184            # Идентификатор команды
CLIENT_SECRET=your_secret    # Секретный ключ
INTERBANK_CLIENT=team184-1   # Идентификатор клиента
```

### Поддерживаемые банки

- **Virtual Bank** (vbank) - https://vbank.open.bankingapi.ru
- **Awesome Bank** (abank) - https://abank.open.bankingapi.ru  
- **Smart Bank** (sbank) - https://sbank.open.bankingapi.ru

## Сборка проекта

```powershell
mvn clean compile package
```

## Запуск сканирования

### Автоматический запуск (рекомендуется)

```powershell
powershell -ExecutionPolicy Bypass -File "run_scan.ps1"
```

Скрипт выполнит:
- Выбор банка и клиента
- Аутентификацию и получение токена
- Создание согласия (consent) при необходимости
- Запуск полного сканирования безопасности

### Ручной запуск

```powershell
java -jar target/api-security-scanner-1.0-SNAPSHOT.jar ^
  --openapi https://sbank.open.bankingapi.ru/openapi.json ^
  --base-url https://sbank.open.bankingapi.ru ^
  --auth "bearer:YOUR_TOKEN" ^
  --requesting-bank team184 ^
  --client team184-1 ^
  --create-consent true ^
  --verbose
```

## Параметры командной строки

- `--openapi` - URL OpenAPI спецификации
- `--base-url` - Базовый URL API
- `--auth` - Токен аутентификации (bearer:token)
- `--client-id` - Идентификатор клиента
- `--client-secret` - Секретный ключ
- `--requesting-bank` - Идентификатор банка-инициатора
- `--client` - Идентификатор клиента для межбанковых операций
- `--create-consent` - Создавать согласие (true/false)
- `--verbose` - Подробный вывод
- `--add-header` - Дополнительные заголовки (можно несколько)

## Проверяемые уязвимости

Сканер покрывает OWASP API Security Top 10:

- **API1** - Broken Object Level Authorization (BOLA/IDOR)
- **API2** - Broken Authentication
- **API3** - Broken Object Property Level Authorization  
- **API4** - Unrestricted Resource Consumption
- **API5** - Broken Function Level Authorization
- **API6** - Unrestricted Access to Sensitive Business Flows
- **API7** - Server Side Request Forgery (SSRF)
- **API8** - Security Misconfiguration
- **API9** - Improper Inventory Management
- **API10** - Unsafe Consumption of APIs

## Дополнительные проверки

- Валидация соответствия API контракту (OpenAPI schema)
- Проверка безопасности заголовков
- Обнаружение скрытых эндпоинтов
- Тестирование на переполнение ресурсов
- Проверка механизмов аутентификации и авторизации

## Форматы отчетов

После сканирования генерируются отчеты в папке `target/reports/`:

- **JSON** - `{BankName}-SecurityReport-YYYYMMDD-HHMMSS.json`
  - Структурированные данные для автоматической обработки
  - Метаинформация, статистика, детали уязвимостей
  - Интеграция с CI/CD системами

- **PDF** - `{BankName}-SecurityReport-YYYYMMDD-HHMMSS.pdf`
  - Детальный отчет для ручного анализа
  - Сводная статистика и рекомендации
  - Группировка по категориям OWASP

## Интеграция в CI/CD

Проект может быть интегрирован в процессы непрерывной интеграции:

```yaml
# Пример GitHub Actions
- name: API Security Scan
  run: |
    java -jar api-security-scanner.jar \
      --openapi ${{ secrets.OPENAPI_URL }} \
      --base-url ${{ secrets.API_BASE_URL }} \
      --auth "bearer:${{ secrets.API_TOKEN }}" \
      --create-consent false
```

## Архитектура

Сканер использует модульную архитектуру с плагинами:

1. **Парсинг OpenAPI** - анализ спецификации API
2. **Генерация сценариев** - создание тестовых запросов
3. **Выполнение запросов** - отправка HTTP запросов
4. **Валидация ответов** - проверка соответствия контракту
5. **Плагины безопасности** - специализированные проверки
6. **Генерация отчетов** - формирование результатов

## Логирование и отладка

Используйте параметр `--verbose` для подробного вывода:

```powershell
java -jar target/api-security-scanner-1.0-SNAPSHOT.jar --verbose
```

Логи включают:
- Выполняемые HTTP запросы
- Статус коды ответов
- Прогресс выполнения плагинов
- Обнаруженные уязвимости

## Процесс сканирования

1. **Инициализация** - загрузка конфигурации и аутентификация
2. **Анализ OpenAPI** - парсинг спецификации и извлечение эндпоинтов
3. **Создание согласия** - формирование consent для доступа к данным
4. **Генерация сценариев** - создание тестовых случаев на основе спецификации
5. **Выполнение тестов** - отправка запросов и анализ ответов
6. **Запуск плагинов** - выполнение специализированных проверок безопасности
7. **Валидация контракта** - проверка соответствия ответов спецификации
8. **Генерация отчетов** - формирование результатов в JSON и PDF форматах

## Обработка ошибок

Сканер обрабатывает следующие сценарии:
- Ошибки аутентификации и авторизации
- Отсутствие необходимых согласий (consent)
- Недоступность эндпоинтов API
- Несоответствие ответов OpenAPI спецификации
- Ограничения rate limiting

## Безопасность

- Токены аутентификации не сохраняются в отчетах
- Конфиденциальные данные маскируются в логах
- Поддержка безопасного хранения секретов через переменные окружения

## Ограничения

- Требуется действительный доступ к тестовым стендам банков
- Необходимы корректные client_id и client_secret
- Для полного тестирования требуется создание согласий
- Сканирование может занимать несколько минут в зависимости от размера API (но менее 5 минут)
