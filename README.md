## 📁 **СТРУКТУРА ПРОЕКТА API SECURITY SCANNER**

```
api-security-scanner/
├── 📄 pom.xml
├── 📄 README.md
├── 📄 .gitignore
├── 🎯 target/
│   └── 📊 reports/
│       ├── VirtualBankAPI-YYYYMMDD-HHMMSS.json
│       └── VirtualBankAPI-YYYYMMDD-HHMMSS.pdf
└── 📂 src/
    └── 📂 main/
        └── 📂 java/
            └── 📂 securityscanner/
                ├── 🎯 auditor/
                │   └── 📄 APISecurityAuditor.java
                ├── 🔧 core/
                │   ├── 📄 ExecutionContext.java
                │   ├── 📄 PluginRegistry.java
                │   ├── 📄 SecurityPlugin.java
                │   ├── 📄 ResponseValidator.java
                │   └── 📂 model/
                │       └── 📄 Finding.java
                ├── 🎲 generator/
                │   └── 📄 ScenarioGenerator.java
                ├── 🌐 http/
                │   └── 📄 RequestExecutor.java
                ├── 📖 parser/
                │   └── 📄 OpenAPIParserSimple.java
                ├── 🔌 plugins/          # OWASP API Top 10 2023
                │   ├── 📄 BolaPlugin.java                    # API1:2023
                │   ├── 📄 BrokenAuthPlugin.java              # API2:2023
                │   ├── 📄 ObjectPropertyAuthPlugin.java      # API3:2023
                │   ├── 📄 ResourceConsumptionPlugin.java     # API4:2023
                │   ├── 📄 BrokenFunctionAuthPlugin.java      # API5:2023
                │   ├── 📄 BusinessFlowPlugin.java            # API6:2023
                │   ├── 📄 SSRFPlugin.java                    # API7:2023
                │   ├── 📄 SecurityMisconfigPlugin.java       # API8:2023
                │   ├── 📄 InventoryManagementPlugin.java     # API9:2023
                │   ├── 📄 UnsafeConsumptionPlugin.java       # API10:2023
                │   └── 📄 InjectionPlugin.java               # Дополнительный
                ├── 📊 report/
                │   ├── 📄 ReportWriter.java
                │   └── 📄 ResponseValidator.java
                └── 🚀 runner/
                    └── 📄 BankingAPIScanner.java
```

---

# 🔍 API Security Scanner

**Автоматизированный сканер безопасности API с полным покрытием OWASP API Top 10 2023**

## 🎯 Возможности

- ✅ **Полное покрытие OWASP API Top 10 2023** - 10/10 категорий
- 🔍 **Автоматическое сканирование** - один клик для комплексной проверки
- 📊 **Профессиональные отчеты** - JSON и PDF форматы
- 🔧 **Интеграция с CI/CD** - готовность к DevOps процессам
- 🌐 **Поддержка OpenAPI** - автоматический парсинг спецификаций

## 🚀 Быстрый старт

### 1. Сборка проекта
```bash
mvn clean package
```

### 2. Запуск сканирования
```powershell
java -jar target/api-security-scanner-1.0-SNAPSHOT.jar `
  --openapi https://vbank.open.bankingapi.ru/openapi.json `
  --base-url https://vbank.open.bankingapi.ru `
  --auth "bearer:YOUR_TOKEN" `
  --requesting-bank team184 `
  --client team184-1 `
  --create-consent true `
  --verbose
```

### 3. Просмотр результатов
Отчеты сохраняются в `target/reports/`:
- `VirtualBankAPI-YYYYMMDD-HHMMSS.json`
- `VirtualBankAPI-YYYYMMDD-HHMMSS.pdf`

## 📋 Параметры запуска

| Параметр | Обязательный | Описание |
|----------|--------------|-----------|
| `--openapi` | ✅ | URL или путь к OpenAPI спецификации |
| `--base-url` | ✅ | Базовый URL API |
| `--auth` | ✅ | Токен аутентификации (`bearer:TOKEN`) |
| `--requesting-bank` | ✅ | Идентификатор банка (например, `team184`) |
| `--client` | ✅ | Идентификатор клиента (например, `team184-1`) |
| `--create-consent` | ❌ | Создание согласия (по умолчанию: `true`) |
| `--verbose` | ❌ | Подробный вывод (по умолчанию: `false`) |

## 🛡️ Покрытие OWASP API Top 10 2023

| Категория | Статус | Описание |
|-----------|--------|-----------|
| **API1:2023** - Broken Object Level Authorization | ✅ | Проверка доступа к чужим данным |
| **API2:2023** - Broken Authentication | ✅ | Тестирование аутентификации |
| **API3:2023** - Broken Object Property Level Authorization | ✅ | Проверка свойств объектов |
| **API4:2023** - Unrestricted Resource Consumption | ✅ | Тестирование ограничений ресурсов |
| **API5:2023** - Broken Function Level Authorization | ✅ | Проверка авторизации функций |
| **API6:2023** - Unrestricted Access to Sensitive Business Flows | ✅ | Тестирование бизнес-процессов |
| **API7:2023** - Server Side Request Forgery | ✅ | Проверка SSRF уязвимостей |
| **API8:2023** - Security Misconfiguration | ✅ | Поиск misconfiguration |
| **API9:2023** - Improper Inventory Management | ✅ | Анализ управления API |
| **API10:2023** - Unsafe Consumption of APIs | ✅ | Проверка внешних API |