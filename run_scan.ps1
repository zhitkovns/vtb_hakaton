# --- Paths / defaults ---
$JAR = "target\api-security-scanner-1.0-SNAPSHOT.jar"

# --- Clear credentials to force re-entry ---
Remove-Item Env:CLIENT_ID -ErrorAction SilentlyContinue
Remove-Item Env:CLIENT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:BANK_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:REQUESTING_BANK -ErrorAction SilentlyContinue
Remove-Item Env:INTERBANK_CLIENT -ErrorAction SilentlyContinue
Remove-Item Env:SELECTED_BANK -ErrorAction SilentlyContinue

# --- Load scanner.env if exists ---
if (Test-Path "scanner.env") {
    Write-Host "Loading scanner.env..."
    Get-Content "scanner.env" | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            $name = $matches[1]
            $value = $matches[2]
            Set-Item -Path "env:$name" -Value $value
        }
    }
}

# --- Bank selection ---
if (-not $env:SELECTED_BANK) {
    Write-Host "`n=== ВЫБОР БАНКА ===" -ForegroundColor Green
    Write-Host "1 - Virtual Bank (vbank)"
    Write-Host "2 - Awesome Bank (abank)" 
    Write-Host "3 - Smart Bank (sbank)"
    
    do {
        $bankChoice = Read-Host "`nВведите номер банка (1-3)"
        switch ($bankChoice) {
            "1" { 
                $env:SELECTED_BANK = "vbank"
                Write-Host "Выбран Virtual Bank" -ForegroundColor Green
                break
            }
            "2" { 
                $env:SELECTED_BANK = "abank"
                Write-Host "Выбран Awesome Bank" -ForegroundColor Green
                break
            }
            "3" { 
                $env:SELECTED_BANK = "sbank"
                Write-Host "Выбран Smart Bank" -ForegroundColor Green
                break
            }
            default { 
                Write-Host "Ошибка: введите число от 1 до 3" -ForegroundColor Red
            }
        }
    } while (-not $env:SELECTED_BANK)
} else {
    Write-Host "Используется предварительно выбранный банк: $env:SELECTED_BANK" -ForegroundColor Yellow
}

# --- Set URLs based on selected bank ---
$OPENAPI = "https://$env:SELECTED_BANK.open.bankingapi.ru/openapi.json"
$BASEURL = "https://$env:SELECTED_BANK.open.bankingapi.ru"

Write-Host "`n=== НАСТРОЙКИ БАНКА ===" -ForegroundColor Green
Write-Host "Банк: $env:SELECTED_BANK"
Write-Host "OpenAPI: $OPENAPI"
Write-Host "Base URL: $BASEURL"

# --- If CLIENT_ID or CLIENT_SECRET missing, prompt ---
if (-not $env:CLIENT_ID) {
    Write-Host "`n=== АУТЕНТИФИКАЦИЯ ===" -ForegroundColor Green
    $env:CLIENT_ID = Read-Host "Введите CLIENT_ID"
}

if (-not $env:CLIENT_SECRET) {
    Write-Host "Введите CLIENT_SECRET: " -NoNewline
    $secureSecret = Read-Host -AsSecureString
    # Правильное преобразование SecureString в plain text
    $env:CLIENT_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret))
}

# --- Request additional fields if missing ---
if (-not $env:REQUESTING_BANK) {
    Write-Host "`n=== ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ ===" -ForegroundColor Green
    $env:REQUESTING_BANK = Read-Host "Введите REQUESTING_BANK (по умолчанию: team184)"
    if (-not $env:REQUESTING_BANK) { $env:REQUESTING_BANK = "team184" }
}

# --- Client number selection ---
if (-not $env:INTERBANK_CLIENT) {
    Write-Host "`n=== ВЫБОР КЛИЕНТА ===" -ForegroundColor Green
    Write-Host "Доступные номера клиентов:"
    for ($i = 1; $i -le 10; $i++) {
        Write-Host "$i - $env:REQUESTING_BANK-$i"
    }
    
    do {
        $clientInput = Read-Host "`nВведите номер клиента (1-10)"
        if ($clientInput -match "^\d+$" -and [int]$clientInput -ge 1 -and [int]$clientInput -le 10) {
            $clientNumber = [int]$clientInput
            $env:INTERBANK_CLIENT = "$env:REQUESTING_BANK-$clientNumber"
            Write-Host "Выбран клиент: $env:INTERBANK_CLIENT" -ForegroundColor Green
            break
        } else {
            Write-Host "Ошибка: введите число от 1 до 10" -ForegroundColor Red
        }
    } while ($true)
} else {
    Write-Host "Используется предварительно выбранный клиент: $env:INTERBANK_CLIENT" -ForegroundColor Yellow
}

# --- Ensure we have required values ---
if (-not $env:CLIENT_ID) {
    Write-Error "ОШИБКА: CLIENT_ID обязателен."
    pause
    exit 1
}

if (-not $env:CLIENT_SECRET) {
    Write-Error "ОШИБКА: CLIENT_SECRET обязателен."
    pause
    exit 1
}

# --- Create scanner.env if it doesn't exist ---
if (-not (Test-Path "scanner.env")) {
    Write-Host "`nСоздание файла scanner.env..." -ForegroundColor Green
    @"
SELECTED_BANK=$env:SELECTED_BANK
CLIENT_ID=$env:CLIENT_ID
CLIENT_SECRET=$env:CLIENT_SECRET
REQUESTING_BANK=$env:REQUESTING_BANK
INTERBANK_CLIENT=$env:INTERBANK_CLIENT
"@ | Out-File -FilePath "scanner.env" -Encoding ASCII
    
    Write-Host "scanner.env создан со значениями:"
    Write-Host "SELECTED_BANK: $env:SELECTED_BANK"
    Write-Host "CLIENT_ID: $env:CLIENT_ID"
    Write-Host "REQUESTING_BANK: $env:REQUESTING_BANK" 
    Write-Host "INTERBANK_CLIENT: $env:INTERBANK_CLIENT"
}

# --- Obtain BANK_TOKEN if not set ---
if (-not $env:BANK_TOKEN) {
    Write-Host "`n=== ПОЛУЧЕНИЕ ТОКЕНА ===" -ForegroundColor Green
    Write-Host "Получение BANK_TOKEN..."
    try {
        $uri = "$BASEURL/auth/bank-token?client_id=$env:CLIENT_ID&client_secret=$env:CLIENT_SECRET"
        Write-Host "URL запроса: $uri"
        $tokenResponse = Invoke-RestMethod -Method POST -Uri $uri
        $env:BANK_TOKEN = $tokenResponse.access_token
        Write-Host "BANK_TOKEN успешно получен" -ForegroundColor Green
    } catch {
        Write-Error "Ошибка получения BANK_TOKEN: $_"
        Write-Host "Пожалуйста, проверьте ваш CLIENT_ID и CLIENT_SECRET"
        pause
        exit 1
    }
}

# --- Set report title based on selected bank ---
$BANK_NAMES = @{
    "vbank" = "Virtual Bank"
    "abank" = "Awesome Bank" 
    "sbank" = "Smart Bank"
}
$REPORT_TITLE = "$($BANK_NAMES[$env:SELECTED_BANK]) API Security Report"

# --- Run scanner ---
Write-Host "`n=== ЗАПУСК СКАНЕРА ===" -ForegroundColor Green
Write-Host "Запуск сканера для $($BANK_NAMES[$env:SELECTED_BANK])..."
java -jar "$JAR" --openapi $OPENAPI --base-url $BASEURL --auth "bearer:$env:BANK_TOKEN" --requesting-bank $env:REQUESTING_BANK --client $env:INTERBANK_CLIENT --create-consent true --verbose

Write-Host "`n=== ЗАВЕРШЕНИЕ ===" -ForegroundColor Green
Write-Host "Отчеты сохранены в папку: reports\"
Write-Host "Примечание: Отчеты сохраняются в папку 'reports' и сохраняются между сборками"
pause