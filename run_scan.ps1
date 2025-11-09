# --- Paths / defaults ---
$JAR = "target\api-security-scanner-1.0-SNAPSHOT.jar"

# --- Clear credentials to force re-entry ---
Remove-Item Env:CLIENT_ID -ErrorAction SilentlyContinue
Remove-Item Env:CLIENT_SECRET -ErrorAction SilentlyContinue
Remove-Item Env:BANK_TOKEN -ErrorAction SilentlyContinue
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
Write-Host "`n=== BANK SELECTION ===" -ForegroundColor Green
Write-Host "1 - Virtual Bank (vbank)"
Write-Host "2 - Awesome Bank (abank)" 
Write-Host "3 - Smart Bank (sbank)"

if ($env:SELECTED_BANK) {
    Write-Host "Current selection: $env:SELECTED_BANK" -ForegroundColor Yellow
    $changeBank = Read-Host "Change bank? (y/n)"
    if ($changeBank -eq 'y' -or $changeBank -eq 'Y') {
        $env:SELECTED_BANK = $null
    }
}

if (-not $env:SELECTED_BANK) {
    do {
        $bankChoice = Read-Host "`nEnter bank number (1-3)"
        switch ($bankChoice) {
            "1" { 
                $env:SELECTED_BANK = "vbank"
                Write-Host "Selected Virtual Bank" -ForegroundColor Green
                break
            }
            "2" { 
                $env:SELECTED_BANK = "abank"
                Write-Host "Selected Awesome Bank" -ForegroundColor Green
                break
            }
            "3" { 
                $env:SELECTED_BANK = "sbank"
                Write-Host "Selected Smart Bank" -ForegroundColor Green
                break
            }
            default { 
                Write-Host "Error: enter number from 1 to 3" -ForegroundColor Red
            }
        }
    } while (-not $env:SELECTED_BANK)
} else {
    Write-Host "Using bank: $env:SELECTED_BANK" -ForegroundColor Green
}

# --- Set URLs based on selected bank ---
$OPENAPI = "https://$env:SELECTED_BANK.open.bankingapi.ru/openapi.json"
$BASEURL = "https://$env:SELECTED_BANK.open.bankingapi.ru"

Write-Host "`n=== BANK SETTINGS ===" -ForegroundColor Green
Write-Host "Bank: $env:SELECTED_BANK"
Write-Host "OpenAPI: $OPENAPI"
Write-Host "Base URL: $BASEURL"

# --- If CLIENT_ID or CLIENT_SECRET missing, prompt ---
if (-not $env:CLIENT_ID) {
    Write-Host "`n=== AUTHENTICATION ===" -ForegroundColor Green
    $env:CLIENT_ID = Read-Host "Enter CLIENT_ID"
} else {
    Write-Host "Using CLIENT_ID: $env:CLIENT_ID" -ForegroundColor Green
}

if (-not $env:CLIENT_SECRET) {
    Write-Host "Enter CLIENT_SECRET: " -NoNewline
    $secureSecret = Read-Host -AsSecureString
    # Convert SecureString to plain text
    $env:CLIENT_SECRET = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret))
} else {
    Write-Host "CLIENT_SECRET: [already set]" -ForegroundColor Green
}

# --- Client number selection ---
Write-Host "`n=== CLIENT SELECTION ===" -ForegroundColor Green
Write-Host "Available client numbers for $env:CLIENT_ID:"
for ($i = 1; $i -le 10; $i++) {
    Write-Host "$i - $env:CLIENT_ID-$i"
}

if ($env:INTERBANK_CLIENT) {
    Write-Host "Current selection: $env:INTERBANK_CLIENT" -ForegroundColor Yellow
    $changeClient = Read-Host "Change client? (y/n)"
    if ($changeClient -eq 'y' -or $changeClient -eq 'Y') {
        $env:INTERBANK_CLIENT = $null
    }
}

if (-not $env:INTERBANK_CLIENT) {
    do {
        $clientInput = Read-Host "`nEnter client number (1-10)"
        if ($clientInput -match "^\d+$" -and [int]$clientInput -ge 1 -and [int]$clientInput -le 10) {
            $clientNumber = [int]$clientInput
            $env:INTERBANK_CLIENT = "$env:CLIENT_ID-$clientNumber"
            Write-Host "Selected client: $env:INTERBANK_CLIENT" -ForegroundColor Green
            break
        } else {
            Write-Host "Error: enter number from 1 to 10" -ForegroundColor Red
        }
    } while ($true)
} else {
    Write-Host "Using client: $env:INTERBANK_CLIENT" -ForegroundColor Green
}

# --- Ensure we have required values ---
if (-not $env:CLIENT_ID) {
    Write-Error "ERROR: CLIENT_ID is required."
    pause
    exit 1
}

if (-not $env:CLIENT_SECRET) {
    Write-Error "ERROR: CLIENT_SECRET is required."
    pause
    exit 1
}

# --- Create scanner.env if it doesn't exist ---
if (-not (Test-Path "scanner.env")) {
    Write-Host "`nCreating scanner.env file..." -ForegroundColor Green
    $envFileContent = @"
SELECTED_BANK=$env:SELECTED_BANK
CLIENT_ID=$env:CLIENT_ID
CLIENT_SECRET=$env:CLIENT_SECRET
INTERBANK_CLIENT=$env:INTERBANK_CLIENT
"@
    $envFileContent | Out-File -FilePath "scanner.env" -Encoding ASCII
    
    Write-Host "scanner.env created with values:"
    Write-Host "SELECTED_BANK: $env:SELECTED_BANK"
    Write-Host "CLIENT_ID: $env:CLIENT_ID"
    Write-Host "INTERBANK_CLIENT: $env:INTERBANK_CLIENT"
} else {
    # Update existing scanner.env with new values
    Write-Host "`nUpdating scanner.env file..." -ForegroundColor Green
    $envFileContent = @"
SELECTED_BANK=$env:SELECTED_BANK
CLIENT_ID=$env:CLIENT_ID
CLIENT_SECRET=$env:CLIENT_SECRET
INTERBANK_CLIENT=$env:INTERBANK_CLIENT
"@
    $envFileContent | Out-File -FilePath "scanner.env" -Encoding ASCII
    
    Write-Host "scanner.env updated with values:"
    Write-Host "SELECTED_BANK: $env:SELECTED_BANK"
    Write-Host "CLIENT_ID: $env:CLIENT_ID"
    Write-Host "INTERBANK_CLIENT: $env:INTERBANK_CLIENT"
}

# --- Obtain BANK_TOKEN if not set ---
if (-not $env:BANK_TOKEN) {
    Write-Host "`n=== GETTING TOKEN ===" -ForegroundColor Green
    Write-Host "Getting BANK_TOKEN..."
    try {
        $uri = "$BASEURL/auth/bank-token?client_id=$env:CLIENT_ID&client_secret=$env:CLIENT_SECRET"
        Write-Host "Request URL: $uri"
        $tokenResponse = Invoke-RestMethod -Method POST -Uri $uri
        $env:BANK_TOKEN = $tokenResponse.access_token
        Write-Host "BANK_TOKEN received successfully" -ForegroundColor Green
    } catch {
        Write-Error "Failed to get BANK_TOKEN: $_"
        Write-Host "Please check your CLIENT_ID and CLIENT_SECRET"
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
Write-Host "`n=== STARTING SCANNER ===" -ForegroundColor Green
Write-Host "Running scanner for $($BANK_NAMES[$env:SELECTED_BANK])..."
java -jar "$JAR" --openapi $OPENAPI --base-url $BASEURL --auth "bearer:$env:BANK_TOKEN" --requesting-bank $env:CLIENT_ID --client $env:INTERBANK_CLIENT --create-consent true --verbose

Write-Host "`n=== COMPLETED ===" -ForegroundColor Green
Write-Host "Reports saved to folder: reports\"
Write-Host "Note: Reports are saved in 'reports' folder and preserved between builds"
pause