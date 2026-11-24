<#
Подготовка подписи Windows-сборки.
Запуск (в PowerShell, из папки проекта):
  npm run sign:setup -- -Thumbprint <SHA1-отпечаток-сертификата>

Скрипт НЕ создаёт сертификат. Сертификат для подписи кода выдаёт удостоверяющий центр
(OV или EV) и импортируется в хранилище Windows заранее (см. README, раздел «Подпись»).
#>
param(
  [Parameter(Mandatory = $true)][string]$Thumbprint,
  [string]$TimestampUrl = "http://timestamp.comodoca.com",
  [switch]$Tsp
)

$ErrorActionPreference = "Stop"

$thumb = ($Thumbprint -replace '\s', '').ToUpper()
if ($thumb -notmatch '^[0-9A-F]{40}$') {
  throw "Отпечаток должен состоять из 40 шестнадцатеричных символов (SHA-1)."
}

# Ищем сертификат в личном и машинном хранилищах.
$cert = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue) |
  Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
if (-not $cert) {
  throw "Сертификат с таким отпечатком не найден в хранилище Windows. Сначала импортируйте .pfx."
}

# Сертификат должен быть выписан именно для подписи кода (EKU 1.3.6.1.5.5.7.3.3).
$isCodeSigning = $cert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' }
if (-not $isCodeSigning) {
  throw "Этот сертификат не предназначен для подписи кода (это, например, SSL-сертификат)."
}
if ((Get-Date) -gt $cert.NotAfter) {
  throw "Срок действия сертификата истёк: $($cert.NotAfter)."
}

# Прописываем настройки в tauri.conf.json (tauri -> bundle -> windows).
$cfgPath = Join-Path $PSScriptRoot "..\src-tauri\tauri.conf.json"
$cfg = Get-Content $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
$win = $cfg.tauri.bundle.windows
$win | Add-Member -NotePropertyName certificateThumbprint -NotePropertyValue $thumb -Force
$win | Add-Member -NotePropertyName digestAlgorithm -NotePropertyValue "sha256" -Force
$win | Add-Member -NotePropertyName timestampUrl -NotePropertyValue $TimestampUrl -Force
$win | Add-Member -NotePropertyName tsp -NotePropertyValue ([bool]$Tsp) -Force

# Записываем без BOM: Tauri читает JSON-файл, лишний BOM ломает разбор.
$json = $cfg | ConvertTo-Json -Depth 32
[System.IO.File]::WriteAllText($cfgPath, $json, (New-Object System.Text.UTF8Encoding $false))

Write-Host "Готово. Сертификат: $($cert.Subject)"
Write-Host "Издатель, который увидят пользователи, берётся из этого поля Subject."
Write-Host "Теперь выполните: npm run tauri build"
