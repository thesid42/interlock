param(
    [int]$ApiPort = 8000,
    [int]$WebPort = 5173
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\python.exe'
$Dashboard = Join-Path $Root 'app\dashboard'

if (-not (Test-Path -LiteralPath $Python)) {
    throw 'Create .venv and install requirements.txt first. See README.md.'
}
if (-not (Test-Path -LiteralPath (Join-Path $Dashboard 'node_modules'))) {
    throw 'Run npm install in app/dashboard first. See README.md.'
}

function Get-FreePort([int]$Candidate) {
    while (Get-NetTCPConnection -LocalPort $Candidate -State Listen -ErrorAction SilentlyContinue) {
        $Candidate += 1
    }
    return $Candidate
}

$ApiPort = Get-FreePort $ApiPort
$WebPort = Get-FreePort $WebPort
$Logs = Join-Path $Root 'logs'
New-Item -ItemType Directory -Path $Logs -Force | Out-Null
$env:INTERLOCK_API_URL = "http://127.0.0.1:$ApiPort"
$Api = Start-Process -FilePath $Python -ArgumentList @('-m', 'uvicorn', 'app.api.main:app', '--host', '127.0.0.1', '--port', "$ApiPort") -WorkingDirectory $Root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Logs "api-$ApiPort.log") -RedirectStandardError (Join-Path $Logs "api-$ApiPort.err.log")
$Node = (Get-Command node.exe -ErrorAction Stop).Source
$Vite = Join-Path $Dashboard 'node_modules\vite\bin\vite.js'
$Web = Start-Process -FilePath $Node -ArgumentList @("`"$Vite`"", '--host', '127.0.0.1', '--port', "$WebPort", '--strictPort') -WorkingDirectory $Dashboard -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Logs "web-$WebPort.log") -RedirectStandardError (Join-Path $Logs "web-$WebPort.err.log")

Write-Output "Interlock: http://127.0.0.1:$WebPort"
Write-Output "API docs: http://127.0.0.1:$ApiPort/docs"
Write-Output "API PID: $($Api.Id); Web PID: $($Web.Id)"
Write-Output 'Logs: logs/. Stop the listed process IDs to shut down.'
