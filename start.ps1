
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$Python = Join-Path $Backend ".venv\Scripts\python.exe"

# Validate project requirements
if (-not (Test-Path $Python)) {
    Write-Error "Python virtual environment not found: $Python"
    exit 1
}

if (-not (Test-Path (Join-Path $Frontend "package.json"))) {
    Write-Error "Frontend package.json not found."
    exit 1
}

if (-not (Test-Path (Join-Path $Frontend "node_modules"))) {
    Write-Error "Frontend dependencies missing. Run: npm --prefix frontend install"
    exit 1
}

Write-Host "Starting Zyncle Port Scanner..." -ForegroundColor Cyan

# Start FastAPI backend
$BackendCommand = @"
Set-Location '$Backend'
& '$Python' -m uvicorn app.main:app --app-dir '$Backend' --reload --host 127.0.0.1 --port 8000
"@

Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    $BackendCommand
)

# Start React/Vite frontend
$FrontendCommand = @"
Set-Location '$Frontend'
npm run dev -- --host 127.0.0.1
"@

Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    $FrontendCommand
)

Write-Host "Backend:  http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "Frontend: http://127.0.0.1:5173 (check Vite terminal)" -ForegroundColor Green
