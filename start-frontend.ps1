# Node.js memory optimization for Windows
$env:NODE_OPTIONS = "--max-old-space-size=4096"

# Change to the frontend directory
Set-Location "c:\Users\kingaustin\Documents\securecipher_ui"

Write-Host "================================" -ForegroundColor Green
Write-Host " SecureCipher Banking Platform" -ForegroundColor Green  
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "Starting React Frontend with optimized settings..." -ForegroundColor Yellow
Write-Host ""

# Start the development server with stable configuration
npm run dev-stable
