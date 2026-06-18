@echo off
setlocal

cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js est introuvable. Installe Node.js puis relance ce fichier.
  pause
  exit /b 1
)

echo Demarrage du serveur DD Service...
echo.

set HTTPS_ENABLED=true
set HTTPS_PFX=%~dp0certs\localhost.pfx

for /f "usebackq tokens=1,* delims==" %%A in ("%~dp0.env") do (
  if "%%A"=="HTTPS_PASSPHRASE" set HTTPS_PASSPHRASE=%%B
)

if "%HTTPS_PASSPHRASE%"=="" (
  echo HTTPS_PASSPHRASE est introuvable dans .env.
  pause
  exit /b 1
)

if not exist "%~dp0certs" mkdir "%~dp0certs"
if not exist "%HTTPS_PFX%" (
  echo Creation du certificat HTTPS local...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$password = ConvertTo-SecureString '%HTTPS_PASSPHRASE%' -AsPlainText -Force; $cert = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(3); Export-PfxCertificate -Cert $cert -FilePath '%HTTPS_PFX%' -Password $password | Out-Null"
  if errorlevel 1 (
    echo Impossible de creer le certificat HTTPS local.
    pause
    exit /b 1
  )
)

set PORT=3443
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 3443 -State Listen -ErrorAction SilentlyContinue) { exit 1 }"
if errorlevel 1 (
  echo Le port 3443 est deja utilise.
  set PORT=3444
)

echo Adresse du site:
echo https://localhost:%PORT%
echo.
echo Le navigateur peut afficher un avertissement car le certificat est local.
echo Laisse cette fenetre ouverte pendant l'utilisation du site.
echo Appuie sur Ctrl+C pour arreter le serveur.
echo.

node server.js

echo.
echo Le serveur s'est arrete avec le code %errorlevel%.

pause
