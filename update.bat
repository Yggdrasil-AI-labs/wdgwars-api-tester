@echo off
REM Double-click to refresh wdgwars_api_tester.py from main.
REM Stdlib only — no deps to refresh.

python -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)" 2>nul
if errorlevel 1 (
    echo wdgwars-api-tester needs Python 3.8 or newer. Your current Python is:
    python --version 2>nul || echo   ^(not found on PATH^)
    echo.
    echo Install Python 3.8+ from https://python.org/downloads/ and re-run.
    goto :done
)

echo [1/1] Refreshing wdgwars_api_tester.py from GitHub...
python -c "import urllib.request as u; u.urlretrieve('https://raw.githubusercontent.com/HiroAlleyCat/wdgwars-api-tester/main/wdgwars_api_tester.py', r'%~dp0wdgwars_api_tester.py')"
if errorlevel 1 (
    echo.
    echo Could not fetch wdgwars_api_tester.py. Check internet connection
    echo and that Python is installed and on PATH.
    goto :done
)

echo.
echo Updated. Current version:
python "%~dp0wdgwars_api_tester.py" --version

:done
echo.
pause
