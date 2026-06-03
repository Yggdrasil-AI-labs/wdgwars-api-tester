@echo off
REM Double-click to run a default probe of wdgwars.pl.
REM Forwards any args to wdgwars_api_tester.py.
python "%~dp0wdgwars_api_tester.py" %*
echo.
pause
