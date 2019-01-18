virtualenv -p python3 venv || python3 -m venv venv || python -m venv venv || goto :error
venv\Scripts\activate.bat || goto :error
pip install --requirement requirements.txt || goto :error
set FLASK_APP=server.py
flask run || goto :error

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
