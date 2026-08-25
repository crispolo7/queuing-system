#  Queuing Management System

## Secure local setup

1. Create the environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Replace every `replace_with_...` value in `.env`.

   Generate the password hash with:

   ```powershell
   python -c "from getpass import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass()))"
   ```

3. Install the pinned dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

4. Start the application:

   ```powershell
   python run_app.py
   ```
5. You can Modify the the Logos and Names for this project in the static and templates. Initial logos and name are from comelec since this project is for initiative to help comelec client flow improvement.

To build the Windows executable, install the additional build dependency and use the existing spec file:

```powershell
python -m pip install -r requirements-build.txt
pyinstaller --clean run_app.spec
```

The default bind address is localhost. Do not set `SERVER_HOST=0.0.0.0` unless the service is protected by a properly configured HTTPS reverse proxy and network controls. The default database is local SQLite; an externally managed database can be supplied through `DATABASE_URL`.

Never commit `.env`, databases, the administrator password file, build output, executables, or Python cache files.
