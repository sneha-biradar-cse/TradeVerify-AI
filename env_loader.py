"""
Loads optional settings files (otp_settings.env) into the environment BEFORE the rest of the server starts.
Lines look like  NAME=value ; blank lines and lines starting with # are ignored. A setting already set in the
environment (for example in start.bat) is never overridden, and a file that does not exist is simply skipped.
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def load(filenames=('otp_settings.env', 'email_settings.env')):
    loaded = []
    for filename in filenames:
        try:
            with open(os.path.join(_HERE, filename), encoding='utf-8') as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    name, value = line.split('=', 1)
                    name, value = name.strip(), value.strip().strip('"').strip("'")
                    if name and value and name not in os.environ:
                        os.environ[name] = value
                        loaded.append(name)
        except FileNotFoundError:
            pass
    return loaded


load()
