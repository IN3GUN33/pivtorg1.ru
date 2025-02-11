import sys
import os
import logging
import http.client

# Включите логирование HTTP-запросов
http.client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
INTERP = "/opt/python/python-3.9.0/bin/python"  # Путь из which python3.9

if sys.executable != INTERP:
    os.execl(INTERP, INTERP, *sys.argv)

sys.path.append(os.getcwd())
from app import application 
