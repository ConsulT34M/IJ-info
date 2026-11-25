"""Gunicorn 설정. Apache 뒤에서만 받는다.

운영 형태는 Apache 2.4(mod_ssl, mod_proxy) → Gunicorn 127.0.0.1:8000 → Flask다.
컨테이너에서는 같은 네트워크의 web 컨테이너만 들어오므로 0.0.0.0에 바인딩하고,
외부 노출은 compose의 포트 매핑으로 막는다(app 컨테이너는 포트를 열지 않는다).
"""

import multiprocessing
import os

bind = os.environ.get("GUNICORN_BIND", "0.0.0.0:8000")
workers = int(os.environ.get("GUNICORN_WORKERS", min(multiprocessing.cpu_count() * 2 + 1, 5)))
threads = int(os.environ.get("GUNICORN_THREADS", 2))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", 60))
graceful_timeout = 30
keepalive = 5

# Apache가 덮어쓴 X-Real-IP만 믿는다(TRUST_PROXY=true와 짝). 그 앞단은 신뢰하지 않는다.
forwarded_allow_ips = os.environ.get("GUNICORN_FORWARDED_ALLOW_IPS", "*")

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")
# 접근 로그에 질의 문자열을 남기지 않는다. 검색어·토큰이 로그로 새지 않게 한다.
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(M)sms "%(a)s"'

# 서버 정보를 응답에 남기지 않는다(웹서버 정보 노출 항목).
proc_name = "ekyc"
