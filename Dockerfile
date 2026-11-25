# A사 앱 컨테이너. 운영 형태(EC2: Apache → Gunicorn → Flask)의 Gunicorn 자리다.
# Apache는 별도 컨테이너(ops/apache)로 앞에 둔다.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/ekyc

# 의존성 먼저 설치해 레이어 캐시를 살린다
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY app ./app
COPY carrier ./carrier
COPY seed ./seed
COPY tools ./tools
COPY samples ./samples
COPY migrations ./migrations
COPY ops/gunicorn.conf.py ./ops/gunicorn.conf.py

# 앱은 root로 돌리지 않는다(주통기 U-/금취분평 서버 항목).
RUN useradd --system --create-home --uid 10001 ekyc \
    && mkdir -p /srv/ekyc/instance \
    && chown -R ekyc:ekyc /srv/ekyc
USER ekyc

EXPOSE 8000
CMD ["gunicorn", "--config", "ops/gunicorn.conf.py", "app:create_app()"]
