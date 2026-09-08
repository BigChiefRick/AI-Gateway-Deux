FROM python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/gateway

WORKDIR /app

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --requirement requirements.lock

RUN groupadd --gid 10001 gateway \
    && useradd --uid 10001 --gid gateway --create-home --shell /usr/sbin/nologin gateway \
    && chmod 0700 /home/gateway

COPY --chown=gateway:gateway app ./app

USER gateway
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
