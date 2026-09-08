FROM python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/webresearch

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libzbar0 \
        poppler-utils \
        tesseract-ocr \
        tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir --requirement requirements.lock

RUN groupadd --gid 10002 webresearch \
    && useradd --uid 10002 --gid webresearch --create-home --shell /usr/sbin/nologin webresearch \
    && chmod 0700 /home/webresearch

COPY --chown=webresearch:webresearch app ./app

USER webresearch
EXPOSE 8000

CMD ["python", "-m", "app.server"]
