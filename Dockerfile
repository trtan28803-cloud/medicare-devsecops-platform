# Dockerfile - MediCare EHR (v2.2)
FROM python:3.11-slim

LABEL maintainer="Tran Tuan An <trtan28803@gmail.com>"
LABEL org.opencontainers.image.title="MediCare HICP Zero-Trust EHR"
LABEL org.opencontainers.image.version="2.2"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HICP_HOST=0.0.0.0 \
    HICP_PORT=8080 \
    HICP_DATA_DIR=/var/lib/hicp-ehr \
    HICP_NONINTERACTIVE=1

WORKDIR /app

# 1. Khởi tạo tài khoản hệ thống phi đặc quyền
RUN groupadd -r hicp-ehr && useradd -r -g hicp-ehr -s /usr/sbin/nologin hicp-ehr \
    && mkdir -p /var/lib/hicp-ehr /app \
    && chown -R hicp-ehr:hicp-ehr /var/lib/hicp-ehr /app

# 2. Sao chép mã nguồn
COPY --chown=hicp-ehr:hicp-ehr app.py README.md ./
COPY --chown=hicp-ehr:hicp-ehr static/ ./static/
COPY --chown=hicp-ehr:hicp-ehr scripts/ ./scripts/
COPY --chown=hicp-ehr:hicp-ehr deploy/ ./deploy/

# 3. Khởi tạo dữ liệu mặc định
RUN python3 scripts/setup.py \
    && chown -R hicp-ehr:hicp-ehr /var/lib/hicp-ehr \
    && chmod 750 /var/lib/hicp-ehr

USER hicp-ehr

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1

CMD ["python3", "app.py"]
