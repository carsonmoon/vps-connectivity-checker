FROM python:3.12-slim

# ping/ping6 供 ICMP 检测调用（容器默认具备 CAP_NET_RAW，无需特权模式）
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.py .
COPY static ./static

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    PORT=52000

VOLUME /data
EXPOSE 52000
CMD ["python", "server.py"]
