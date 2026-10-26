FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY lab_server.py detect_failed_logins.py simulate_logins.py dashboard.html ./
CMD ["python", "lab_server.py", "--host", "0.0.0.0", "--log", "/logs/lab_auth.log", "--alerts", "/logs/lab_alerts.log"]
