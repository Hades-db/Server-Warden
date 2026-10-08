FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config/ ./config/
COPY handlers/ ./handlers/
COPY keyboards/ ./keyboards/
COPY middlewares/ ./middlewares/
COPY services/ ./services/
COPY main.py .

CMD ["python", "main.py"]