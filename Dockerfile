FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default: run the data pipeline
CMD ["python", "src/data/fetch_onchain.py"]   