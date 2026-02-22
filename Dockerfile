# Utilizziamo una base image Python leggera
FROM python:3.11-slim

# Impostiamo la directory di lavoro nel container
WORKDIR /app

# Copiamo il file delle dipendenze e le installiamo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamo l'intero progetto all'interno del container
COPY . .

# Entry point per l'esecuzione dello scanner
ENTRYPOINT ["python", "/app/main.py"]
