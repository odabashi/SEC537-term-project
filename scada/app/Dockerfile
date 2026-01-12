FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install only required system utilities
RUN apt-get update && apt-get install -y \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/* \

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . ./app/

# Expose SCADA web interface port
EXPOSE 8000

# Start the SCADA application
#CMD ["python", "app/main.py"]
CMD ["uvicorn", "scada.app.main:app", "--host", "0.0.0.0", "--port", "8000"]