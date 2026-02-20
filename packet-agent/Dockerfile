FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py ./

EXPOSE 8765

CMD ["python", "agent.py", "--host", "0.0.0.0", "--port", "8765", "--bpf", "tcp or udp"]
