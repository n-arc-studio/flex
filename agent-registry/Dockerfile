FROM python:3.11-slim

WORKDIR /app

COPY agent-registry/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY agent-registry/registry.py ./registry.py
COPY packet-agent/agent.py ./packet-agent/agent.py
COPY packet-agent/requirements.txt ./packet-agent/requirements.txt

CMD ["python", "registry.py", "--host", "0.0.0.0", "--port", "8780"]
