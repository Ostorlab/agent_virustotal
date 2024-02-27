FROM python:3.11-alpine as base
FROM base as builder
RUN apk add build-base
RUN apk update
RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN pip install --prefix=/install -r /requirements.txt
FROM base
RUN apk add libmagic
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/virus_total_agent.py"]
