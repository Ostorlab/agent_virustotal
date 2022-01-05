FROM python:3.8-slim-buster

WORKDIR /app

COPY requirement.txt .
RUN pip3 install -r requirement.txt

COPY src/ .
COPY agent.yaml .

CMD python3 /code/agent.py
