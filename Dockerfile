FROM python:3.8-alpine as base
FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
RUN mkdir -p /app/ostorlab
COPY ostorlab_client /app/ostorlab
WORKDIR /app/ostorlab
RUN python3 -m pip install .
WORKDIR /app/agent
CMD ["python3", "/app/agent/agent.py"]
