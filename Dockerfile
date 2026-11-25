# WiCrackAgent — CPU image (hashcat CPU/OpenCL + John the Ripper)
# For NVIDIA GPUs use nvidia/cuda base image + drivers on the host.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        hashcat john hcxtools hashcat-utils tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Persistent state: uploads, results, potfile, vault
VOLUME ["/app/data", "/app/wifi_captures"]
EXPOSE 5000

ENTRYPOINT ["wicrack"]
CMD ["serve", "--host", "0.0.0.0", "--port", "5000"]
