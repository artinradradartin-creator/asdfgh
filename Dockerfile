FROM python:3.11-slim

# Install necessary system utilities (wget for downloading, unzip for Xray, procps/psmisc for port management)
RUN apt-get update && \
    apt-get install -y wget unzip procps psmisc && \
    rm -rf /var/lib/apt/lists/*

# Download and install the latest Xray-Core
RUN wget -O /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && \
    unzip /tmp/xray.zip -d /tmp/xray && \
    mv /tmp/xray/xray /usr/local/bin/xray && \
    chmod +x /usr/local/bin/xray && \
    rm -rf /tmp/xray.zip /tmp/xray

# Set the working directory
WORKDIR /app

# Copy the Python panel script into the container
COPY main.py .

# Tell Railway what command to execute (-u prevents log buffering so you see logs instantly)
CMD ["python", "-u", "main.py"]
