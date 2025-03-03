

# Use Python 3.9 as the base image
FROM python:3.9

# Set working directory
WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y curl git && rm -rf /var/lib/apt/lists/*

# Copy project files to the container
COPY . /app

# Install Python dependencies
RUN python -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache-dir .

# Install Foundry and make sure it's available in PATH
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup && \
    ln -s /root/.foundry/bin/forge /usr/local/bin/forge && \
    ln -s /root/.foundry/bin/cast /usr/local/bin/cast && \
    ln -s /root/.foundry/bin/anvil /usr/local/bin/anvil

# Expose required port
EXPOSE 8545

# Set default command to run `make run` and keep container running
CMD ["/bin/bash", "-c", "make run && tail -f /dev/null"]

