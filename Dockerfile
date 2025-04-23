# Use Python 3.12 as the base image
FROM python:3.12

# Set working directory
WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    dnsutils \
    curl \
    git \
    libgmp3-dev \
    build-essential \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install MCL
RUN apt-get update && apt-get install -y clang wget unzip cmake make \
    && wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip \
    && unzip v1.93.zip \
    && cd mcl-1.93 \
    && mkdir build \
    && cd build \
    && cmake -DCMAKE_CXX_COMPILER=clang++ .. \
    && make -j8 \
    && make install \
    && cd /app \
    && rm -rf mcl-1.93 v1.93.zip


# Install Foundry (for Anvil)
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"

# Clone and build eigenlayer-contracts
RUN git clone https://github.com/Layr-Labs/eigenlayer-contracts.git \
    && cd eigenlayer-contracts \
    && git checkout 2e53e2f7662d8d9a43b2ca0cca22ecd068604226 \
    && forge build


# Copy application requirements first for better caching
COPY setup.py requirements-dev.txt /app/
RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir -r requirements-dev.txt

# Copy the rest of the application code
COPY . /app/

# Install the application
RUN pip install --no-cache-dir -e .

# Expose port 8545 for Anvil
EXPOSE 8545

# Default command to execute init.sh
CMD ["anvil"]