FROM python:3.9

WORKDIR /app

# Install required system dependencies
RUN apt-get update && apt-get install -y curl git && rm -rf /var/lib/apt/lists/*

COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir .

# Install Foundry and make sure it's available in PATH
RUN curl -L https://foundry.paradigm.xyz | bash ; /root/.foundry/bin/foundryup; ln -s /root/.foundry/bin/forge /usr/local/bin/forge;ln -s /root/.foundry/bin/cast /usr/local/bin/cast; ln -s /root/.foundry/bin/anvil /usr/local/bin/anvil


RUN git clone https://github.com/Layr-Labs/eigenlayer-contracts.git 
RUN cd /app/eigenlayer-contracts; forge clean
RUN cd eigenlayer-contracts ; forge build
EXPOSE 8545
