# eigensdk-python

A Python SDK for EigenLayer, derived from the official [eigensdk-go](https://github.com/layr-Labs/eigensdk-go/tree/master/) implementation.

> [!CAUTION]
> This library is a PoC implemented for the EigenLayer hackathon. Do not use it in Production, testnet only.

## Manual Installation

If you prefer not to use Docker, you can install the dependencies manually.

### Dependencies

MCL native package is required:
```bash
sudo apt install libgmp3-dev
wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
unzip v1.93.zip
cd mcl-1.93
mkdir build
cd build
cmake ..
make
make install
```

### Installation

```bash
pip install -e .
```

## Docker Setup (Recommended)

We provide a comprehensive Docker setup for testing with Python 3.12. This setup includes:

- Python 3.12
- MCL library pre-installed
- Foundry (with Anvil for local Ethereum development)
- EigenLayer contracts (pre-cloned and built)
- Development tools (Black, Flake8, MyPy)

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose V2](https://docs.docker.com/compose/install/) (using `docker compose` command)

## Testing

### Quick Start

For a quick test setup and run:

```bash
# Build and run tests

make build

make test

```

### Test Commands

1. **Run Basic Tests** (No blockchain dependency):
   ```bash
   make simple-setup
   ```
   Runs tests that don't require Anvil connection, useful for quick verification.


2. **Full Test Setup with Contract Deployment**:
   ```bash
   # Build, deploy contracts, and run all tests
   make setup-all
   ```


### Test Environment Setup

1. **Start Test Environment**:
   ```bash
   # Start Anvil and deploy contracts
   make anvil-up
   
   # Update environment with contract addresses
   make update-env
   ```

2. **Clean Test Environment**:
   ```bash
   # Clean up containers and artifacts
   make clean
   make down
   ```

## Development Setup

1. **Build the Docker image**:
   ```bash
   make build
   ```

2. **Run tests**:
   ```bash
   make test
   ```

3. **Format and Lint**:
   ```bash
   make format  # Run Black formatter
   make lint    # Run Flake8
   make mypy    # Run type checking
   ```

4. **Development Shells**:
   ```bash
   make shell        # Open bash shell
   make anvil-shell  # Open Anvil container shell
   ```

### Contract Address Management

1. **View deployed addresses**:
   ```bash
   make get-addresses
   ```

2. **Update environment**:
   ```bash
   make update-env
   ```


## Documentation

Documentation is available [here](https://eigensdk-python.readthedocs.io/en/latest) and in the docs directory.
