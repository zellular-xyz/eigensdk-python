# eigensdk-python

A Python implementation of the EigenLayer SDK, based on the official [eigensdk-go](https://github.com/layr-Labs/eigensdk-go) repository. This SDK equips developers with tools to interact with **EigenLayer Core contracts** and to build **AVS (Autonomous Verifiable Services)** using Python.

**⚠️ Warning:** This library is currently in active development. While it can be used for testing and development purposes, please exercise caution when using in production environments.

## Installation

### Prerequisites

The [MCL](https://github.com/herumi/mcl) native library is required for BLS signing & verification.

**System dependencies:**

```bash
sudo apt update
sudo apt install libgmp3-dev cmake make wget unzip
```

**Install MCL library:**

```bash
wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
unzip v1.93.zip
cd mcl-1.93
mkdir build && cd build
cmake .. && make
sudo make install
```

### Installing from PyPI

After installing the MCL library, you can install or upgrade `eigensdk-python` via:

```bash
pip install eigensdk --upgrade
```

### Installing from Source

```bash
git clone https://github.com/zellular-xyz/eigensdk-python
cd eigensdk-python
pip install .
```

## Testing & Development

A complete Docker-based environment is provided, featuring:

* Python 3.12
* Pre-installed MCL library
* [Foundry](https://book.getfoundry.sh/) (for local Ethereum development)
* EigenLayer contracts (cloned and built)
* Incredible-Squaring AVS example contracts
* Pre-configured development tools: Black, Flake8, MyPy

This setup ensures a clean, reproducible environment for development and testing.

### Requirements

* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose V2](https://docs.docker.com/compose/install/)

### Quick Start

```bash
git clone https://github.com/zellular-xyz/eigensdk-python
cd eigensdk-python
make build
make test
```

### Development Workflow

```bash
make build      # Build Docker image
make test       # Run tests
make format     # Format code using Black
make lint       # Lint code with Flake8
make mypy       # Run type checking
```

## Documentation

For detailed API documentation, installation guides, and examples, please refer to the [official documentation](https://eigensdk-python.readthedocs.io/en/latest).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
