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

## Documentation

For detailed API documentation, installation guides, and examples, please refer to the [official documentation](https://eigensdk-python.readthedocs.io/en/latest).

## Testing & Development

A complete [Docker](https://docs.docker.com/get-docker/) based environment is provided, featuring:

* Python 3.12
* Pre-installed MCL library
* [Foundry](https://book.getfoundry.sh/) (for local Ethereum development)
* EigenLayer contracts (cloned and built)
* Incredible-Squaring AVS example contracts

This setup ensures a clean, reproducible environment for development and testing.

```bash
git clone https://github.com/zellular-xyz/eigensdk-python
cd eigensdk-python
make build
make test
```

Formatting, linting and type checking is also available via:

```bash
make format     # Format code using Black
make lint       # Lint code with Flake8
make mypy       # Run type checking
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
