# eigensdk-python

A Python implementation of the EigenLayer SDK, based on the official [eigensdk-go](https://github.com/layr-Labs/eigensdk-go) repository. This SDK equips developers with tools to interact with **EigenLayer Core contracts** and to build **AVS (Actively Validated Services)** using Python.

> ⚠️ **Note**
> This library is currently in active development. While it can be used for testing and development purposes, please exercise caution when using in production environments.

This SDK was originally developed by **Abram Symons** and is now actively maintained and extended by [**iF3 Labs**](https://github.com/if3-xyz), under his supervision. The project originated as part of [Zellular](https://github.com/zellular-xyz).

📬 **Contact**: [mail@if3.xyz](mailto:mail@if3.xyz)

---

## 🛠 Manual Installation

If you prefer not to use Docker, you can install the SDK and its dependencies manually.

### System Requirements

You must first install the MCL native library:

```bash
sudo apt install libgmp3-dev
wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
unzip v1.93.zip
cd mcl-1.93
mkdir build
cd build
cmake ..
make
sudo make install
```

### Python Installation

**From Git Repository (Recommended):**
```bash
pip install git+https://github.com/zellular-xyz/eigensdk-python
```

**Local Development:**
```bash
git clone https://github.com/zellular-xyz/eigensdk-python
cd eigensdk-python
pip install -e .
```

---

## 🐳 Docker Setup (Recommended)

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

---

## ✅ Testing

### Quick Start

```bash
make build
make test
```

---

## 🧪 Development Workflow

```bash
make build      # Build Docker image
make test       # Run tests
make format     # Format code using Black
make lint       # Lint code with Flake8
make mypy       # Run type checking
```

---

## 📚 Documentation

Full documentation is available:

* Online: [https://eigensdk-python.readthedocs.io/en/latest](https://eigensdk-python.readthedocs.io/en/latest)
* Locally: See the `docs/` directory

For detailed API documentation, installation guides, and examples, please refer to the documentation.

---

## 🔗 Related Projects

* [Zellular GitHub](https://github.com/zellular-xyz/) - Original developers of this SDK
* [iF3 Labs GitHub](https://github.com/if3-xyz) - Current maintainers of this SDK
* [Incredible Squaring AVS (Python)](https://github.com/zellular-xyz/incredible-squaring-avs-python) - Example AVS implementation in Python
* [EigenLayer Middleware](https://github.com/Layr-Labs/eigenlayer-middleware) - Official EigenLayer middleware contracts
* [EigenLayer Contracts](https://github.com/Layr-Labs/eigenlayer-contracts) - Core EigenLayer protocol contracts