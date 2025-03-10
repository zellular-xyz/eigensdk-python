# eigensdk-python

A Python SDK for EigenLayer, derived from the official [eigensdk-go](https://github.com/layr-Labs/eigensdk-go/tree/master/) implementation.

> [!CAUTION]
> This library is a PoC implemented for the EigenLayer hackathon. Do not use it in Production, testnet only.


## Dependencies

It required to [MCL](https://github.com/herumi/mcl) native package to be installed.
```
$ sudo apt install libgmp3-dev
$ wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
$ unzip v1.93.zip
$ cd mcl-1.93
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make install
```

## Installation

```
pip install -e .
```

## Documentation

Documentation is available [here](https://eigensdk-python.readthedocs.io/en/latest) and in the docs directory.


## Test

```
$ pkill -9 anvil
$ docker compose up -d
$ cd tests/elreader
$ pytest -s test_el_reader.py
```