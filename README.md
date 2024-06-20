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
pip3 install git+https://github.com/abramsymons/eigensdk-python
```

## Documentation

Documentation is available [here](https://eigensdk-python.readthedocs.io/en/latest) and in the docs directory.

## Example

You can use [Incredible Squaring Python AVS](https://github.com/abramsymons/incredible-squaring-avs-python/) as an example application using this SDK. 

## Test

Tests use the anvil chain snapshot of the [Incredible Squaring AVS](https://github.com/zellular-xyz/incredible-squaring-avs-python?tab=readme-ov-file#running). To run tests, use the following commands after running the anvil chain as described [here](https://github.com/zellular-xyz/incredible-squaring-avs-python?tab=readme-ov-file#running):

```
$ cd tests
$ python -m unittest run_tests.py
```