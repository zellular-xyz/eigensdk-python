from setuptools import setup, find_packages

setup(
    name="eigensdk",
    version="0.0.3",
    packages=find_packages(),
    install_requires=[
        "web3==7.4.0",
        "fastapi",
        "pydantic",
        "uvicorn"
    ],
    entry_points={
        "console_scripts": [
            # Define any CLI scripts here
        ],
    },
    author="Abram Symons",
    author_email="abramsymons@gmail.com",
    description="A SDK for developing EigenLayer AVS in Python",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/abramsymons/eigensdk-python",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
