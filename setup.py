from setuptools import setup, find_packages

setup(
    name="eigensdk",
    version="0.0.3",
    packages=find_packages(),
    install_requires=[
        "mcl @ git+https://github.com/sadeghte/mcl-python.git",
        "web3",
        "python-dotenv==1.0.1",
        "fastapi",
        "pydantic",
        "uvicorn",
    ],
    entry_points={
        "console_scripts": [],
    },
    author="Abram Symons",
    author_email="abramsymons@gmail.com",
    maintainer="iF3Labs",
    maintainer_email="mail@if3.xyz",
    description="A Python SDK for developing EigenLayer AVS. Originally developed by Abram Symons and maintained by iF3Labs under his supervision.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/abramsymons/eigensdk-python",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    include_package_data=True,
    package_data={
        "eigensdk": ["**/*.json"],
    },
)
