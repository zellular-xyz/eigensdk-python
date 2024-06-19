import subprocess

test_modules = [
    "elwriter_test",
    "avsregistry_writer_test",
    "elreader_test",
    "avsregistry_reader_test",
]

for module in test_modules:
    subprocess.run(["python", "-m", "unittest", "-v", module])
