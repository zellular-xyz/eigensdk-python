# Configuration file for the Sphinx documentation builder.

# -- Project information

project = "EigenSDK Python"
copyright = "2025, Abram Symons"
author = "Abram Symons"

release = "0.1.0"
version = "0.1.0"

# -- General configuration

extensions = [
    "sphinx.ext.duration",
    "sphinx.ext.doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
}
intersphinx_disabled_domains = ["std"]

templates_path = ["_templates"]

# -- Options for HTML output

html_theme = "sphinx_rtd_theme"

# -- Options for EPUB output

epub_show_urls = "footnote"

# -- Custom project attribution note (can be used in templates or footers)

rst_epilog = """
.. |project_note| replace:: This SDK was originally developed by Abram Symons .
"""
