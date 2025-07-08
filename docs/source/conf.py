# Configuration file for the Sphinx documentation builder.

# -- Project information

project = "EigenSDK Python"
copyright = "2025, Abram Symons"
author = "Abram Symons"

release = "0.1.0"
version = "0.1.0"

# -- General configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "sphinx": ("https://www.sphinx-doc.org/en/master/", None),
}
intersphinx_disabled_domains = ["std"]

autodoc_typehints = "description"

# templates_path = ["_templates"]

# -- Options for HTML output

html_theme = "sphinx_rtd_theme"

# -- Options for EPUB output

# epub_show_urls = "footnote"
napoleon_google_docstring = True
napoleon_numpy_docstring = False