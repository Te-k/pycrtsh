# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import os
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _get_version
from typing import List

sys.path.insert(0, os.path.abspath("../.."))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "pycrtsh"
copyright = "2023, Etienne Tek Maynier"
author = "Etienne Tek Maynier"
try:
    # Single source of truth is the version declared in pyproject.toml
    release = _get_version("pycrtsh")
except PackageNotFoundError:
    # pycrtsh is not installed, docs are built from the source tree only
    release = "unknown"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.todo",
    "sphinx_rtd_theme",
    "sphinx_mdinclude",
]

templates_path = ["_templates"]
exclude_patterns: List[str] = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
