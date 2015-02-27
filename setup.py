#!/usr/bin/env python
# encoding: utf-8

from distutils.core import setup
from io import open


setup(
    name="trustybrowser",
    version='0.1',
    url="https://svn-etu-info-sciences.univ-rouen.fr",
    license="GNU General Public License v3",
    author="M2 SSI Université de Rouen",
    author_email=" ",
    description="Audit d'implémentation SSL pour navigateur web",
    long_description=open("README.md").read(),
    packages=["trustybrowser", "trustybrowser.tlslite", "trustybrowser.utils",
              "trustybrowser.plugins", "trustybrowser.tlslite.utils",
              "trustybrowser.tlslite.integration"],
    data_files=[('/usr/share/trustybrowser/html', ['html/index.html'])],
    platforms="any",
    classifiers=[
        "Programming Language :: Python :: 3.4",
        "Development Status :: 2 - Pre-Alpha",
        "Natural Language :: French",
        "Environment :: Web Environment",
        "Intended Audience :: End Users/Desktop",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ]
)
