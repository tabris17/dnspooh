#!/usr/bin/env python
import setuptools
import io


pkg_author = 'tabris17'
pkg_name = 'dnspooh'
pkg_url = 'https://github.com/tabris17/dnspooh'
pkg_desc = 'A Lightweight DNS Proxy/Relay'
pkg_requires = [
    'cachetools==5.2.0',
    'certifi==2022.12.7',
    'dnslib==0.9.23',
    'maxminddb==2.2.0',
    'pyparsing==3.0.9',
    'PyYAML==6.0',
]
pkg_version = {}
python_requires = '>=3.11'

with io.open('README.md', 'r', encoding='utf8') as f:
    long_description = f.read()

with io.open('%s/version.py' % (pkg_name, ), 'r', encoding='utf8') as f:
    exec(f.read(), pkg_version)

setuptools.setup(
    author=pkg_author,
    classifiers=[
        "Topic :: Internet :: Name Service (DNS)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3 :: Only",
    ],
    description=pkg_desc,
    include_package_data=True,
    install_requires=pkg_requires,
    license='MIT',
    long_description=long_description,
    long_description_content_type="text/markdown",
    name=pkg_name,
    packages=setuptools.find_packages(),
    package_dir={'dnspooh': 'dnspooh'},
    package_data={'dnspooh': ['geoip']},
    python_requires=python_requires,
    url=pkg_url,
    entry_points={
        'console_scripts': [
            'dnspooh = dnspooh.cli:main',
        ],
    },
    version=pkg_version['__version__'],
    zip_safe=True
)
