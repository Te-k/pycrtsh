from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pycrtsh',
    version='0.3.2',
    description='Python library to request crt.sh certificate information',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/Te-k/pycrtsh',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='security',
    install_requires=['requests', 'lxml==4.5.1', 'beautifulsoup4==4.9.1', 'python-dateutil'],
    license='MIT',
    packages=['pycrtsh'],
    entry_points= {
        'console_scripts': [ 'certsh=pycrtsh.cli:main' ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
