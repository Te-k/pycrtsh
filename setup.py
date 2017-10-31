from setuptools import setup

setup(
    name='pycrtsh',
    version='0.1',
    description='Python library to request crt.sh certificate information',
    url='https://github.com/Te-k/pycrtsh',
    author='Tek',
    author_email='tek@randhome.io',
    keywords='security',
    install_requires=['requests'],
    license='MIT',
    packages=['pycrtsh'],
    entry_points= {
        'console_scripts': [ 'certsh=pycrtsh.cli:main' ]
    }
)
