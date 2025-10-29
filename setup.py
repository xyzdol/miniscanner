from setuptools import setup, find_packages
setup(
    name="miniscanner",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        'requests'
    ],
    entry_points={
        'console_scripts': [
            'miniscanner = src.app:main'
        ]
    },
)