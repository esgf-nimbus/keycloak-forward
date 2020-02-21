from setuptools import find_packages
from setuptools import setup

setup(
    name='keycloak-forward',
    version='1.0.0',
    packages=find_packages(exclude=['tests']),
    install_requires=[
        'flask',
        'tabulate',
        'authlib',
        'flask-sqlalchemy',
        'gunicorn',
    ],
)
