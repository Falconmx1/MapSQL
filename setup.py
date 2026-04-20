from setuptools import setup, find_packages

setup(
    name="mapsql",
    version="1.0.0",
    author="Falconmx1",
    description="Herramienta de SQLi más potente que sqlmap",
    packages=find_packages(),
    install_requires=['requests'],
    entry_points={'console_scripts': ['mapsql=mapsql:main']},
)
