from setuptools import setup, find_packages

setup(
    name='mpsiemlib',
    version='0.1.0',
    packages=find_packages(exclude=['tests']),
    url='github.com',
    license='GPLv3',
    author='nikolaiav',
    author_email='',
    description='Maxpatrol SIEM API SDK',
    zip_safe=False
)
