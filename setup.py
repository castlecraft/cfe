# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open('requirements.txt') as f:
	install_requires = f.read().strip().split('\n')

# get version from __version__ variable in castlecraft/__init__.py
from castlecraft import __version__ as version

setup(
	name='castlecraft',
	version=version,
	description='Castlecraft Frappe Extensions',
	author='Castlecraft Ecommerce Pvt. Ltd.',
	author_email='support@castlecraft.in',
	packages=find_packages(),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)
