from setuptools import setup, find_packages
import os

version = '0.0.0'

requires = [
    "lxml",
    ]

tests_require = []

long_description = (
    open('README.txt').read()
    + '\n' +
    'Contributors\n'
    '============\n'
    + '\n' +
    open('CONTRIBUTORS.txt').read()
    + '\n' +
    open('CHANGES.txt').read()
    + '\n')

setup(name='lxmlmechanize',
      version=version,
      description="",
      long_description=long_description,
      classifiers=[
        "Topic :: Internet",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Browsers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.5",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Testing :: Traffic Generation",
        ],
      keywords='',
      author='Moriyoshi Koizumi',
      author_email='mozo@mozo.jp',
      url='https://github.com/moriyoshi/lxmlmechanize',
      license='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=True,
      install_requires=requires,
      tests_require=requires+tests_require,
      extras_require={
          "testing": requires+tests_require,
      },
      test_suite='lxmlmechanize',
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
