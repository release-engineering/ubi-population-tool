#!/usr/bin/env python

import glob
import sys

from setuptools import setup

INSTALL_REQUIRES = ['ubi_config']


def get_install_requires():
    out = INSTALL_REQUIRES[:]
    if sys.version_info[0] < 3:
        out.append("futures")
    return out


setup(name='ubi-population-tool',
      description='###TODO###',
      version='0.01',
      #url=
      install_requires=get_install_requires(),
      packages=['ubipop'],
      dependency_links=['git+http://github.com/release-engineering/ubi-config#egg=ubi_config-0.0.0'],
      entry_points={
          'console_scripts': [
              'ubipop = ubipop.cli:entry_point',
          ]
      }
      )
