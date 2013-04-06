#!/usr/bin/env python

from distutils.core import setup

setup(name='nx_util',
      version='2.0',
      description='Naxsi log parser, whitelist & report generator',
      author='Naxsi Dev Team',
      author_email='thibault.koechlin@nbs-system.com',
      url='naxsi.googlecode.com',
      scripts=['nx_util.py'],
      packages=['nx_lib'],
      data_files=[('nx_datas', ['nx_datas/bootstrap.min.css',
                                'nx_datas/bootstrap-responsive.min.css',
                                'nx_datas/highcharts.js',
                                'nx_datas/map.tpl',
                                'nx_datas/bootstrap.min.js',
                                'nx_datas/country2coords.txt']),
                  ('/usr/share/man/man1', ['nx_util.1.gz']),
                  ('/usr/local/etc/', ['nx_util.conf'])]
      )
