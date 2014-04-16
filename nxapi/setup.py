#!/usr/bin/env python

from distutils.core import setup
import os
import glob
import pprint

f = {}
data_files = [('/usr/local/nxapi/', ['nx_datas/country2coords.txt']),
              ('/usr/local/etc/', ['nxapi.json'])]
#modules = []
for dirname, dirnames, filenames in os.walk('tpl/'):
    for filename in filenames:
        if filename.endswith(".tpl"):
            print dirname+"#"+filename
            if "/usr/local/nxapi/"+dirname not in f.keys():
                
                f["/usr/local/nxapi/"+dirname] = []
                
            f["/usr/local/nxapi/"+dirname].append(os.path.join(dirname, filename))

for z in f.keys():
    data_files.append( (z, f[z]))


setup(name='nxtool',
      version='1.0',
      description='Naxsi log parser, whitelist & report generator',
      author='Naxsi Dev Team',
      author_email='thibault.koechlin@nbs-system.com',
      url='http://github.com/nbs-system/naxsi',
      scripts=['nxtool.py'],
      packages=['nxapi'],
      data_files=data_files
      )

