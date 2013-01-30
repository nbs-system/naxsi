#!/usr/bin/env python

import os

FILENAME="report.html"

class NxReport(object):
    
    def __init__(self, dest_dir):
        self.__dest_dir = dest_dir
        if not os.path.exists(dest_dir):
            raise Exception, "{0} does not exist !".format(dest_dir)
        else:
            os.mkdir(self.__dest_dir)


    def output(self):
        pass
