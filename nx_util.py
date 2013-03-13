#!/usr/bin/env python

from optparse import OptionParser
import os
from nx_lib.nx_imports import NxReader, NxInject 
from nx_lib.SQLWrapper import SQLWrapper, SQLWrapperException
from nx_lib.nx_whitelists import NxWhitelistExtractor
from nx_lib.nx_report import NxReportGen
from nx_lib.nx_tools import NxConfig
#import logging
import sys
# Did you see how bad I am ?

# optparse needs this, argsparse is for > 2.7 only. 
def cb(option, opt_str, value, parser):
        args=[]
        for arg in parser.rargs:
                if arg[0] != "-":
                        args.append(arg)
                else:
                        del parser.rargs[:len(args)]
                        break
        if getattr(parser.values, option.dest):
                args.extend(getattr(parser.values, option.dest))
        setattr(parser.values, option.dest, args)


	

if __name__ == "__main__":
	usage = """
%prog [-l /var/log/*error.log] [-o] [-H file] [-d dbname] [-c config]
nginx/naxsi log parser, whitelist and report generator.
"""
	parser = OptionParser(usage=usage)
	# Save/Recover options
	parser.add_option("-d", "--dbname", dest="db",
			  help="db (sqlite3) name", type="string",
			  default="naxsi_sig")
	parser.add_option("-i", "--incremental", dest="incremental",
			  action="store_true", default=False,
			  help="Append to database, rather than creating a new one")
	# Outputing options
	parser.add_option("-H", "--html-out", dest="dst_file",
			  help="Generate HTML report to file", 
			  type="string")
	parser.add_option("-o", "--out", dest="output_whitelist", 
			  action="store_true", default=False,
			  help="Generate whitelists, outputs on stdout")
	parser.add_option("-r", "--rules-limit", default=15,
			  help="Control the number of rules to be match in a whitelist before suggesting a wl:0",
			  type="int", dest="wl_rlimit")
	parser.add_option("-p", "--pages-limit", default=10,
			  help="Number of pages an exception must happen on before suggesting a location-wide whitelist",
			  type="int", dest="wl_plimit")
	
	# Input options
	parser.add_option("-l", "--log", dest="logfiles",
			  help="Parse logfile(s) matching regex, ie. /var/log/nginx/*myproj*error.log", 
			  action="callback", callback=cb)
	
	# Configuration
	parser.add_option("-c", "--config", dest="conf_path",
			  help="Path to configuration (defaults to /usr/local/etc/nx_util.conf)", 
			  type="string", default="/usr/local/etc/nx_util.conf")
	
	# Filtering options should go here :)
	parser.add_option("-f", "--filters", dest="usr_filter",
			  help="Filter imported data",
			  type="string")
	
	(options, args) = parser.parse_args()
	
	if options.dst_file is None and options.output_whitelist is False and options.logfiles is None:
		parser.print_help()
		sys.exit (-1)
	
	config = NxConfig(options.conf_path)
	if config.parse() == 0:
		print "Unable to parse configuration ["+options.conf_path+"]"
		sys.exit(-1)
	# destroy existing database, unless incremental is set.
	if options.incremental is False and options.logfiles is not None:
		try:
			print "Deleting old database :"+config.db_dir+options.db
			os.remove(config.db_dir+options.db)
		except: 
			pass
	sql = SQLWrapper(config.db_dir+options.db)
	if options.logfiles is not None:
		# Create injector
		inject = NxInject(sql, filters=options.usr_filter)
		if len(options.logfiles) == 0:
			reader = NxReader(inject, stdin=True)
			reader.read_files()
		else:
			# Imports
			logfiles = []
			logfiles.extend(options.logfiles)
			reader = NxReader(inject, lglob=logfiles)
			reader.read_files()
	if options.output_whitelist is not False:
		wl = NxWhitelistExtractor(sql, config.core_rules, pages_hit=options.wl_plimit, rules_hit=options.wl_rlimit)
		wl.gen_basic_rules()
		base_rules, opti_rules = wl.opti_rules_back()
		opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
		r = wl.format_rules_output(wl.final_rules)
		print r
	if options.dst_file is not None:
		print "Outputing HTML report to ["+options.dst_file+"]"
		report = NxReportGen(options.dst_file, config.data_dir, sql)
		report.write()
		print "Done!"
