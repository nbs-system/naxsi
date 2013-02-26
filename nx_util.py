#!/usr/bin/env python
# Injection :
# -l --log logfile1, logfile2 ... : Inject logfile1 et logfile2. If logfile is '-', logs are read from stdin
# -g --glob "/var/log/nginx/*/*foobar*.error.log*" : Inject all files with name matching "*rx*" that are contained in directory "/path/" (recursive)

# Save :
# -s --save db_name : Save db under the name db_name
# -r --recover db_name : Recover db from db_name

# Reporting :
# --report /dir/ : Create report in directory /dir/

# Whitelist :
# -o --output : Output whitelists on stdout

# Extra :
# -i --incremental : Incremental mode, data will be appened
# -d --date-interval [date intervals] : Include only events that are within date interval(s)
# --src 2.2.2.2, 1.1.1.1 : Limit learning to exceptions from IP 2.2.2.2 or IP 1.1.1.1

# Config :
# --config config_file : Use this config file. Defaults to naxsi-utils.conf

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
%prog [-l /var/log/*mysite*error.log] [-o] [-H dir/] [-d dbname] [-c config]
nginx/naxsi log parser, whitelist and report generator.
"""
	parser = OptionParser(usage=usage)
	# Save/Recover options
	parser.add_option("-d", "--dbname", dest="db",
			  help="db (sqlite3) name", type="string",
			  default="naxsi_sig")
	parser.add_option("-i", "--incremental", dest="incremental",
			  action="store_true", default=False,
			  help="Append to database, rather than creating a news one.")
	# Outputing options
	parser.add_option("-H", "--html-out", dest="dst_dir",
			  help="Generate HTML report to directory", 
			  type="string")
	parser.add_option("-o", "--out", dest="output_whitelist", 
			  action="store_true", default=False,
			  help="Generate whitelists, outputs on stdout")
	# Input options
	parser.add_option("-l", "--log", dest="logfiles",
			  help="Parse logfile(s) matching regex, ie. /var/log/nginx/*myproj*error.log", 
			  action="callback", callback=cb)
	
	# Configuration
	parser.add_option("-c", "--config", dest="conf_path",
			  help="Path to configuration (defaults to ./nx_util.conf)", 
			  type="string", default="nx_util.conf")
	

	# Filtering options should go here :)
	parser.add_option("-f", "--filters", dest="usr_filter",
			  help="Filter imported data",
			  type="string")
	
	(options, args) = parser.parse_args()
	
	if options.dst_dir is None and options.output_whitelist is False and options.logfiles is None:
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
		wl = NxWhitelistExtractor(sql, config.core_rules)
		wl.gen_basic_rules()
		base_rules, opti_rules = wl.opti_rules_back()
		opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
		r = wl.format_rules_output(wl.final_rules)
		print r
	if options.dst_dir is not None:
		print "Outputing HTML report to directory ["+options.dst_dir+"]"
		report = NxReportGen(options.dst_dir, config.data_dir, sql)
		report.write()
		print "Done!"
