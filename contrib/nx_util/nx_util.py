#!/usr/bin/env python
# Injection :
# -l --log logfile1, logfile2 ... : Inject logfile1 et logfile2. If logfile is '-', logs are read from stdin
# -g --glob "/var/log/nginx/*/*foobar*.error.log*" : Inject all files with name matching "*rx*" that are contained in directory "/path/" (recursive)

# Sauvegarde :
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
from nx_imports import NxReader, NxInject 
from SQLWrapper import SQLWrapper, SQLWrapperException
from nx_whitelists import NxWhitelistExtractor
from nx_report import NxReport
import logging
#from terminal import render


# optparse needs this, argsparse is for > 2.7 only. 
# death to slow packagers
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
%prog [-l /var/log/*mysite*error.log] [-o] [-H dir/] [-s db] [-r db]
nginx/naxsi log parser, whitelist and report generator.
"""
	parser = OptionParser(usage=usage)
	# Save/Recover options
	parser.add_option("-s", "--save", dest="db_dst",
			  help="Save exceptions to db", type="string")
	parser.add_option("-r", "--recover", dest="db_src",
			  help="Load exceptions from db", type="string")
	# Outputing options
	parser.add_option("-H", "--html-out", dest="dst_dir",
			  help="Generate HTML report to directory.", type="string")
	parser.add_option("-o", "--out", dest="output_whitelist", 
			  action="store_true", default=False,
			  help="Generate whitelists, outputs on stdout")
	# Input options
	parser.add_option("-l", "--log", dest="logfiles",
			  help="Parse logfile(s) matching regex, ie. /var/log/nginx/*myproj*error.log", 
			  action="callback", callback=cb)
	# Filtering options ## TBD
	# ....
	
	(options, args) = parser.parse_args()
	# Setup debug log.
	logging.basicConfig(filename='nx_utils.log',level=logging.DEBUG)

	# This should be rewritten once we have new wrapper
	sql = SQLWrapper()
#	sql.create_db()
#	sql.create_all_tables()
	
	if options.logfiles is not None and len(options.logfiles) > 0:
		# Create injector
		inject = NxInject(sql)
		# Imports
		logfiles = []
		logfiles.extend(options.logfiles)
		reader = NxReader(inject, lglob=logfiles)
		reader.read_files()
	elif options.output_whitelist is not False:
		wl = NxWhitelistExtractor(sql, "/etc/nginx/naxsi_core.rules", "naxsi-ui.conf", None)
		wl.gen_basic_rules()
		base_rules, opti_rules = wl.opti_rules_back()
		opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
		r = wl.format_rules_output(wl.final_rules)
		print r
	elif options.dst_dir is not None:
		report = NxReport(options.dest_dir)
		print "Outputing HTML ..."
	else:
		parser.print_help()
