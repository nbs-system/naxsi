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
parser = OptionParser()

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

        
parser.add_option("-s", "--save", dest="db_dst",
                  help="Save exceptions to db", type="string")
parser.add_option("-H", "--html-out", dest="dst_dir",
                  help="Generate HTML report to directory.", type="string")
parser.add_option("-o", "--out", dest="output_whitelist", action="store_false")
parser.add_option("-r", "--recover", dest="db_src",
                  help="Load exceptions from db", type="string")
parser.add_option("-l", "--log", dest="logfiles",
                  help="Parse logfile(s) matching regex (glob)", 
                  action="callback", callback=cb)
(options, args) = parser.parse_args()

# DB
sql = SQLWrapper("naxsi-ui.conf", None)
sql.create_db()
sql.create_all_tables()


# Create injector
inject = NxInject(sql)


# Imports
logfiles = []
if options.logfiles is not None:
    logfiles.extend(options.logfiles)
    reader = NxReader(inject, lglob=logfiles)
    reader.read_files()
    wl = NxWhitelistExtractor(sql, "/etc/nginx/naxsi_core.rules", "naxsi-ui.conf", None)
    wl.gen_basic_rules()
    base_rules, opti_rules = wl.opti_rules_back()
    opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
    r = wl.format_rules_output(wl.final_rules)
    print r
