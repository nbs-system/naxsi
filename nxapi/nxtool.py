#!/usr/bin/env python

import glob, fcntl, termios
import sys
import socket
import elasticsearch 
import time
from optparse import OptionParser, OptionGroup
from nxapi.nxtransform import *
from nxapi.nxparse import *

F_SETPIPE_SZ = 1031  # Linux 2.6.35+
F_GETPIPE_SZ = 1032  # Linux 2.6.35+



def open_fifo(fifo):
    try:
        os.mkfifo(fifo)
    except OSError:
        print "Fifo ["+fifo+"] already exists (non fatal)."
    except Exception, e:
        print "Unable to create fifo ["+fifo+"]"
    try:
        print "Opening fifo ... will return when data is available."
        fifo_fd = open(fifo, 'r')
        fcntl.fcntl(fifo_fd, F_SETPIPE_SZ, 1000000)
        print "Pipe (modified) size : "+str(fcntl.fcntl(fifo_fd, F_GETPIPE_SZ))
    except Exception, e:
        print "Unable to create fifo, error: "+str(e)
        return None
    return fifo_fd

def macquire(line):
    z = parser.parse_raw_line(line)
    # add data str and country
    if z is not None:
        for event in z['events']:
            event['date'] = z['date']
            event['coords'] = geoloc.ip2ll(event['ip'])
            event['country'] = geoloc.ip2cc(event['ip'])
        # print "Got data :)"
        # pprint.pprint(z)
        #print ".",
        injector.insert(z)
    else:
        pass
        #print "No data ? "+line
    #print ""



opt = OptionParser()
# group : config
p = OptionGroup(opt, "Configuration options")
p.add_option('-c', '--config', dest="cfg_path", default="/usr/local/etc/nxapi.json", help="Path to nxapi.json (config).")
p.add_option('--colors', dest="colors", action="store_false", default="true", help="Disable output colorz.")
# p.add_option('-q', '--quiet', dest="quiet_flag", action="store_true", help="Be quiet.")
# p.add_option('-v', '--verbose', dest="verb_flag", action="store_true", help="Be verbose.")
opt.add_option_group(p)
# group : in option
p = OptionGroup(opt, "Input options (log acquisition)")
p.add_option('--files', dest="files_in", help="Path to log files to parse.")
p.add_option('--fifo', dest="fifo_in", help="Path to a FIFO to be created & read from. [infinite]")
p.add_option('--stdin', dest="stdin", action="store_true", help="Read from stdin.")
p.add_option('--no-timeout', dest="infinite_flag", action="store_true", help="Disable timeout on read operations (stdin/fifo).")
p.add_option('--syslog', dest="syslog_in", action="store_true", help="Listen on tcp port for syslog logging.")
opt.add_option_group(p)
# group : filtering
p = OptionGroup(opt, "Filtering options (for whitelist generation)")
p.add_option('-s', '--server', dest="server", help="FQDN to which we should restrict operations.")
p.add_option('--filter', dest="filter", action="append", help="This option specify a filter for each type of filter, filter are merge with existing templates/filters. (--filter 'uri /foobar')")
opt.add_option_group(p)
# group : tagging
p = OptionGroup(opt, "Tagging options (tag existing events in database)")
p.add_option('-w', '--whitelist-path', dest="wl_file", help="A path to whitelist file, will find matching events in DB.")
p.add_option('-i', '--ip-path', dest="ips", help="A path to IP list file, will find matching events in DB.")
p.add_option('--tag', dest="tag", action="store_true", help="Actually tag matching items in DB.")
opt.add_option_group(p)
# group : whitelist generation
p = OptionGroup(opt, "Whitelist Generation")
p.add_option('-f', '--full-auto', dest="full_auto", action="store_true", help="Attempt fully automatic whitelist generation process.")
p.add_option('-t', '--template', dest="template", help="Path to template to apply.")
p.add_option('--slack', dest="slack", action="store_false", help="Enables less strict mode.")
opt.add_option_group(p)
# group : statistics
p = OptionGroup(opt, "Statistics Generation")
p.add_option('-x', '--stats', dest="stats", action="store_true", help="Generate statistics about current's db content.")
opt.add_option_group(p)

(options, args) = opt.parse_args()


try:
    cfg = NxConfig(options.cfg_path)
except ValueError:
    sys.exit(-1)

if options.server is not None:
    cfg.cfg["global_filters"]["server"] = options.server

cfg.cfg["output"]["colors"] = str(options.colors).lower()
cfg.cfg["naxsi"]["strict"] = str(options.slack).lower()

if options.filter is not None:
    x = {}
    to_parse = []
    kwlist = ['server', 'uri', 'zone', 'var_name', 'ip', 'id', 'content', 'country', 'date',
              '?server', '?uri', '?var_name', '?content']
    try:
        for argstr in options.filter:
            argstr = ' '.join(argstr.split())
            to_parse += argstr.split(' ')
        if [a for a in kwlist if a in to_parse]:
            for kw in to_parse:
                if kw in kwlist:
                    x[kw] = to_parse[to_parse.index(kw)+1]
        else:
            raise
    except:
        logging.critical('option --filter must have at least one option')
        sys.exit(-1)
    for z in x.keys():
        cfg.cfg["global_filters"][z] = x[z]
    #print "-- modified global filters : "
    #pprint.pprint(cfg.cfg["global_filters"])


es = elasticsearch.Elasticsearch(cfg.cfg["elastic"]["host"])
translate = NxTranslate(es, cfg)



# whitelist generation options
if options.full_auto is True:
    translate.load_cr_file(translate.cfg["naxsi"]["rules_path"])
    translate.full_auto()
    sys.exit(1)

if options.template is not None:
    scoring = NxRating(cfg.cfg, es, translate)

    tpls = translate.expand_tpl_path(options.template)
    gstats = {}
    if len(tpls) <= 0:
        print "No template matching"
        sys.exit(1)
    # prepare statistics for global scope
    scoring.refresh_scope('global', translate.tpl2esq(cfg.cfg["global_filters"]))
    for tpl_f in tpls:
        scoring.refresh_scope('rule', {})
        scoring.refresh_scope('template', {})

        print translate.grn.format("#Loading tpl '"+tpl_f+"'")
        tpl = translate.load_tpl_file(tpl_f)
        # prepare statistics for filter scope
        scoring.refresh_scope('template', translate.tpl2esq(tpl))
        #pprint.pprint(tpl)
        print "Hits of template : "+str(scoring.get('template', 'total'))

        whitelists = translate.gen_wl(tpl, rule={})
        print str(len(whitelists))+" whitelists ..."
        for genrule in whitelists:
            #pprint.pprint(genrule)
            scoring.refresh_scope('rule', genrule['rule'])
            scores = scoring.check_rule_score(tpl)
            if (len(scores['success']) > len(scores['warnings']) and scores['deny'] == False) or cfg.cfg["naxsi"]["strict"] == "false":
                #print "?deny "+str(scores['deny'])
                translate.fancy_display(genrule, scores, tpl)
                print translate.grn.format(translate.tpl2wl(genrule['rule'], tpl)).encode('utf-8')
    sys.exit(1)

# tagging options

if options.wl_file is not None and options.server is None:
    print translate.red.format("Cannot tag events in database without a server name !")
    sys.exit(2)

if options.wl_file is not None:
    wl_files = []
    wl_files.extend(glob.glob(options.wl_file))
    count = 0
    for wlf in wl_files:
        print translate.grn.format("#Loading tpl '"+wlf+"'")
        try:
            wlfd = open(wlf, "r")
        except:
            print translate.red.format("Unable to open wl file '"+wlf+"'")
            sys.exit(-1)
        for wl in wlfd:
            [res, esq] = translate.wl2esq(wl)
            if res is True:
                count += translate.tag_events(esq, "Whitelisted", tag=options.tag)
        print translate.grn.format(str(count)) + " items tagged ..."
        count = 0
    sys.exit(1)

if options.ips is not None:
    ip_files = []
    ip_files.extend(glob.glob(options.ips))
    tpl = {}
    count = 0
#    esq = translate.tpl2esq(cfg.cfg["global_filters"])
    
    for wlf in ip_files:
        try:
            wlfd = open(wlf, "r")
        except:
            print "Unable to open ip file '"+wlf+"'"
            sys.exit(-1)
        for wl in wlfd:
            print "=>"+wl
            tpl["ip"] = wl.strip('\n')
            esq = translate.tpl2esq(tpl)
            pprint.pprint(esq)
            pprint.pprint(tpl)
            count += translate.tag_events(esq, "BadIPS", tag=options.tag)
        print translate.grn.format(str(count)) + " items to be tagged ..."
        count = 0
    sys.exit(1)

# statistics
if options.stats is True:
    print translate.red.format("# Whitelist(ing) ratio :")
    translate.fetch_top(cfg.cfg["global_filters"], "whitelisted", limit=2)
    print translate.red.format("# Top servers :")
    translate.fetch_top(cfg.cfg["global_filters"], "server", limit=10)
    print translate.red.format("# Top URI(s) :")
    translate.fetch_top(cfg.cfg["global_filters"], "uri", limit=10)
    print translate.red.format("# Top Zone(s) :")
    translate.fetch_top(cfg.cfg["global_filters"], "zone", limit=10)
    print translate.red.format("# Top Peer(s) :")
    translate.fetch_top(cfg.cfg["global_filters"], "ip", limit=10)
    sys.exit(1)

# input options, only setup injector if one input option is present
if options.files_in is not None or options.fifo_in is not None or options.stdin is not None or options.syslog_in is not None:
    if options.fifo_in is not None or options.syslog_in is not None:
        injector = ESInject(es, cfg.cfg, auto_commit_limit=1)
    else:
        injector = ESInject(es, cfg.cfg)
    parser = NxParser()
    offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
    offset = offset / 60 / 60 * -1
    if offset < 0:
        offset = str(-offset)
    else:
        offset = str(offset)
    offset = offset.zfill(2)
    parser.out_date_format = "%Y-%m-%dT%H:%M:%S+"+offset #ES-friendly
    try:
        geoloc = NxGeoLoc(cfg.cfg)
    except:
        print "Unable to get GeoIP"
        sys.exit(-1)

if options.files_in is not None:
    reader = NxReader(macquire, lglob=[options.files_in])
    reader.read_files()
    injector.stop()
    sys.exit(1)
if options.fifo_in is not None:
    fd = open_fifo(options.fifo_in)
    if options.infinite_flag is True:
        reader = NxReader(macquire, fd=fd, stdin_timeout=None)
    else:
        reader = NxReader(macquire, fd=fd)
    while True:
        print "start-",
        reader.read_files()
        print "stop"
    injector.stop()
    sys.exit(1)

if options.syslog_in is not None:
    sysloghost = cfg.cfg["syslogd"]["host"]
    syslogport = cfg.cfg["syslogd"]["port"]
    while 1:
      reader = NxReader(macquire, syslog=True, syslogport=syslogport, sysloghost=sysloghost)
      reader.read_files()
    injector.stop()
    sys.exit(1)

if options.stdin is True:
    if options.infinite_flag:
        reader = NxReader(macquire, lglob=[], stdin=True, stdin_timeout=None)
    else:
        reader = NxReader(macquire, lglob=[], stdin=True)
    while True:
        print "start-",
        reader.read_files()
        print "stop"
    sys.exit(1)

opt.print_help()
sys.exit(1)


