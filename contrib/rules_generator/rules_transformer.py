#!/usr/bin/python
import urlparse
import urllib
import pprint
from operator import itemgetter, attrgetter
import sys


class rulz:
    def __init__(self, rules, debug):
        
        self.keyword = "NAXSI_FMT"
        self.fatdict = []
        self.rules = rules
        self.log = debug
        #self.mlog("#RT - Start")
        pass
    def mlog(self, fmt):
        f = open (self.rules, 'a+')
        if not f:
            print "enabled to open dst rules file .."
            return 
        f.write(fmt+"\n")
    def create_rulestruct(self, tmpdict):
        currdict={}
        server=""
        uri=""
        ridx = '0'
        for i in range(len(tmpdict)):
            if (tmpdict[i][0][-1] >= '0' and tmpdict[i][0][-1] <= '9' and
                tmpdict[i][0][-1] != ridx):
                currdict["uri"] = uri
                currdict["server"] = server
                if ("var_name" not in currdict):
                    currdict["var_name"] = ""
                self.fatdict.append(currdict)
                currdict={}
                ridx = tmpdict[i][0][-1]
            if (tmpdict[i][0].startswith("server")):
                server = tmpdict[i][1]
            if (tmpdict[i][0].startswith("uri")):
                uri = tmpdict[i][1]
            if (tmpdict[i][0].startswith("id")):
                currdict["id"] = tmpdict[i][1]
            if (tmpdict[i][0].startswith("zone")):
                currdict["zone"] = tmpdict[i][1]
            if (tmpdict[i][0].startswith("var_name")):
                currdict["var_name"] = tmpdict[i][1]
        # and do the last one :)    
        currdict["uri"] = uri
        currdict["server"] = server
        if ("var_name" not in currdict):
            currdict["var_name"] = ""
        self.fatdict.append(currdict)
    def eat_rules(self, logfile):
        try:
            f = open(logfile, 'r')
        except IOError:
            return
        
        lines = f.readlines()
        f.close()
        # if it's "final" log file, clear it.
        if (logfile is self.rules):
            f = open(logfile, 'w')
            f.close()
        for i in range(len(lines)):
            ln = lines[i]
            ln = ln.strip("\n")
            if ln.find(self.keyword) == -1:
                continue
            #if (logfile is not self.rules):
            self.mlog("#"+ln)
            # just relying on parse_qsl to be clever
            tmpdict = urlparse.parse_qsl(ln)
            self.create_rulestruct(tmpdict)
        self.mlog( "# total rule number pre-opti : "+
                   str(len(self.fatdict))+" in file "+logfile)
        #print "END-OUTPUT"
    def gen_rulz(self):
        #print "END OUTPUT"
        for x in range(len(self.fatdict)):
            tmprule = "BasicRule wl:"+self.fatdict[x]["id"]+ " \"mz:"
            if (len(self.fatdict[x]["uri"]) > 0):
                tmprule += "$URL:"+self.fatdict[x]["uri"]+"|"
            if (len(self.fatdict[x]["var_name"]) > 0):
                tmprule += "$"+self.fatdict[x]["zone"]+"_VAR:"+urllib.quote(self.fatdict[x]["var_name"])
            else:
                tmprule += self.fatdict[x]["zone"]
            tmprule += "\";"
            # finally, write the rule
            self.mlog(tmprule)
    def opti_rulz(self, search_id=-1, search_zone=""):
        self.fatdict.sort(key=itemgetter('zone'))
        self.fatdict.sort(key=itemgetter('id'))
        cid_start = -1
        cid_end = -1
        last = 0
        if (search_id == -1):
            search_id = int(self.fatdict[0]["id"])
            if (search_zone == ""):
                search_zone = self.fatdict[0]["zone"]
        
        #print "[post init] searching id:"+str(search_id)+", zone:"+search_zone
        # seek the zone were the ID starts
        for i in range(len(self.fatdict)):
            tmpid = int(self.fatdict[i]["id"])
            tmpzone = self.fatdict[i]["zone"]
            if (search_id == tmpid):
                if (search_zone == ""):
                    search_zone = tmpzone
                    break
                elif (search_zone == tmpzone):
                    break
        cid_start = i
        # step 1 : Identify range of rules targetting ID and ZONE given as args.
        for x in range(cid_start, len(self.fatdict)):
            tmpid = int(self.fatdict[x]["id"])
            tmpzone = self.fatdict[x]["zone"]
            # good id, but wrong zone, group switch
            if (search_id == tmpid and search_zone != tmpzone):
                print "RANGE for ID="+str(search_id)+",ZONE="+search_zone+", range="+str(cid_start)+"-"+str(x)
                self.agreggate_rulesrange(cid_start, x)
                #opti
                self.opti_rulz(tmpid, tmpzone)
                return
            if (search_id != tmpid):
                print "RANGE for ID="+str(search_id)+",ZONE="+search_zone+", range="+str(cid_start)+"-"+str(x)
                self.agreggate_rulesrange(cid_start, x)
                #opti
                self.opti_rulz(tmpid, "")
                return
        if (x == len(self.fatdict)-1):
            print "RANGE for ID="+str(search_id)+",ZONE=NONE, range="+str(cid_start)+"-"+str(x)
            self.agreggate_rulesrange(cid_start, x+1)
            
    def agreggate_rulesrange(self, start, end):
        same_url = 1
        same_zone = 1
        same_name = 1
        saw_rule_without_url = -1
        id = self.fatdict[start]["id"]
        uri = self.fatdict[start]["uri"]
        zone = self.fatdict[start]["zone"]
        var_name = self.fatdict[start]['var_name']
        cid = self.fatdict[start]["id"]
        for z in range(start, end):
            if (self.fatdict[z]["uri"] is ""):
                saw_rule_without_url = i
            if (self.fatdict[z]["uri"] != self.fatdict[start]["uri"]):
                same_url = 0
            if (self.fatdict[z]["zone"] != self.fatdict[start]["zone"]):
                same_zone = 0
            if (self.fatdict[z]["var_name"] != self.fatdict[start]["var_name"]):
                same_name = 0
        # if we have duplicate rules, drop'em
        if (same_zone and same_name and same_url and saw_rule_without_url == -1):
            print "# for rule "+str(id)+", we have "+str(end - start)+" elements in zone "+zone
            print "#duplicate for id "+str(id)+", delete ("+str(end - start)+" elems)"
            del self.fatdict[start+1:end]
        # if we have "inclusive" rules, a.k.a one agreggating others
        if (saw_rule_without_url > -1):
            print "# for rule "+str(id)+", we have "+str(end - start)+" elements in zone "+zone
            print "#GLOB for id "+str(id)+", "+str(end - start)+" rules agreggated !"
            del self.fatdict[start:end]
            self.fatdict.append({'id' : id,
                                 'server' : server,
                                 'uri': '',
                                 'zone' : zone,
                                 'var_name' : var_name})
            # if we can agreggate on zone+arg_name
        if (same_zone and same_name and not same_url):
            print "# for rule "+str(id)+", we have "+str(end - start)+" elements in zone "+zone
            print "#opti for id "+str(id)+", "+str(end - start)+" rules agreggated !"
            del self.fatdict[start:end]
            self.fatdict.append({'id' : id, 
                                 'uri': '',
                                 'zone' : zone,
                                 'var_name' : var_name})
                
#        pprint.pprint(self.fatdict)
dst_rules="/tmp/RT_naxsi.tmp"
debug_log="/tmp/nginx_error.log"
print "NAXSI rules generator (from nginx's logs)"
print "args: [debug_log="+debug_log+"] [rules file="+dst_rules+"]"
#print "args:"+str(len(sys.argv))
if (len(sys.argv) > 1):
    debug_log = sys.argv[1]
if (len(sys.argv) > 2):
    dst_rules = sys.argv[2]
r = rulz(dst_rules, debug_log)
r.eat_rules(dst_rules)
r.eat_rules(debug_log)
r.fatdict.sort(key=itemgetter('id'))
#pprint.pprint(r.fatdict)
# sort'em
r.opti_rulz()
pprint.pprint(r.fatdict)
r.gen_rulz()


            
