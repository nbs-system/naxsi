from datetime import datetime

import urlparse
import pprint
import hashlib
import itertools
import sys
import re
from NaxsiLib.SQLWrapper import SQLWrapper


class signature_parser:
    def __init__(self, wrapper, log, tab):
        self.tab = tab
        self.log = log
        self.wrapper = wrapper
        try:
            self.wrapper.execute("SELECT 1 FROM exceptions")
        except :
            self.log.warning("Unable to select, DB must be empty. Create ...")
#            self.log.warning("exception:"+str(sys.exc_info()[0]))
            self.dbcreate()

    def dbcreate(self):
        self.log.warning ("Droping and creating new tables")
        self.wrapper.create_all_tables()

    def last_id(self):
        return self.wrapper.getLastId()

    def insert(self, fmt, *args):
        self.wrapper.execute(fmt, [args])

    def add_matchzones(self, exception_id, d):
        for i in range(0, 100):
            zn = ""
            vn = ""
            if "zone"+str(i) in d:
                zn = d.get("zone"+str(i), "")
            else:
                break
            if "var_name"+str(i) in d:
                vn = d.get("var_name"+str(i), "")

            self.wrapper.execute("INSERT INTO match_zone (exception_id, "
                                "zone, arg_name, rule_id) "
                                "VALUES (%s, %s, %s, %s)", 
                                (str(exception_id), zn, vn, 
                                 d.get("id"+str(i), "")))
        return
    def try_log_request(self, raw_request, sig):
        if self.tab is None:
            #self.log.warning("Monitor rules are empty, skip.")
            return
        tmpsig = re.sub("total_processed=\d+", "total_processed=0", sig)
        tmpsig = re.sub("total_blocked=\d+", "total_blocked=0", tmpsig)
        for x in self.tab:
#            print "try: "+x+" vs "+tmpsig
            if x in tmpsig:
                self.log.critical("Monitoring request !")
                self.log.critical(raw_request)
                return
        return
    
    def sig_to_db(self, raw_request, sig, date=None, learning=1):
        """
        Insert signature into database. returns 
        associated connection_id.
        """
        if date is None:
            date = datetime.now()
        d = dict(urlparse.parse_qsl(sig))
#        pprint.pprint(d)
#        self.log.warning("sig:"+sig)
        if not d.has_key('server'):
            d['server'] = ''
        if not d.has_key('uri'):
            d['uri'] = ''
        self.try_log_request(raw_request, sig)
        if learning is 0:
            return
        self.wrapper.execute("INSERT INTO urls (url) VALUES (%s)", (d['uri'],))
        url_id = self.wrapper.getLastId()
#        self.log.warning( "url id "+str(url_id))
        for i in itertools.count():
            zn = ''
            vn = ''
            rn = ''
            if 'zone' + str(i) in d.keys():
                zn  = d['zone' + str(i)]
            else:
                break
            if 'var_name' + str(i) in d.keys():
                vn = d['var_name' + str(i)]
            if 'id' + str(i) in d.keys():
                rn = d['id' + str(i)]
            self.wrapper.execute('INSERT INTO exceptions (zone, var_name, rule_id) VALUES (%s,%s,%s)', (zn, vn, rn))
            exception_id  = self.wrapper.getLastId()
            self.wrapper.execute('INSERT INTO connections (peer_ip, host, url_id, id_exception,date) VALUES (%s,%s,%s,%s,%s)', (d['ip'], d['server'], str(url_id), str(exception_id), date))
    

class rules_extractor:
    def __init__(self, pages_hit, rules_hit, rules_file, conf_file, log):
        self.log = log
        self.wrapper = SQLWrapper(conf_file, self.log)
        self.wrapper.connect()
        self.wrapper.setRowToDict()
        self.rules_hit = self.page_hit = 10
        self.rules_list = []
        self.final_rules = []
        self.base_rules = []
        self.pages_hit = pages_hit
        self.rules_hit = rules_hit
        self.core_msg = {}
        self.extract_core(rules_file)
#        self.log.warning( "Rules hit setting : "+str(self.rules_hit))
       
    def extract_core(self, rules_file):
        try:
            fd = open(rules_file, 'r')
            for i in fd:
                if i.startswith('MainRule') or i.startswith('#@MainRule'):
                    pos = i.find('id:')
                    pos_msg = i.find('msg:')
                    self.core_msg[i[pos + 3:i[pos + 3].find(';') - 1]] = i[pos_msg + 4:][:i[pos_msg + 4:].find('"')]
            fd.close()
        except:
            self.log.warning ("Unable to open rules file.")
            pass

    def gen_basic_rules(self,url=None, srcip=None, dsthost=None,
                        rule_id=None, exception_md5=None,
                        exception_id=None):

        tmp_rules = []
        self.base_rules = self.rules_list[:]

    def transform_to_dict(self, l):
        d = {}
        for i in l:
            if not d.has_key(i[0]):
                d[i[0]] = []
            d[i[0]].append(i[1])
      #elimininate duplicate ids in each value
        for i in d:
            d[i] = list(set(d[i]))
        return d

    def opti_rules_back(self):
        # rules of requests extracting optimized whitelists, from 
        # more restrictive to less restrictive.
        opti_select_DESC = [
            # select on url+var_name+zone+rule_id
            ("select  count(*) as ct, e.rule_id, e.zone, e.var_name, u.url, count(distinct c.peer_ip) as peer_count, "
             "(select count(distinct peer_ip) from connections) as ptot, "
             "(select count(*) from connections) as tot "
             "from exceptions as e, urls as u, connections as c where c.url_id "
             "= u.url_id and c.id_exception = e.exception_id GROUP BY u.url, e.var_name,"
             "e.zone, e.rule_id HAVING (ct) > ((select count(*) from connections)/1000)"),
            # select on var_name+zone+rule_id (unpredictable URL)
            ("select  count(*) as ct, e.rule_id, e.zone, e.var_name, '' as url, count(distinct c.peer_ip) as peer_count, "
             "(select count(distinct peer_ip) from connections) as ptot, "
             "(select count(*) from connections) as tot "
             "from exceptions as e, urls as u, connections as c where c.url_id = u.url_id and c.id_exception = "
             "e.exception_id GROUP BY e.var_name,  e.zone, e.rule_id HAVING (ct) > "
             "((select count(*) from connections)/1000)"),
            # select on zone+url+rule_id (unpredictable arg_name)
            ("select  count(*) as ct, e.rule_id, e.zone, '' as var_name, u.url, count(distinct c.peer_ip) as peer_count, "
             "(select count(distinct peer_ip) from connections) as ptot, "
             "(select count(*) from connections) as tot "
             "from exceptions as e, urls as u, connections as c where c.url_id "
             "= u.url_id and c.id_exception = e.exception_id GROUP BY u.url, "
             "e.zone, e.rule_id HAVING (ct) > ((select count(*) from connections)/1000)"),
            # select on zone+url+var_name (unpredictable id)
            ("select  count(*) as ct, 0 as rule_id, e.zone, e.var_name, u.url, count(distinct c.peer_ip) as peer_count, "
             "(select count(distinct peer_ip) from connections) as ptot, "
             "(select count(*) from connections) as tot "
             "from exceptions as e, urls as u, connections as c where c.url_id "
             "= u.url_id and c.id_exception = e.exception_id GROUP BY u.url, "
             "e.zone, e.var_name HAVING (ct) > ((select count(*) from connections)/1000)")
            ]
      
        for req in opti_select_DESC:
        #    print "#------------------- first set of results"
            self.wrapper.execute(req)
            res = self.wrapper.getResults()
            for r in res:
         #       print(r)
                if len(r['var_name']) > 0:
                    self.try_append({'url': r['url'], 'rule_id': r['rule_id'], 'zone': r['zone'],  'var_name': r['var_name'], 
                                     'hcount':  r['ct'], 'htotal': r['tot'], 'pcount':r['peer_count'], 'ptotal':r['ptot'],
                                     'pratio': round((r['peer_count'] / float(r['ptot'])) * 100,2),
                                     'hratio': round((r['ct'] / float(r['tot'])) * 100,2)
                                     })
                else:
                    self.try_append({'url': r['url'], 'rule_id': r['rule_id'], 'zone': r['zone'], 'var_name': '', 
                                     'hcount': r['ct'],  'htotal': r['tot'], 'ptotal':r['ptot'],
                                     'pratio': round((r['peer_count'] / float(r['ptot'])) * 100,2),
                                     'hratio': round((r['ct'] / float(r['tot'])) * 100,2),
                                     'pcount':r['peer_count']})
        return self.base_rules, self.final_rules

#returns true if whitelist 'target' is already handled by final_rules
#does a dummy comparison and compares the counters
    def try_append(self, target, delmatch=False):
        count=0
        nb_rule=0
        uurl = set()
        
#        print "########## TRY APPEND :"
#        pprint.pprint(target)
#        print "--- vs ---"
        for z in self.final_rules[:]:
            if len(target['url']) > 0 and len(z['url']) > 0 and target['url'] != z['url']:
                continue
            if target['rule_id'] != 0 and z['rule_id'] != 0 and target['rule_id'] != z['rule_id']:
                continue
            if len(target['zone']) > 0 and len(z['zone']) > 0 and target['zone'] != z['zone']:
                continue
            if len(target['var_name']) > 0 and len(z['var_name']) > 0 and target['var_name'] != z['var_name']:
                continue
#            pprint.pprint(z)
            #print "url:"+target['url']
            uurl.add(z['url'])
            if delmatch is True:
                #print(z)
                self.final_rules.remove(z)
            else:
                nb_rule += 1
                count += int(z['hcount'])
        if delmatch is True:
            return
        # No rules are matching this one, append.
        if not count and not nb_rule:
            self.final_rules.append(target)
#        print "Number of unique URLS covered "+str(len(uurl))
        if target['hcount'] >= count and len(uurl) > self.pages_hit:
            self.try_append(target, True)
            self.final_rules.append(target)
            return
            
        if (target['hcount'] > count+1) or (target['hcount'] >= count and nb_rule > self.rules_hit):
            self.try_append(target, True)
            self.final_rules.append(target)
            return

    def generate_stats(self):
        stats = ""
        self.wrapper.execute("select count(distinct exception_id) as uniq_exception from exceptions")
        uniq_ex = self.wrapper.getResults()[0]['uniq_exception']
        self.wrapper.execute("select count(distinct peer_ip) as uniq_peer from connections")
        uniq_peer = self.wrapper.getResults()[0]['uniq_peer']
        return "There is currently %s unique exceptions, with %s different peers that triggered rules." % (uniq_ex, uniq_peer)

    def format_rules_output(self, opti_rules):
        r = '########### Optimized Rules Suggestion ##################\n'
        if not len(opti_rules):
            r+= "#No rules to be generated\n"
            return
        opti_rules.sort(key=lambda k: (k['hratio'], k['pratio']))
        _i = len(opti_rules)-1
        while _i >= 0:
            i = opti_rules[_i]
            _i = _i - 1
            r += ("# total_count:"+str(i['hcount'])+" ("+str(i['hratio'])+
                  "%), peer_count:"+str(i['pcount'])+" ("+str(i['pratio'])+"%)")
            r += " | "+self.core_msg.get(str(i['rule_id']), "?")+"\n"
            if (i['hratio'] < 5 and i['pratio'] < 5) or (i['pratio'] < 5):
                r += '#'
            r += 'BasicRule wl:' + str(i['rule_id']) + ' "mz:'
            if i['url'] is not None and len(i['url']) > 0:
                r += '$URL:' + i['url']
            if i['rule_id'] == 1 and i['zone'] == "REQUEST":
                r += '";\n'
                continue
            if i['zone'] is not None and len(i['zone']) > 0:
                if i['url']:
                    r += '|'
                if "|NAME" in i['zone'] and i['var_name'] is not None and len(i['var_name']) > 0:
                    i['zone'] = i['zone'].replace("|NAME", "")
                    if i['var_name'] is None:
                        i['var_name'] = ''
                    i['var_name'] = i['var_name']+"|NAME"
                r += i['zone']
            if i['var_name'] is not None and len(i['var_name']) > 0:
                # oooh, that must be bad.
                r = r[:-len(i['zone'])]+"$"+r[-len(i['zone']):]
                r += "_VAR:"+i['var_name']
            r += '";\n'      
        return r
                            
if __name__ == '__main__':
    print 'This module is not intended for direct use. Please launch nx_intercept.py or nx_extract.py'
