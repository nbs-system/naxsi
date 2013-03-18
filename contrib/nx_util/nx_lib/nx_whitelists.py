import pprint

class NxWhitelistExtractor:
    def __init__(self, cursor, rules_file, pages_hit=10, rules_hit=20, exlog_max=5):
        self.wrapper = cursor
        self.rules_list = []
        self.final_rules = []
        self.base_rules = []
        self.pages_hit = pages_hit
        self.rules_hit = rules_hit
        self.core_msg = {}
        self.extract_core(rules_file)
        self.exlog_max = exlog_max
       
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
            print "Unable to open rules file :"+rules_file
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
        """ Perform a serie of predefined SELECTs to 
        find possible whitelist factorisations """
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
            res = self.wrapper.execute(req)
#            res = self.wrapper.getResults()
            for r in res:
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

    def try_append(self, target, delmatch=False):
        """returns true if whitelist 'target' is already handled by final_rules
        does a dummy comparison and compares the counters"""
        count=0
        nb_rule=0
        uurl = set()
        
        for z in self.final_rules[:]:
            if len(target['url']) > 0 and len(z['url']) > 0 and target['url'] != z['url']:
                continue
            if target['rule_id'] != 0 and z['rule_id'] != 0 and target['rule_id'] != z['rule_id']:
                continue
            if len(target['zone']) > 0 and len(z['zone']) > 0 and target['zone'] != z['zone']:
                continue
            if len(target['var_name']) > 0 and len(z['var_name']) > 0 and target['var_name'] != z['var_name']:
                continue
            #print "url:"+target['url']
            uurl.add(z['url'])
            if delmatch is True:
                self.final_rules.remove(z)
            else:
                nb_rule += 1
                count += int(z['hcount'])
        if delmatch is True:
            return
        # No rules are matching this one, append.
        if not count and not nb_rule:
            self.final_rules.append(target)
        # Check the number of unique URLs covered by the rule
        if target['hcount'] >= count and len(uurl) > self.pages_hit:
            self.try_append(target, True)
            self.final_rules.append(target)
            return
        # Check the nimber of unique IDs covered by the rule
        if (target['hcount'] > count+1) or (target['hcount'] >= count and nb_rule > self.rules_hit):
            self.try_append(target, True)
            self.final_rules.append(target)
            return
    
    def lookup_exlog(self, rule):
        """Lookup into DB if we can find an exception 
        that fits the criterias, and has a content (from EXLOG)"""
        first = True
        args = []
        append = ""
        find_back = ("select  e.rule_id, e.zone, e.var_name, u.url, e.content "
                     "from exceptions as e, urls as u, connections as c where "
                     "c.url_id = u.url_id and c.id_exception = e.exception_id "
                     " AND length(e.content) > 0 GROUP BY u.url, e.var_name, e.zone, e.rule_id")
        # If rule_id is present, match it.
        if rule['rule_id'] != 0:
            append += "e.rule_id == ?"
            args.append(str(rule['rule_id']))
            first = False
        # same goes for zone
        if len(rule['zone']) > 0:
            if first is False:
                append += " AND "
            append += "e.zone == ?"
            args.append(rule['zone'])
            first = False
        # and url
        if len(rule['url']) > 0:
            if first is False:
                append += " AND "
            append += "u.url == ?"
            args.append(rule['url'])
            first = False
        # and finally, var_name
        if len(rule['var_name']) > 0:
            if first is False:
                append += " AND "
            append += "e.var_name == ?"
            args.append(rule['var_name'])
            first = False
            
        if first is False:
            req = find_back+" HAVING "+append
        res = self.wrapper.execute(req, tuple(args))
#        res = self.wrapper.getResults()
        return res
    
    def format_rules_output(self, opti_rules):
        r = '########### Optimized Rules Suggestion ##################\n'
        if not len(opti_rules):
            r+= "#No rules to be generated\n"
            return
        opti_rules.sort(key=lambda k: (k['hratio'], k['pratio']))
        _i = len(opti_rules)-1
        while _i >= 0:
            exlog_count = 0
            i = opti_rules[_i]
            _i = _i - 1
            r += ("# total_count:"+str(i['hcount'])+" ("+str(i['hratio'])+
                  "%), peer_count:"+str(i['pcount'])+" ("+str(i['pratio'])+"%)")
            r += " | "+self.core_msg.get(str(i['rule_id']), "?")+"\n"
            res = self.lookup_exlog(i)
            for exlog in res:
                r += "#exemple (from exlog) : '"+str(res[4][0][4])+"'\n"
                exlog_count += 1
                if exlog_count > self.exlog_max:
                    break
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
                if "FILE_EXT" in i['zone'] and i['var_name'] is not None and len(i['var_name']) > 0:
                    i['zone'] = i['zone'].replace("FILE_EXT", "BODY")
                    if i['var_name'] is None:
                        i['var_name'] = ''
                    i['var_name'] = i['var_name']+"|FILE_EXT"
                if "|NAME" in i['zone'] and i['var_name'] is not None and len(i['var_name']) > 0:
                    i['zone'] = i['zone'].replace("|NAME", "")
                    if i['var_name'] is None:
                        i['var_name'] = ''
                    i['var_name'] = i['var_name']+"|NAME"
                r += i['zone']
            if i['var_name'] is not None and len(i['var_name']) > 0:
                r = r[:-len(i['zone'])]+"$"+r[-len(i['zone']):]
                r += "_VAR:"+i['var_name']
            r += '";\n'      
        return r
