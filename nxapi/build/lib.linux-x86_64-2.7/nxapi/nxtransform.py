import logging
import json
import copy
import operator
import os
import pprint
import shlex
import datetime


class NxConfig():
    """ Simple configuration loader """
    cfg = {}
    def __init__(self, fname):
        try:
            self.cfg = (json.loads(open(fname).read()))
        except:
            logging.critical("Unable to open/parse configuration file.")
            raise ValueError
    
class NxTranslate():
    """ Transform Whitelists, template into
    ElasticSearch queries, and vice-versa, conventions :
    esq : elasticsearch query
    tpl : template
    cr : core rule
    wl : whitelist """
    def __init__(self, es, cfg):
        self.es = es
        self.debug = True
        self.cfg = cfg.cfg
        self.cfg["global_warning_rules"] = self.normalize_checks(self.cfg["global_warning_rules"])
        self.cfg["global_success_rules"] = self.normalize_checks(self.cfg["global_success_rules"])
        self.core_msg = {}
        # by default, es queries will return 1000 results max
        self.es_max_size = self.cfg.get("elastic").get("max_size", 1000)
        print "# size :"+str(self.es_max_size)
        # purely for output coloring
        self.red = '{0}'
        self.grn = '{0}'
        self.blu = '{0}'
        if self.cfg["output"]["colors"] == "true":
            self.red = "\033[01;31m{0}\033[00m"
            self.grn = "\033[1;36m{0}\033[00m"
            self.blu = "\033[1;94m{0}\033[00m"
        # Attempt to parse provided core rules file
        self.load_cr_file(self.cfg["naxsi"]["rules_path"])

    def full_auto(self):
        """ Loads all tpl within template_path
        If templates has hit, peers or url(s) ratio > 15%,
        attempts to generate whitelists.
        Only displays the wl that did not raise warnings, ranked by success"""
        # gather total IPs, total URIs, total hit count
        strict = True
        if self.cfg.get("naxsi").get("strict", "") == "false":
            strict = False
        total_peers = len(self.fetch_uniques(self.cfg["global_filters"], "ip"))
        total_uri = len(self.fetch_uniques(self.cfg["global_filters"], "uri"))
        x =  self.search( self.tpl2esq(self.cfg["global_filters"]) )
        total_hits = self.search( self.tpl2esq(self.cfg["global_filters"]) )['hits']['total']

        for root, dirs, files in os.walk(self.cfg["naxsi"]["template_path"]):
            for file in files:
                if file.endswith(".tpl"):
                    print "# "+self.grn.format(" template :")+root+"/"+file+" "
                    template = self.load_tpl_file(root+"/"+file)
                    esq = self.tpl2esq(template)
                    x = self.search(esq)
                    hratio =  round( (float(x['hits']['total']) / total_hits) * 100.0, 2)
                    print "# "+self.grn.format(str(x['hits']['total']))+" hits ("+str(hratio)+"% of total - "+str(total_hits)+")"
                    y = self.fetch_uniques(template, "ip")
                    pratio =  round( (float(len(y)) / total_peers) * 100.0, 2)
                    print "# "+self.grn.format(str(len(y)))+" peers triggered this ("+str(pratio)+"% of total - "+str(total_peers)+")"
                    y = self.fetch_uniques(template, "uri")
                    uratio = round((float(len(y)) / total_uri) * 100.0, 2)
                    print "# "+self.grn.format(str(len(y)))+" URIs triggered this ("+str(uratio)+"% of total - "+str(total_uri)+")"
                    # full auto baby !
                    if hratio > 15 or pratio > 15 or uratio > 15:
                        print self.grn.format("#  template matched, generating all rules.")
                        whitelists = self.gen_wl(template, rule={})
                        print str(len(whitelists))+" whitelists ..."
                        for genrule in whitelists:
                            stats = self.gather_stats(genrule['rule'], template)
                            stats['total_hits'] = total_hits
                            #stats['total_ip_count'] = total_ip_count
                            stats['rule_hits'] = float(genrule['total_hits'])
                            stats['hit_ratio_template'] = (stats['rule_hits'] / stats['total_hits'] ) * 100
                            ratings = self.check_success(template, stats)
                            if strict is True and ratings['warning'] > 0:
                                #print "DISCARD:WARNING"
                                continue
                            if strict is True and ratings['success'] <= 0:
                                #print "DISCARD:NO_SUCCESS"
                                continue
                            self.display_rule(ratings, stats, genrule['rule'], template, genrule['content'])

    def load_tpl_file(self, tpl):
        """ open, json.loads a tpl file,
        cleanup data, return dict. """
        try:
            x = open(tpl)
        except:
            logging.error("Unable to open tpl file.")
            return None
        tpl_s = ""
        for l in x.readlines():
            if l.startswith('#'):
                continue
            else:
                tpl_s += l
        try:
            template = json.loads(tpl_s)
        except:
            logging.error("Unable to load json from '"+tpl_s+"'")
            return None
        if '_success' in template.keys():
            template['_success'] = self.normalize_checks(template['_success'])
        if '_warning' in template.keys():
            template['_warning'] = self.normalize_checks(template['_warning'])
        #return self.tpl_append_gfilter(template)
        return template
    def load_wl_file(self, wlf):
        """ Loads a file of whitelists,
        convert them to ES queries, 
        and returns them as a list """
        esql = []
        try:
            wlfd = open(wlf, "r")
        except:
            logging.error("Unable to open whitelist file.")
            return None
        for wl in wlfd:
            [res, esq] = self.wl2esq(wl)
            if res is True:
                esql.append(esq)
        if len(esql) > 0:
            return esql
        return None
    def load_cr_file(self, cr_file):
        """ parses naxsi's core rule file, to
        decorate output with "msg:" field content """
        core_msg = {}
        core_msg['0'] = "id:0 is wildcard (all rules) whitelist."
        try:
            fd = open(cr_file, 'r')
            for i in fd:
                if i.startswith('MainRule') or i.startswith('#@MainRule'):
                    pos = i.find('id:')
                    pos_msg = i.find('msg:')
                    self.core_msg[i[pos + 3:i[pos + 3].find(';') - 1]] = i[pos_msg + 4:][:i[pos_msg + 4:].find('"')]
            fd.close()
        except:
            logging.error("Unable to open rules file")
    def tpl2esq(self, ob, full=True):
        ''' receives template or a rule, returns a valid 
        ElasticSearch query '''
        qr = { 
            "query" : { "bool" : { "must" : [ ]} },
            "size" : self.es_max_size
            }

        for k in ob.keys():
            if k.startswith("_"):
                continue
            # if key starts with '?' :
            # use content for search, but use content from exceptions to generate WL
            if k[0] == '?':
                k = k[1:]
                qr['query']['bool']['must'].append({"regexp" : { k : ob['?'+k] }})
            # wildcard
            elif ob[k] == '?':
                pass
            else:
                qr['query']['bool']['must'].append({"text" : { k : ob[k]}})

        qr = self.append_gfilter(qr)
        return qr
    def append_gfilter(self, esq):
        """ append global filters parameters 
        to and existing elasticsearch query """
        for x in self.cfg["global_filters"]:
            if {"text" : { x : self.cfg["global_filters"][x] }} not in esq['query']['bool']['must']:
                esq['query']['bool']['must'].append({"text" : { x : self.cfg["global_filters"][x] }})
            # else:
            #     print "double!"
        return esq
    def tpl_append_gfilter(self, tpl):
        for x in self.cfg["global_filters"]:
            tpl[x] = self.cfg["global_filters"][x]
        return tpl
    def wl2esq(self, raw_line):
        """ parses a fulltext naxsi whitelist,
        and outputs the matching es query (ie. for tagging),
        returns [True|False, error_string|ESquery] """
        esq = { 
            "query" : { "bool" : { "must" : [ ]} },
            "size" : self.es_max_size
            }
        wl_id = ""
        mz_str = ""
        # do some pre-check to ensure it's a valid line
        if raw_line.startswith("#"):
            return [False, "commented out"]
        if raw_line.find("BasicRule") == -1:
            return [False, "not a BasicRule"]
        # split line
        strings = shlex.split(raw_line)
        # more checks
        if len(strings) < 3:
            return [False, "empty/incomplete line"]
        if strings[0].startswith('#'):
            return [False, "commented line"]
        if strings[0] != "BasicRule":
            return [False, "not a BasicRule, keyword '"+strings[0]+"'"]
        if strings[len(strings) - 1].endswith(';'):
            strings[len(strings) - 1] = strings[len(strings) - 1][:-1]
        for x in strings:
            if x.startswith("wl:"):
                wl_id = x[3:]
                # if ID contains "," replace them with OR for ES query
                wl_id = wl_id.replace(",", " OR ")
                # if ID != 0 add it, otherwise, it's a wildcard!
                if wl_id != "0":
                    # if IDs are negative, we must exclude all IDs except
                    # those ones.
                    if wl_id.find("-") != -1:
                        wl_id = wl_id.replace("-", "")
                        #print "Negative query."
                        if not 'must_not' in tpl['query']['bool'].keys():
                            esq['query']['bool']['must_not'] = []
                        esq['query']['bool']['must_not'].append({"text" : { "id" : wl_id}})
                    else:
                        esq['query']['bool']['must'].append({"text" : { "id" : wl_id}})
            if x.startswith("mz:"):
                mz_str = x[3:]
                [res, filters] = self.parse_mz(mz_str, esq)
                if res is False:
                    #print "mz parse failed : "+str(filters)
                    return [False, "matchzone parsing failed."]
        #print "#rule: "+raw_line
        #pprint.pprint(filters)
        esq = self.append_gfilter(esq)
        #print "##after :"
        #pprint.pprint(filters)
        return [True, filters]
    def parse_mz(self, mz_str, esq):
        """ parses a match zone from BasicRule, and updates
        es query accordingly """
        kw = mz_str.split("|")
        tpl = esq['query']['bool']['must']
        uri = ""
        zone = ""
        var_name = ""
        t_name = False
        # |NAME flag
        if "NAME" in kw:
            t_name = True
            kw.remove("NAME")
        for k in kw:
            # named var
            if k.startswith('$'):
                k = k[1:]
                try:
                    [zone, var_name] = k.split(':')
                except:
                    return [False, "Incoherent zone : "+k]
                # *_VAR:<string>
                if zone.endswith("_VAR"):
                    zone = zone[:-4]
                    if t_name is True:
                        zone += "|NAME"
                    tpl.append({"text" : { "zone" : zone}})
                    tpl.append({"text" : { "var_name" : var_name}})
                # *_VAR_X:<regexp>
                elif zone.endswith("_VAR_X"):
                    zone = zone[:-6]
                    if t_name is True:
                        zone += "|NAME"
                    tpl.append({"text" : { "zone" : zone}})
                    tpl.append({"regexp" : { "var_name" : var_name}})
                # URL_X:<regexp>
                elif zone == "URL_X":
                    zone = zone[:-2]
                    tpl.append({"regexp" : { "uri" : var_name}})
                # URL:<string>
                elif zone == "URL":
                    tpl.append({"text" : { "uri" : var_name }})
                else:
                    print "huh, what's that ? "+zone

            # |<ZONE>
            else:
                if k not in ["HEADERS", "BODY", "URL", "ARGS"]:
                    return [False, "Unknown zone : '"+k+"'"]
                zone = k
                if t_name is True:
                    zone += "|NAME"
                tpl.append({"text" : {"zone" : zone}})
        return [True, esq]
    def tpl2wl(self, rule):
        """ transforms a rule/esq
        to a valid BasicRule. """
        tname = False
        zone = ""

        wl = "BasicRule "
        wl += " wl:"+str(rule.get('id', 0))

        wl += ' "mz:'

        if rule.get('uri', None) is not None:
            wl += "$URL:"+rule['uri']
            wl += "|"
        # whitelist targets name    
        if rule.get('zone', '').endswith("|NAME"):
            tname = True
            zone = rule['zone'][:-5]
        else:
            zone = rule['zone']

        if rule.get('var_name', '') not in  ['', '?']:
            wl += "$"+zone+"_VAR:"+rule['var_name']
        else:
            wl += zone

        if tname is True:
            wl += "|NAME"

        wl += '";'
        return wl
    #def check_criterias(self, template, , stats, results):
    #pass
    def check_success(self, rule, stats):
        """ check met/failed success/warning criterias
        of a given template vs a set of results """
        score = 0
        warnings = 0

        # Check as rule's specific warning criterias
        if '_warning' in rule.keys():
            for sucrule in rule['_warning'].keys():
                if sucrule not in stats.keys():
                    continue
                else:
                    if rule['_warning'][sucrule][0](stats[sucrule], rule['_warning'][sucrule][1]) is True:
                        warnings += 1
        # Check success rules, and increase score if conditions are met.
        for sucrule in rule['_success'].keys():
            if sucrule not in stats.keys():
                continue
            else:
                if rule['_success'][sucrule][0](stats[sucrule], rule['_success'][sucrule][1]) is True:
                    score += 1

        # Check generic success rules and generic warnings
        for sucrule in self.cfg["global_warning_rules"].keys():
            if sucrule not in stats.keys():
                continue
            else:
                if self.cfg["global_warning_rules"][sucrule][0](stats[sucrule], self.cfg["global_warning_rules"][sucrule][1]) is True:
                    warnings += 1

        # Check generic success rules and generic warnings
        for sucrule in self.cfg["global_success_rules"].keys():
            if sucrule not in stats.keys():
                continue
            else:
                if self.cfg["global_success_rules"][sucrule][0](stats[sucrule], self.cfg["global_success_rules"][sucrule][1]) is True:
                    score += 1
        return { 'success' : score, 'warning' : warnings }
    def fetch_top(self, template, field, limit=10):
        """ fetch top items for a given field,
        clears the field if exists in gfilters """
        x = None
        if field in template.keys():
            x = template[field]
            del template[field]
        esq = self.tpl2esq(template)
        if x is not None:
            template[field] = x
        esq['facets'] =  { "facet_results" : {"terms": { "field": field, "size" : self.es_max_size} }}
        res = self.search(esq)
        total = res['facets']['facet_results']['total']
        count = 0
        for x in res['facets']['facet_results']['terms']:
            print "# "+self.grn.format(x['term'])+" "+str(round( (float(x['count']) / total) * 100.0, 2))+" % (total:"+str(x['count'])+"/"+str(total)+")"
            count += 1
            if count > limit:
                break
    def fetch_uniques(self, rule, key):
        """ shortcut function to gather unique
        values and their associated match count """
        uniques = []
        esq = self.tpl2esq(rule)
        esq['facets'] =  { "facet_results" : {"terms": { "field": key, "size" : self.es_max_size} }}
        #res = self.es.search(index=self.cfg["elastic"]["index"], doc_type=self.cfg["elastic"]["doctype"], body=esq)
        res = self.search(esq)
        for x in res['facets']['facet_results']['terms']:
            uniques.append(x['term'])
        return uniques
    def index(self, body, eid):
        return self.es.index(index=self.cfg["elastic"]["index"], doc_type=self.cfg["elastic"]["doctype"], body=body, id=eid)
    def search(self, esq, stats=False):
        """ search wrapper with debug """
        debug = False
        
        if debug is True:
            print "#SEARCH:PARAMS:index="+self.cfg["elastic"]["index"]+", doc_type="+self.cfg["elastic"]["doctype"]+", body=",
            print "#SEARCH:QUERY:",
            pprint.pprint (esq)
        if len(esq["query"]["bool"]["must"]) == 0:
            del esq["query"]
        x = self.es.search(index=self.cfg["elastic"]["index"], doc_type=self.cfg["elastic"]["doctype"], body=esq)
        if debug is True:
            print "#RESULT:",
            pprint.pprint(x)
        return x
    def normalize_checks(self, tpl):
        """ replace check signs (<, >, <=, >=) by 
                operator.X in a dict-form tpl """
        replace = {
            '>' : operator.gt,
            '<' : operator.lt,
            '>=' : operator.ge,
            '<=' : operator.le
            }
        
        for tpl_key in tpl.keys():
            for token in replace.keys():
                if tpl[tpl_key][0] == token:
                    tpl[tpl_key][0] = replace[token]
        return tpl
    def display_rule(self, ratings, stats, tmprule, template, contents=[]):
        """ displays a given rule+template to BasicRule,
        along with collected statistics """
        # If at least one warning was triggered, it might be a false positive
        if template is not None and '_statics' in template.keys():
            for k in template['_statics'].keys():
                tmprule[k] = template['_statics'][k]

        print "\n\n"
        if ratings['warning'] > 0:
            print self.red.format("# At least one warning was raised, might be a FP")
            print "# Warnings : "+self.red.format('*' * ( ratings['warning']))
        
        print "# Rating : "+self.grn.format('*' * ( ratings['success'] - ratings['warning']))
        print "# "+str(round(stats['hit_ratio_template'], 2))+"% of (total) evts matched WL ("+str(stats['rule_hits'])+"/"+str(stats['total_hits'])+")"
        print "# "+str(round(stats['ip_ratio_global'], 2))+"% of (total) peers triggered this WL ("+str(stats['rule_ip_count'])+"/"+str(stats['global_ip_count'])+")"
        print "# "+str(round(stats['ip_ratio_template'], 2))+"% of (orig rule) peers triggered this WL ("+str(stats['rule_ip_count'])+"/"+str(stats['template_ip_count'])+")"
        print "# "+str(round(stats['uri_ratio_template'], 2))+"% of (orig rule) URLs triggered this WL ("+str(stats['rule_uri_count'])+"/"+str(stats['template_uri_count'])+")"
        print "# rule: "+self.blu.format(self.core_msg.get(tmprule.get('id', 0), "Unknown"))
        for x in contents:
            print "# content: "+x.encode('utf-8')
        if ratings['success'] > 0:
            print self.grn.format(self.tpl2wl(tmprule)).encode('utf-8')
        else:
            print "# "+self.red.format(self.tpl2wl(tmprule)).encode('utf-8')


    def tag_events(self, esq, msg, tag=False):
        count = 0
        esq["size"] = "0"
        x = self.search(esq)
        print self.grn.format(str(x["hits"]["total"])) + " items to be tagged ..."
        esq["size"] = x["hits"]["total"]
        res = self.search(esq)
        # Iterate through matched evts to tag them.
        for item in res['hits']['hits']:
            eid = item['_id']
            body = item['_source']
            cm = item['_source']['comments']
            body['comments'] += ","+msg+":"+str(datetime.datetime.now())
            body['whitelisted'] = "true"
            if tag is True:
                print "Tagging id: "+eid
                print str(self.index(body, eid))
            else:
                print eid+",",
            count += 1
        print ""
        return count


    def gen_wl(self, tpl, rule={}):
        #print "=>",
        #pprint.pprint(rule)
        retlist = []
        # first, set static values
        for tpl_key in tpl.keys():
            if tpl_key in rule.keys():
                continue
            if tpl_key[0] in ['_', '?']:
                continue
            if tpl[tpl_key] == '?':
                continue
            #print "setting static : x["+tpl_key+"] = '"+tpl[tpl_key]+"'"
            rule[tpl_key] = tpl[tpl_key]
        for tpl_key in tpl.keys():
            if tpl_key.startswith('_'):
                continue
            elif tpl_key.startswith('?'):
                if tpl_key[1:] in rule.keys():
                    continue
                unique_vals = self.fetch_uniques(rule, tpl_key[1:])
                for uval in unique_vals:
                    rule[tpl_key] = uval
                    retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
            elif tpl[tpl_key] == '?':
                if tpl_key in rule.keys():
                    continue
                unique_vals = self.fetch_uniques(rule, tpl_key)
                for uval in unique_vals:
                    rule[tpl_key] = uval
                    retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
            elif tpl_key not in rule.keys():
                rule[tpl_key] = tpl[tpl_key]
                retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
    
        esq = self.tpl2esq(rule)
        res = self.search(esq)
        
        if res['hits']['total'] > 0:
            clist = []
        # extract 'content' for user display
            for x in res['hits']['hits']:
                if len(x.get("_source").get("content", "")) > 0:
                    clist.append(x["_source"]["content"])
                    if len(clist) >= 5:
                        break
                    
            retlist.append({'rule' : rule, 'content' : clist, 'total_hits' : res['hits']['total']})
            return retlist
        return []
    def gather_stats(self, crule, orule):
        ''' Gather statistics crule (current rule) covered exceptions vs orule (original rule) for :
        CRULE VS ORULE :
         - count(peers) matched crule vs count(peers) matched orule
         - count(uri) matched crule vs count(uri) matched orule
        CRULE VS GLOBAL FILTERS
         - count(peers) matched crule vs count(peers) matched global_filters
         - count(uri) matched crule vs count(uri) matched global_filters
        OVERALL STATS :
         - count(id) matched crule
         - count(uri) matched crule'''
        stats = {}
        facet = { "facet_results" : {"terms": { "field": '', "size" : self.es_max_size} }}
        # gather crule vs orule stats
        for x in ['ip', 'uri']:
            facet['facet_results']['terms']['field'] = x
            # crule stats
            esq = self.tpl2esq(crule)
            esq['facets'] = facet
            res = self.search(esq)
            stats['rule_'+x+'_count'] = res['facets']['facet_results']['total']
            # orule stats
            esq = self.tpl2esq(orule)
            esq['facets'] = facet
            res = self.search(esq)
            stats['template_'+x+'_count'] = res['facets']['facet_results']['total']
            # global filters stats
            esq = self.tpl2esq(self.cfg["global_filters"])
            esq['facets'] = facet
            res = self.search(esq)
            stats['global_'+x+'_count'] = res['facets']['facet_results']['total']
        stats['ip_ratio_template'] = (float(stats['rule_ip_count']) / stats['template_ip_count']) * 100.0
        stats['uri_ratio_template'] = (float(stats['rule_uri_count']) / stats['template_uri_count']) * 100.0
        stats['ip_ratio_global'] = (float(stats['rule_ip_count']) / stats['global_ip_count']) * 100.0
        return stats
