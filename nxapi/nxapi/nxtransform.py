import logging
import json
import copy
import operator
import os
import pprint
import shlex
import datetime
import glob
import sys

from nxtypificator import Typificator

class NxConfig():
    """ Simple configuration loader """
    cfg = {}
    def __init__(self, fname):
        try:
            self.cfg = (json.loads(open(fname).read()))
        except:
            logging.critical("Unable to open/parse configuration file.")
            raise ValueError

class NxRating():
    """ A class that is used to check success criterias of rule.
    attempts jit querying + caching """
    def __init__(self, cfg, es, tr):
        self.tr = tr
        self.cfg = cfg
        self.es = es
        self.esq = {
            'global' : None,
            'template' : None,
            'rule' : None}
        self.stats = {
            'global' : {},
            'template' : {},
            'rule' : {}
            }
        self.global_warnings = cfg["global_warning_rules"]
        self.global_success = cfg["global_success_rules"]
        self.global_deny = cfg["global_deny_rules"]
    def drop(self):
        """ clears all existing stats """
        self.stats['template'] = {}
        self.stats['global'] = {}
        self.stats['rule'] = {}
    def refresh_scope(self, scope, esq):
        """ drops all datas for a named scope """
        if scope not in self.esq.keys():
            print "Unknown scope ?!"+scope
        self.esq[scope] = esq
        self.stats[scope] = {}
    def query_ratio(self, scope, scope_small, score, force_refresh):
        """ wrapper to calculate ratio between two vals, rounded float """
        #print "ratio :"+str(self.get(scope_small, score))+" / "+str( self.get(scope, score))
        ratio =  round( (float(self.get(scope_small, score)) / self.get(scope, score)) * 100.0, 2)
        return ratio
    def get(self, scope, score, scope_small=None, force_refresh=False):
        """ fetch a value from self.stats or query ES """
        #print "#GET:"+scope+"_?"+str(scope_small)+"?_"+score+" = ?"
        if scope not in self.stats.keys():
            #print "unknown scope :"+scope
            return None
        if scope_small is not None:
            return self.query_ratio(scope, scope_small, score, force_refresh)
        elif score in self.stats[scope].keys() and force_refresh is False:
            return self.stats[scope][score]
        else:
            if score is not 'total':
                self.stats[scope][score] = self.tr.fetch_uniques(self.esq[scope], score)['total']
            else:
                res = self.tr.search(self.esq[scope])
                self.stats[scope][score] = res['hits']['total']
            
            return self.stats[scope][score]
    def check_rule_score(self, tpl):
        """ wrapper to check_score, TOFIX ? """
        return self.check_score(tpl_success=tpl.get('_success', None), 
                                tpl_warnings=tpl.get('_warnings', None), 
                                tpl_deny=tpl.get('_deny', None))
    def check_score(self, tpl_success=None, tpl_warnings=None, tpl_deny=None):
#        pprint.pprint(self.stats)
        debug = False
        success = []
        warning = []
        deny = False
        failed_tests = {"success" : [], "warnings" : []}
        glb_success = self.global_success
        glb_warnings = self.global_warnings
        glb_deny = self.global_deny

        for sdeny in [tpl_deny, glb_deny]:
            if sdeny is None:
                continue
            for k in sdeny.keys():
                res = self.check_rule(k, sdeny[k])
                if res['check'] is True:
#                    print "WE SHOULD DENY THAT"
                    deny = True
                    break
        for scheck in [glb_success, tpl_success]:
            if scheck is None:
                continue
            for k in scheck.keys():
                res = self.check_rule(k, scheck[k])
                if res['check'] is True:
                    if debug is True:
                        print "[SUCCESS] OK, on "+k+" vs "+str(res['curr'])+", check :"+str(scheck[k][0])+" - "+str(scheck[k][1])
                    success.append({'key' : k, 'criteria' : scheck[k], 'curr' : res['curr']})
                else:
                    if debug is True:
                        print "[SUCCESS] KO, on "+k+" vs "+str(res['curr'])+", check :"+str(scheck[k][0])+" - "+str(scheck[k][1])
                    failed_tests["success"].append({'key' : k, 'criteria' : scheck[k], 'curr' : res['curr']})
                
        for fcheck in [glb_warnings, tpl_warnings]:
            if fcheck is None:
                continue
            for k in fcheck.keys():
                res = self.check_rule(k, fcheck[k])
                if res['check'] is True:
                    if debug is True:
                        print "[WARNINGS] TRIGGERED, on "+k+" vs "+str(res['curr'])+", check :"+str(fcheck[k][0])+" - "+str(fcheck[k][1])
                    warning.append({'key' : k, 'criteria' : fcheck[k], 'curr' : res['curr']})
                else:
                    if debug is True:
                        print "[WARNINGS] NOT TRIGGERED, on "+k+" vs "+str(res['curr'])+", check :"+str(fcheck[k][0])+" - "+str(fcheck[k][1])
                    failed_tests["warnings"].append({'key' : k, 'criteria' : fcheck[k], 'curr' : res['curr']})
        x = { 'success' : success,
              'warnings' : warning,
              'failed_tests' : failed_tests,
              'deny' : deny}
        return x
    def check_rule(self, label, check_rule):
        """ check met/failed success/warning criterias
        of a given template vs a set of results """
        check = check_rule[0]
        beat = check_rule[1]
        if label.find("var_name") != -1:
            label = label.replace("var_name", "var-name")
        items = label.split('_')
        for x in range(len(items)):
            items[x] = items[x].replace("var-name", "var_name")
            
        if len(items) == 2:
            scope = items[0]
            score = items[1]
            x = self.get(scope, score)
#            print "scope:"+str(scope)+" score:"+str(score)
            return {'curr' : x, 'check' : check( int(self.get(scope, score)), int(beat))}
        elif len(items) == 4:
            scope = items[0]
            scope_small = items[1]
            score = items[2]
            x = self.get(scope, score, scope_small=scope_small)
            #Xpprint.pprint()
            return {'curr' : x, 'check' : check(int(self.get(scope, score, scope_small=scope_small)), int(beat))}
        else:
            print "cannot understand rule ("+label+"):",
            pprint.pprint(check_rule)
            return { 'curr' : 0, 'check' : False }

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
        self.cfg["global_deny_rules"] = self.normalize_checks(self.cfg["global_deny_rules"])
        self.core_msg = {}
        # by default, es queries will return 1000 results max
        self.es_max_size = self.cfg.get("elastic").get("max_size", 1000)
        print "# size :"+str(self.es_max_size)
        # purely for output coloring
        self.red = u'{0}'
        self.grn = u'{0}'
        self.blu = u'{0}'
        if self.cfg["output"]["colors"] == "true":
            self.red = u"\033[91m{0}\033[0m"
            self.grn = u"\033[92m{0}\033[0m"
            self.blu = u"\033[94m{0}\033[0m"
        # Attempt to parse provided core rules file
        self.load_cr_file(self.cfg["naxsi"]["rules_path"])

    def full_auto(self, to_fill_list=None):
        """ Loads all tpl within template_path
        If templates has hit, peers or url(s) ratio > 15%,
        attempts to generate whitelists.
        Only displays the wl that did not raise warnings, ranked by success"""

        # gather total IPs, total URIs, total hit count
        scoring = NxRating(self.cfg, self.es, self)

        strict = True
        if self.cfg.get("naxsi").get("strict", "") == "false":
            strict = False

        scoring.refresh_scope("global", self.cfg["global_filters"])
        if scoring.get("global", "ip") <= 0:
            return []
        output = []
        for sdir in self.cfg["naxsi"]["template_path"]:
            for root, dirs, files in os.walk(sdir):
                for file in files:
                    if file.endswith(".tpl"):
                        output.append("# {0}{1}/{2} ".format(
                            self.grn.format(" template :"),
                            root,
                            file
                        ))
                        template = self.load_tpl_file(root+"/"+file)
                        scoring.refresh_scope('template', self.tpl2esq(template))
                        output.append("Nb of hits : {0}".format(scoring.get('template', 'total')))
                        if scoring.get('template', 'total') > 0:
                            output.append('{0}'.format(self.grn.format("#  template matched, generating all rules.")))
                            whitelists = self.gen_wl(template, rule={})
                            # x add here
                            output.append('{0}'.format(len(whitelists))+" whitelists ...")
                            for genrule in whitelists:
                                scoring.refresh_scope('rule', genrule['rule'])
                                results = scoring.check_rule_score(template)
                                # XX1
                                if (len(results['success']) > len(results['warnings']) and results["deny"] == False) or self.cfg["naxsi"]["strict"] == "false":
                                    # print "?deny "+str(results['deny'])
                                    try:
                                        str_genrule = '{0}'.format(self.grn.format(self.tpl2wl(genrule['rule']).encode('utf-8', 'replace'), template))
                                    except UnicodeDecodeError:
                                        logging.warning('WARNING: Unprocessable string found in the elastic search')
                                    output.append(self.fancy_display(genrule, results, template))
                                    output.append(str_genrule)
                                    if to_fill_list is not None:
                                        genrule.update({'genrule': str_genrule})
                                        to_fill_list.append(genrule)
        return output

    def wl_on_type(self):
        for rule in Typificator(self.es, self.cfg).get_rules():
            print 'BasicRule negative "rx:{0}" "msg:{1}" "mz:${2}_VAR:{3}" "s:BLOCK";'.format(*rule)

    def fancy_display(self, full_wl, scores, template=None):
        output = []
        if template is not None and '_msg' in template.keys():
            output.append("#msg: {0}\n".format(template['_msg']))
        rid = full_wl['rule'].get('id', "0")
        output.append("#Rule ({0}) {1}\n".format(rid, self.core_msg.get(rid, 'Unknown ..')))
        if self.cfg["output"]["verbosity"] >= 4:
            output.append("#total hits {0}\n".format(full_wl['total_hits']))
            for x in ["content", "peers", "uri", "var_name"]:
                if x not in full_wl.keys():
                    continue
                for y in full_wl[x]:
                    output.append("#{0} : {1}\n".format(x, unicode(y).encode("utf-8", 'replace')))
        return ''.join(output)

#        pprint.pprint(scores)
        for x in scores['success']:
            print "# success : "+self.grn.format(str(x['key'])+" is "+str(x['curr']))
        for x in scores['warnings']:
            print "# warnings : "+self.grn.format(str(x['key'])+" is "+str(x['curr']))

        pass
    def expand_tpl_path(self, template):
        """ attempts to convert stuff to valid tpl paths.
        if it starts with / or . it will consider it's a relative/absolute path,
        else, that it's a regex on tpl names. """
        clean_tpls = []
        tpl_files = []
        if template.startswith('/') or template.startswith('.'):
            tpl_files.extend(glob.glob(template))
        else:
            for sdir in self.cfg['naxsi']['template_path']:
                tpl_files.extend(glob.glob(sdir +"/"+template))
        for x in tpl_files:
            if x.endswith(".tpl") and x not in clean_tpls:
                clean_tpls.append(x)
        return clean_tpls

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
        if '_warnings' in template.keys():
            template['_warnings'] = self.normalize_checks(template['_warnings'])
        if '_deny' in template.keys():
            template['_deny'] = self.normalize_checks(template['_deny'])
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
            logging.warning("Unable to open rules file")
    def tpl2esq(self, ob, full=True):
        ''' receives template or a rule, returns a valid 
        ElasticSearch query '''
        qr = { 
            "query" : { "bool" : { "must" : [ ]} },
            "size" : self.es_max_size
            }
        # A hack in case we were inadvertently given an esq
        if 'query' in ob.keys():
            return ob
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
                qr['query']['bool']['must'].append({"match" : { k : ob[k]}})

        qr = self.append_gfilter(qr)
        return qr
    def append_gfilter(self, esq):
        """ append global filters parameters 
        to and existing elasticsearch query """
        for x in self.cfg["global_filters"]:
            if x.startswith('?'):
                x = x[1:]
                if {"regexp" : { x : self.cfg["global_filters"]['?'+x] }} not in esq['query']['bool']['must']:
                    esq['query']['bool']['must'].append({"regexp" : { x : self.cfg["global_filters"]['?'+x] }}) 
            else:
                if {"match" : { x : self.cfg["global_filters"][x] }} not in esq['query']['bool']['must']:
                    esq['query']['bool']['must'].append({"match" : { x : self.cfg["global_filters"][x] }})
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
        # bug #194 - drop everything after the first chunk starting with a '#' (inline comments)
        for x in strings:
            if x.startswith('#'):
                strings = strings[:strings.index(x)]
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
                        if not 'must_not' in esq['query']['bool'].keys():
                            esq['query']['bool']['must_not'] = []
                        esq['query']['bool']['must_not'].append({"match" : { "id" : wl_id}})
                    else:
                        esq['query']['bool']['must'].append({"match" : { "id" : wl_id}})
            if x.startswith("mz:"):
                mz_str = x[3:]
                [res, filters] = self.parse_mz(mz_str, esq)
                if res is False:
                    return [False, "matchzone parsing failed."]
        esq = self.append_gfilter(esq)
        return [True, filters]
    def parse_mz(self, mz_str, esq):
        """ parses a match zone from BasicRule, and updates
        es query accordingly. Removes ^/$ chars from regexp """
        forbidden_rx_chars = "^$"
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
                    tpl.append({"match" : { "zone" : zone}})
                    tpl.append({"match" : { "var_name" : var_name}})
                # *_VAR_X:<regexp>
                elif zone.endswith("_VAR_X"):
                    zone = zone[:-6]
                    if t_name is True:
                        zone += "|NAME"
                    tpl.append({"match" : { "zone" : zone}})
                    #.translate(string.maketrans(chars, newchars))
                    tpl.append({"regexp" : { "var_name" : var_name.translate(None, forbidden_rx_chars)}})
                # URL_X:<regexp>
                elif zone == "URL_X":
                    zone = zone[:-2]
                    tpl.append({"regexp" : { "uri" : var_name.translate(None, forbidden_rx_chars)}})
                # URL:<string>
                elif zone == "URL":
                    tpl.append({"match" : { "uri" : var_name }})
                else:
                    print "huh, what's that ? "+zone

            # |<ZONE>
            else:
                if k not in ["HEADERS", "BODY", "URL", "ARGS", "FILE_EXT"]:
                    return [False, "Unknown zone : '"+k+"'"]
                zone = k
                if t_name is True:
                    zone += "|NAME"
                tpl.append({"match" : {"zone" : zone}})
        # print "RULE :"
        # pprint.pprint(esq)
        return [True, esq]
    def tpl2wl(self, rule, template=None):
        """ transforms a rule/esq
        to a valid BasicRule. """
        tname = False
        zone = ""
        if template is not None and '_statics' in template.keys():
            for x in template['_statics'].keys():
                rule[x] = template['_statics'][x]

        wl = "BasicRule "
        wl += " wl:"+str(rule.get('id', 0)).replace("OR", ",").replace("|", ",").replace(" ", "")

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

        if rule.get('var_name', '') not in  ['', '?'] and zone != "FILE_EXT":
            wl += "$"+zone+"_VAR:"+rule['var_name']
        else:
            wl += zone

        if tname is True:
            wl += "|NAME"

        wl += '";'
        return wl
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
        if self.cfg["elastic"].get("version", None) == "1":
            esq['facets'] =  { "facet_results" : {"terms": { "field": field, "size" : self.es_max_size} }}
        elif self.cfg["elastic"].get("version", None) in ["2", "5"]:
            esq['aggregations'] =  { "agg1" : {"terms": { "field": field, "size" : self.es_max_size} }}
        else:
            print "Unknown / Unspecified ES version in nxapi.json : {0}".format(self.cfg["elastic"].get("version", "#UNDEFINED"))
            sys.exit(1)
            
        res = self.search(esq)

        if self.cfg["elastic"].get("version", None) == "1":
            total = res['facets']['facet_results']['total']
        elif self.cfg["elastic"].get("version", None) in ["2", "5"]:
            total = res['hits']['total']
        else:
            print "Unknown / Unspecified ES version in nxapi.json : {0}".format(self.cfg["elastic"].get("version", "#UNDEFINED"))
            sys.exit(1)

        count = 0
        ret = []
        if self.cfg["elastic"].get("version", None) == "1":
            for x in res['facets']['facet_results']['terms']:
                ret.append('{0} {1}% (total: {2}/{3})'.format(x['term'], round((float(x['count']) / total) * 100, 2), x['count'], total))
                count += 1
                if count > limit:
                    break
        elif self.cfg["elastic"].get("version", None) in ["2", "5"]:
            for x in res['aggregations']['agg1']['buckets']:
                ret.append('{0} {1}% (total: {2}/{3})'.format(x['key'], round((float(x['doc_count']) / total) * 100, 2), x['doc_count'], total))
                count += 1
                if count > limit:
                    break
        else:
            print "Unknown / Unspecified ES version in nxapi.json : {0}".format(self.cfg["elastic"].get("version", "#UNDEFINED"))
            sys.exit(1)
        return ret

    def fetch_uniques(self, rule, key):
        """ shortcut function to gather unique
        values and their associated match count """
        uniques = []
        esq = self.tpl2esq(rule)
        #
        if self.cfg["elastic"].get("version", None) == "1":
            esq['facets'] =  { "facet_results" : {"terms": { "field": key, "size" : 50000} }}
        elif self.cfg["elastic"].get("version", None) in ["2", "5"]:
            esq['aggregations'] =  { "agg1" : {"terms": { "field": key, "size" : 50000} }}
        else:
            print "Unknown / Unspecified ES version in nxapi.json : {0}".format(self.cfg["elastic"].get("version", "#UNDEFINED"))
            sys.exit(1)

        res = self.search(esq)
        if self.cfg["elastic"].get("version", None) == "1":
            for x in res['facets']['facet_results']['terms']:
                if x['term'] not in uniques:
                    uniques.append(x['term'])
        elif self.cfg["elastic"].get("version", None) in ["2", "5"]:
            for x in res['aggregations']['agg1']['buckets']:
                if x['key'] not in uniques:
                    uniques.append(x['key'])
        else:
            print "Unknown / Unspecified ES version in nxapi.json : {0}".format(self.cfg["elastic"].get("version", "#UNDEFINED"))
            sys.exit(1)
            
        return { 'list' : uniques, 'total' :  len(uniques) }
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
    def tag_events(self, esq, msg, tag=False):
        """ tag events with msg + tstamp if they match esq """
        count = 0
        total_events = 0
        esq["size"] = "0"
        print "TAG RULE :",
        pprint.pprint(esq)
        x = self.search(esq)
        total_events = int(str(x["hits"]["total"]))
        print str(self.grn.format(total_events)) + " items to be tagged ..."
        size = int(x['hits']['total'])
        if size > 20000:
            size = size / 100
        elif size > 100:
            size = size / 10
        while count < total_events:
            esq["size"] = size
            esq["from"] = 0
            res = self.search(esq)
            # Iterate through matched evts to tag them.
            if int(res['hits']['total']) == 0:
                break
            for item in res['hits']['hits']:
                eid = item['_id']
                body = item['_source']
                cm = item['_source']['comments']
                body['comments'] += ","+msg+":"+str(datetime.datetime.now())
                body['whitelisted'] = "true"
                if tag is True:
                    self.index(body, eid)
                else:
                    print eid+",",
                count += 1
            print "Tagged {0} events out of {1}".format(count, total_events)
            if total_events - count < size:
                size = total_events - count
        print ""
        #--
        if not tag or tag is False:
            return 0
        else:
            return count


    def gen_wl(self, tpl, rule={}):
        """ recursive whitelist generation function,
        returns a list of all possible witelists. """
        retlist = []
        for tpl_key in tpl.keys():
            if tpl_key in rule.keys():
                continue
            if tpl_key[0] in ['_', '?']:
                continue
            if tpl[tpl_key] == '?':
                continue
            rule[tpl_key] = tpl[tpl_key]
        for tpl_key in tpl.keys():
            if tpl_key.startswith('_'):
                continue
            elif tpl_key.startswith('?'):
                if tpl_key[1:] in rule.keys():
                    continue
                unique_vals = self.fetch_uniques(rule, tpl_key[1:])['list']
                for uval in unique_vals:
                    rule[tpl_key[1:]] = uval
                    retlist += self.gen_wl(tpl, copy.copy(rule))
                return retlist
            elif tpl[tpl_key] == '?':
                if tpl_key in rule.keys():
                    continue
                unique_vals = self.fetch_uniques(rule, tpl_key)['list']
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
            peers = []
            uri = []
            var_name = []

            for x in res['hits']['hits']:
                if len(x.get("_source").get("ip", "")) > 0 and x.get("_source").get("ip", "") not in peers:
                    peers.append(x["_source"]["ip"])
                if len(x.get("_source").get("uri", "")) > 0 and x.get("_source").get("uri", "") not in uri:
                    uri.append(x["_source"]["uri"])
                if len(x.get("_source").get("var_name", "")) > 0 and x.get("_source").get("var_name", "") not in var_name:
                    var_name.append(x["_source"]["var_name"])
                if len(x.get("_source").get("content", "")) > 0 and x.get("_source").get("content", "") not in clist:
                    clist.append(x["_source"]["content"])
                    if len(clist) >= 5:
                        break
            retlist.append({'rule' : rule, 'content' : clist[:5], 'total_hits' : res['hits']['total'], 'peers' : peers[:5], 'uri' : uri[:5],
                            'var_name' : var_name[:5]})
            return retlist
        return []
