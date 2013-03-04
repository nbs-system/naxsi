import urlparse
import string
import itertools
import datetime
import time
import pprint
import gzip
import glob
import logging
import sys
from select import select
import re


class NxImportFilter():
    """ Used to handle user supplied input filters on data acquisition """
    def __init__(self, filters):
        self.gi = None
        self.res_op = []
        self.kw = {
            "ip" : {"methods" : "=,!=,=~"},
            "date" : {"methods" : "=,!=,=~,>,<,>=,<=",
                      "match_method" : self.date_cmp},
            "server" : {"methods" : "=,!=,=~"},
            "uri" : {"methods" : "=,!=,=~"},
            "zone" : {"methods" : "=,!="},
            "id" : {"methods" : "=,!=,>,<,>=,<=",
                    "match_method" : self.int_cmp},
            "var_name" : {"methods" : "=,!=,=~"},
            "content" : {"methods" : "=,!=,=~"},
            "country" : {"methods" : "=,!="}
            }
        try:
            import GeoIP
            self.gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        except:
            print """Python's GeoIP module is not present.
            'World Map' reports won't work,
            and you can't use per-country filters."""
    # returns an integer less than, equal to or greater than zero
    # if date1 is < date2, date1 == date2 or date1 > date2
    def date_cmp(self, date1, date2):
        d1s = time.strptime(date1, "%Y-%m-%d %H:%M:%S")
        d2s = time.strptime(date2, "%Y-%m-%d %H:%M:%S")
        if date1 > date2:
            return 1
        if date1 == date2:
            return 0
        if date1 < date2:
            return -1
    def int_cmp(self, date1, date2):
        int1 = int(date1)
        int2 = int(date2)
        if int1 > int2:
            return 1
        if int1 == int2:
            return 0
        if int1 < int2:
            return -1
    def word(self, w, res):
        if w not in self.kw.keys():
            return -1
        res.append(w)
        return 1
            
    def check(self, w, res):
        if w not in self.kw[res[-1]]["methods"].split(","):
            print "operator "+w+" not allowed for var "+res[-1]
            return -1
        res.append(w)
        return 2

    def checkval(self, w, res):
        # for checks on date, we allow a specialy trick :
        # lastweek => now() - 7days
        # lastmonth = now() - 1 month
        if res[-2] == "date":
            if w == "lastweek":
                mnow = time.gmtime(time.time() - (60*60*24*7))
                w = time.strftime("%Y-%m-%d %H:%M:%S", mnow)
            if w == "lastmonth":
                mnow = time.gmtime(time.time() - (60*60*24*30))
                w = time.strftime("%Y-%m-%d %H:%M:%S", mnow)
        res.append(w)
        return 3

    def synt(self, w, res):
        if w != "or" and w != "and":
            return -1
        res.append(w)
        return 0

    def filter_build(self, instr):
        words = instr.split(' ')
        res_op = []
        # -1 : err, 0 : var, 1 : check, 2 : syntax (and/or), 3 : value, 4 : in quoted string
        state = 0
        tmp_word = ""
        for w in words:
            # wut, quoted string ?
            # and YES, not \ handling, booh
            if w.startswith("'") or w.startswith('"'):
                tmp_word = w[1:]
                state = 4
                continue
            if state == 0:
                state = self.word(w, res_op)
            elif state == 1:
                state = self.check(w, res_op)
            elif state == 2:
                state = self.checkval(w, res_op)
            elif state == 3:
                state = self.synt(w, res_op)
            elif state == 4:
                if w.endswith("'") or w.endswith('"'):
                    tmp_word = tmp_word + " " + w[:-1]
                    state = self.checkval(tmp_word, res_op)
                else:
                    tmp_word = tmp_word + " " +w
            if state == -1:
                print "Unable to build filter, check you syntax at '"+w+"'"
                return False

        self.res_op = res_op
        return True

    def subfil(self, src, sub):
        if sub[0] not in src:
            print "Unable to filter : key "+sub[0]+" does not exist in dict"
            pprint.pprint(src)
            return False
#        else:
#            print "is in dict "
#            pprint.pprint(src)
        srcval = src[sub[0]]
        filval = sub[2]
        if sub[1] == "=" and srcval == filval:
            return True
        elif sub[1] == "!=" and srcval != filval:
            return True
        elif sub[1] == "=~" and re.match(filval, srcval):
            return True
        elif sub[1].startswith(">") or sub[1].startswith("<"):
            if sub[0] not in self.kw or "match_method" not in self.kw[sub[0]]:
                print "Unable to apply operator </>/<=/>= without method"
                pprint.pprint(self.kw[sub[0]])
                return False
            # if date1 is < date2, date1 == date2 or date1 > date2
            if sub[1] == ">" or sub[1] == ">=":
                if self.kw[sub[0]]["match_method"](srcval, filval) == 1:
                    #print srcval+">="+filval
                    return True
            if sub[1] == "<" or sub[1] == "<=":
                if self.kw[sub[0]]["match_method"](srcval, filval) == -1:
                    #print srcval+"<="+filval
                    return True
            if sub[1] == ">=" or sub[1] == "<=":
                if self.kw[sub[0]]["match_method"](srcval, filval) == 0:
                    return True
            return False
        return False

    def dofilter(self, src):
        filters = self.res_op
        if self.gi is not None:
            src['country'] = self.gi.country_code_by_addr(src['ip'])
        else:
            src['country'] = "??"
        last = False
        ok_fail = False
        while last is False:
            sub = filters[0:3]
            filters = filters[3:]
            if len(filters) == 0:
                last = True
            result = self.subfil(src, sub)
            # Final check
            if last is True:
                # if last keyword was or, we can have a fail on last test
                # and still return true.
                if ok_fail is True:
                    return True
                return result
            # if this test succeed with a OR, we can fail next.
            if result is True and filters[0] == "or":
                return True
            if result is False and filters[0] == "or":
                ok_fail = True
                filters = filters[1:]
                continue
            if result is False and filters[0] == "and":
                return False
            # remove and/or
            filters = filters[1:]
        return True
        
class NxReader():
    """ Feeds the given injector from logfiles """
    def __init__(self, injector, stdin=False, lglob=[], step=50,
                 stdin_timeout=5, date_filters=[["", ""]]):
        self.injector = injector
        self.step = step
        self.files = []
        self.date_filters = date_filters
        self.timeout = stdin_timeout
        self.stdin = False
        if stdin is not False:
            print "Using stdin."
            self.stdin = True
            return
        if len(lglob) > 0:
            for regex in lglob:
                self.files.extend(glob.glob(regex))
        print "List of imported files :"+str(self.files)

    def read_stdin(self):
        rlist, _, _ = select([sys.stdin], [], [], self.timeout)
        success = discard = not_nx = malformed = 0
        if rlist:
            s = sys.stdin.readline()
            if s == '':
                return False
            self.injector.acquire_nxline(s)
            return True
        else:
            return False
    def read_files(self):
        if self.stdin is True:
            ret = ""
            while self.read_stdin() is True:
                pass
            self.injector.commit()
            print "Committing to db ..."
            self.injector.wrapper.StopInsert()
            return 0
        count = 0
        total = 0
        for lfile in self.files:
            success = not_nx = discard = malformed = 0
            print "Importing file "+lfile
            try:
                if lfile.endswith(".gz"):
                    fd = gzip.open(lfile, "rb")
                else:
                    fd = open(lfile, "r")
            except:
                print "Unable to open file : "+lfile
                return 1
            for line in fd:
                ret = self.injector.acquire_nxline(line)
                if ret == 0:
                    success += 1
                    count += 1
                elif ret == 1:
                    discard += 1
                elif ret == 2:
                    not_nx += 1
                elif ret == -1:
                    malformed += 1
                if count == self.step:
                    self.injector.commit()
                    count = 0
            fd.close()
            print "\tSuccessful events :"+str(success)
            print "\tFiltered out events :"+str(discard)
            print "\tNon-naxsi lines :"+str(not_nx)
            print "\tMalformed/incomplete lines "+str(malformed)
            total += success
        if count > 0:
            self.injector.commit()
            print "End of db commit... "
            self.injector.wrapper.StopInsert()
        print "Count (lines) success:"+str(total)
        return 0

class NxInject():
    """ Transforms naxsi error log into dicts """
    # din_fmt and fil_fmt are format of dates from logs and from user-supplied filters
    def __init__(self, wrapper, filters=""):
        self.naxsi_keywords = [" NAXSI_FMT: ", " NAXSI_EXLOG: "]
        self.wrapper = wrapper
        self.dict_buf = []
        self.total_objs = 0
        self.total_commits = 0
        self.filters = filters
        self.filt_engine = None
        
        if self.filters is not None:
            self.filt_engine = NxImportFilter(self.filters)
            if self.filt_engine.filter_build(self.filters) is False:
                print "Unable to create filter, abort."
                sys.exit(-1)
    def demult_event(self, event):
        demult = []
        
        entry = {}
        if not event.has_key('uri'):
            entry['uri'] = ''
        else:
            entry['uri'] = event['uri']
        if not event.has_key('server'):
            entry['server'] = ''
        else:
            entry['server'] = event['server']
        if not event.has_key('content'):
            entry['content'] = ''
        else:
            entry['content'] = event['content']
        if not event.has_key('ip'):
            entry['ip'] = ''
        else:
            entry['ip'] = event['ip']
        if not event.has_key('date'):
            entry['date'] = ''
        else:
            entry['date'] = event['date']
        entry['var_name'] = ''
#        pprint.pprint(entry)
        # NAXSI_EXLOG lines only have one triple (zone,id,var_name), but has non-empty content
        if 'zone' in event.keys():
            if 'var_name' in event.keys():
                entry['var_name'] = event['var_name']
            entry['zone'] = event['zone']
            entry['id'] = event['id']
            demult.append(entry)
            return demult
        
        # NAXSI_FMT can have many (zone,id,var_name), but does not have content
        # we iterate over triples.
        elif 'zone0' in event.keys():
            ref = entry
            commit = True
            for i in itertools.count():
                entry = ref
                zn = ''
                vn = ''
                rn = ''
                if 'var_name' + str(i) in event.keys():
                    entry['var_name'] = event['var_name' + str(i)]
                if 'zone' + str(i) in event.keys():
                    entry['zone']  = event['zone' + str(i)]
                else:
                    commit = False
                    break
                if 'id' + str(i) in event.keys():
                    entry['id'] = event['id' + str(i)]
                else:
                    commit = False
                    break
                if commit is True:
                    demult.append(entry)
                else:
                    print "Malformed/incomplete event :"
                    pprint.pprint(event)
                    return demult
            return demult
        else:
            print "Malformed/incomplete event"
            pprint.pprint(event)
            return demult
    def commit(self):
        """Process dicts of dict (yes) and push them to DB """
        self.total_objs += len(self.dict_buf)
        count = 0
        for entry in self.dict_buf:
            url_id = self.wrapper.insert(url = entry['uri'], table='urls')()
            # NAXSI_EXLOG lines only have one triple (zone,id,var_name), but has non-empty content
            if 'content' in entry.keys():
                count += 1
                exception_id = self.wrapper.insert(zone=entry['zone'], var_name=entry['var_name'], 
                                                   rule_id=entry['id'], content=entry['content'], table='exceptions')()
                self.wrapper.insert(peer_ip=entry['ip'], host = entry['server'], url_id=str(url_id), id_exception=str(exception_id),
                                    date=str(entry['date']), table = 'connections')()#[1].force_commit()
            # NAXSI_FMT can have many (zone,id,var_name), but does not have content
            # we iterate over triples.
            else:
                count += 1
                exception_id = self.wrapper.insert(zone = entry['zone'], var_name = entry['var_name'], rule_id = entry['id'], content = '', table = 'exceptions')()
                self.wrapper.insert(peer_ip=entry['ip'], host = entry['server'], url_id=str(url_id), id_exception=str(exception_id),
                                    date=str(entry['date']), table = 'connections')()
        self.total_commits += count
        # Real clearing of dict.
        del self.dict_buf[0:len(self.dict_buf)]
    def exception_to_dict(self, line):
        """Parses a naxsi exception to a dict, 
        1 on error, 0 on success"""
        odict = urlparse.parse_qs(line)
        for x in odict.keys():
            odict[x][0] = odict[x][0].replace('\n', "\\n")
            odict[x][0] = odict[x][0].replace('\r', "\\r")
            odict[x] = odict[x][0]
        # check for incomplete/truncated lines
        if 'zone0' in odict.keys():
            for i in itertools.count():
                is_z = is_id = False
                if 'zone' + str(i) in odict.keys():
                    is_z = True
                if 'id' + str(i) in odict.keys():
                    is_id = True
                if is_z is True and is_id is True:
                    continue
                if is_z is False and is_id is False:
                    break
#                if is_z is True:
                try:
                    del (odict['zone' + str(i)])
                #if is_id is True:
                    del (odict['id' + str(i)])
                    del (odict['var_name' + str(i)])
                except:
                    pass
                break
                    
        return odict
    def date_unify(self, date):
        idx = 0
        res = ""
#        print "date=>"+date
#Jan  8 16:48:36 
        ref_format = "%Y-%m-%d %H:%M:%S"
        supported_formats = [
            "%b  %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S+",
            ]
        while date[idx] == " " or date[idx] == "\t":
            idx += 1
        success = 0
        for date_format in supported_formats:
            nb_sp = date_format.count(" ")
            clean_date = string.join(date.split(" ")[:nb_sp+1], " ")
            try:
                x = time.strptime(clean_date, date_format)
                z = time.strftime(ref_format, x)
                success = 1
                break
            except:
                pass
        if success == 0:
            print "Unable to parse date format :"+date
            sys.exit(-1)
        return z
    # can return : 
    # 0 : ok
    # 1 : ok, but discarded by filters
    # -1 : incomplete/malformed line 
    # 2 : not naxsi line
    def acquire_nxline(self, line, date_format='%Y/%m/%d %H:%M:%S',
                       sod_marker=[' [error] ', ' [debug] '], eod_marker=[', client: ', '']):
        line = line.rstrip('\n')
        for mark in sod_marker:
            date_end = line.find(mark)
            if date_end != -1:
                break
        for mark in eod_marker:
            if mark == '':
                data_end = len(line)
                break
            data_end = line.find(mark)
            if data_end != -1:
                break
        if date_end == -1 or data_end == 1:
            return -1
        date = self.date_unify(line[:date_end])
#        try:
#        time.strptime(date.replace("-", "/"), date_format)
 #       except:
  #          print "Unable to parse date '"+date+"'"
            
        chunk = line[date_end:data_end]
        md = None
        for word in self.naxsi_keywords:
            idx = chunk.find(word)
            if (idx != -1):
                md = self.exception_to_dict(chunk[idx+len(word):])
                if md is None:
                    return -1
                md['date'] = date
                break
        if md is None:
            return 2
        # if input filters on country were used, forced geoip XXX
        for entry in self.demult_event(md):
            if self.filt_engine is None or self.filt_engine.dofilter(entry) is True:
                self.dict_buf.append(entry)
#            print "Appending =>"+str(md)
            return 0
        return 1
