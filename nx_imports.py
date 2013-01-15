import urlparse
import itertools
import datetime
import pprint
import gzip
import glob

class NxReader():
    """ Feeds the given injector from logfiles """
    def __init__(self, injector, stdin=False, lglob=[], step=50):
        self.injector = injector
        self.step = step
        self.files = []
        if stdin is not False:
            print "Using stdin."
            self.stdin = True
            return
        if len(lglob) > 0:
            for regex in lglob:
                self.files.extend(glob.glob(regex))
        print "List of imported files :"+str(self.files)
    def read_files(self):
        count = 0
        for lfile in self.files:
            success = fail = 0
            print "Importing file "+lfile,
            try:
                if lfile.endswith(".gz"):
                    fd = gzip.open(lfile, "rb")
                else:
                    fd = open(lfile, "r")
            except:
                print "Unable to open file : "+lfile
                return 1
            for line in fd:
                count += 1
                if self.injector.acquire_nxline(line) == 0:
                    success += 1
                else:
                    fail += 1
                if count == self.step:
                    self.injector.commit()
                    count = 0
            fd.close()
        self.injector.commit()
        print "Counts : success:"+str(success)+", fail:"+str(fail)
    
class NxInject():
    """ Transforms naxsi error log into dicts """
    def __init__(self, wrapper):
        self.naxsi_keywords = [" NAXSI_FMT: ", " NAXSI_EXLOG: "]
        self.wrapper = wrapper
        self.dict_buf = []
    def commit(self):
        """Process dicts of dict (yes) and push them to DB """
        print "Commiting "+str(len(self.dict_buf))+" items"
        count = 0
        for entry in self.dict_buf:
            if not entry.has_key('uri'):
                entry['uri'] = ''
            if not entry.has_key('server'):
                entry['server'] = ''
            self.wrapper.execute("INSERT INTO urls (url) VALUES (?)", (entry['uri'],))
            url_id = self.wrapper.getLastId()
            if not entry.has_key('content'):
                entry['content'] = ''
            # NAXSI_EXLOG lines only have one triple (zone,id,var_name), but has non-empty content
            if 'zone' in entry.keys():
                count += 1
                if 'var_name' not in entry.keys():
                    entry['var_name'] = ''
                self.wrapper.execute('INSERT INTO exceptions (zone, var_name, rule_id, content) '
                                     'VALUES (?,?,?,?)', (entry['zone'], entry['var_name'], 
                                                          entry['id'], entry['content']))
                exception_id  = self.wrapper.getLastId()
                self.wrapper.execute('INSERT INTO connections (peer_ip, host, url_id, id_exception,date) '
                                     'VALUES (?,?,?,?,?)', (entry['ip'], entry['server'], str(url_id), 
                                                            str(exception_id), str(entry['date'],)))
            # NAXSI_FMT can have many (zone,id,var_name), but does not have content
            # we iterate over triples.
            elif 'zone0' in entry.keys():
                count += 1
                for i in itertools.count():
                    zn = ''
                    vn = ''
                    rn = ''
                    if 'zone' + str(i) in entry.keys():
                        zn  = entry['zone' + str(i)]
                    else:
                        break
                    if 'var_name' + str(i) in entry.keys():
                        vn = entry['var_name' + str(i)]
                    if 'id' + str(i) in entry.keys():
                        rn = entry['id' + str(i)]
                    else:
                        print "Error: No id at pos:"+str(i)+","+str(entry)
                        break
                    self.wrapper.execute('INSERT INTO exceptions (zone, var_name, rule_id, content) VALUES '
                                         '(?,?,?,?)', (zn, vn, rn, ''))
                exception_id  = self.wrapper.getLastId()
                self.wrapper.execute('INSERT INTO connections (peer_ip, host, url_id, id_exception,date) '
                                     'VALUES (?,?,?,?,?)', (entry['ip'], entry['server'], str(url_id), 
                                                            str(exception_id), str(entry['date'])))
        print "Inserted "+str(count)+" entries in DB."
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
        return odict
    # can return : 
    # 0 : ok
    # 1 : incomplete/malformed line 
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
            return 1
        try:
#datetime.datetime.strptime(line[:date_end], date_format)
            date = line[:date_end]
        except ValueError:
            return 1
        chunk = line[date_end:data_end]
        md = None
        for word in self.naxsi_keywords:
            idx = chunk.find(word)
            if (idx != -1):
                md = self.exception_to_dict(chunk[idx+len(word):])
                if md is not None:
                    md['date'] = date
                    break
        if md is None:
            return 1
        self.dict_buf.append(md)
        return 0
