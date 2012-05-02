from ConfigParser import ConfigParser
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor, threads
from ordereddict import OrderedDict # don't lose compatibility with python < 2.7

import MySQLdb
import MySQLConnector
import pprint
import re
import getopt
import sys
import datetime
import time
import cgi


glob_allow=True
glob_rules_file="/etc/nginx/naxsi_core.rules"
glob_conf_file = ''


class rules_extractor(object):
   def __init__(self, page_hit, rules_hit, rules_file, conf_file='naxsi-ui.conf'):
      self.db = MySQLConnector.MySQLConnector(glob_conf_file).connect()
      self.cursor = self.db.cursor(MySQLdb.cursors.DictCursor)
      self.rules_list = []
      self.final_rules = []
      self.base_rules = []
      self.page_hit = page_hit
      self.rules_hit = rules_hit
      self.core_msg = {}
      self.extract_core(glob_rules_file)
   def extract_core(self, rules_file):
      try:
         fd = open(glob_rules_file, 'r')
         for i in fd:
            if i.startswith('MainRule'):
               pos = i.find('id:')
               pos_msg = i.find('msg:')
               self.core_msg[i[pos + 3:i[pos + 3].find(';') - 1]] = i[pos_msg + 4:][:i[pos_msg + 4:].find('"')]
         fd.close()
      except:
         pass

   def gen_basic_rules(self,url=None, srcip=None, dsthost=None,
                rule_id=None, exception_md5=None,
                exception_id=None):
      tmp_rules = []
      self.cursor.execute("""select exception.exception_id as id, exception.md5 as md5, exception.url as url, exception.count as count, srcpeer.peer_ip as src, count(distinct srcpeer.peer_ip) as cnt_peer, dstpeer.peer_host as dst, GROUP_CONCAT(distinct "mz:", match_zone.rule_id, ":", "$", match_zone.zone, "_VAR:", match_zone.arg_name)  as match_zones from exception LEFT JOIN  (peer as srcpeer, peer as dstpeer, connections, match_zone)  on (connections.src_peer_id = srcpeer.peer_id and  connections.dst_peer_id = dstpeer.peer_id and  connections.exception_id = exception.exception_id and  match_zone.exception_id = exception.exception_id) GROUP BY id;""")
      data = self.cursor.fetchall()
      for row in data:
         if (url is not None and not re.search(url, row.get("url", ""))):
            continue
         if (srcip is not None and not re.search(srcip, row.get("src", ""))):
            continue
         if (dsthost is not None and not re.search(dsthost, row.get("dst", ""))):
            continue
         if (exception_md5 is not None and not re.search(exception_md5, row.get("md5", ""))):
            continue
         tmp_rules.append(row)
      for i in tmp_rules:
         if i['match_zones'] is None:
            continue
         for j in i['match_zones'].split(','):
            if len(j.split(':')) < 2:
               continue
            da_dict = {}
            da_dict['url'] = i['url']
            da_dict['arg'] = ':'.join(j.split(':')[2:])            
            # fix exception of URL
            da_dict['arg'] = da_dict['arg'].replace("$URL_VAR:", "URL")
            da_dict['id'] = j.split(':')[1]
            da_dict['count'] = i['count']
            da_dict['cnt_peer'] = i['cnt_peer']
            if da_dict not in self.rules_list:
               self.rules_list.append(da_dict)
      self.base_rules = self.rules_list[:]

   def opti_rules_back(self):
      lr = len(self.rules_list)
      i = 0
      while i < lr:
         matching = []
         if (len(self.rules_list[i]['arg'].split(':')) > 1):
            arg_type, arg_name = tuple(self.rules_list[i]['arg'].split(':'))
         else:
            # Rules targeting URL zone
            if self.rules_list[i]['arg'] == "URL":
               arg_name = ""
               arg_type = "URL"
            # Internal rules have small IDs
            elif self.rules_list[i]['id'] < 10:
               arg_name = ""
               arg_type = ""
         id = self.rules_list[i]['id']
         url = self.rules_list[i]['url']
         matching = filter(lambda l: (l['arg'] == arg_type + ':' + arg_name) and id == l['id'] , self.rules_list)
         if len(matching) >= self.page_hit:
            #whitelist the ids on every url with arg_name and arg_type -> BasicRule wl:id "mz:argtype:argname"
            self.final_rules.append({'url': None, 'id': id, 'arg': arg_type + ':' + arg_name})
            for bla in matching:
               self.rules_list.remove(bla)
            lr -= len(matching)
            i = 0
            print "*) "+str(len(matching))+" hits for same mz:"+arg_type+':'+arg_name+" and id:"+str(id)
            print "removed "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list))
            continue
         matching = filter(lambda l: url == l['url'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
         if len(matching) >= self.rules_hit:
            #whitelist all id on url with arg_name and arg_type -> BasicRule wl:0 "mz:$url:xxx|argtype:argname"
            self.final_rules.append({'url': url, 'id': str(0), 'arg': arg_type + ':' + arg_name})
            print "about to del "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list))
            for bla in matching:
               self.rules_list.remove(bla)
            lr -= len(matching)
            i = 0
            print "*) "+str(len(matching))+" hits for same mz:"+str(url)+'|'+str(arg_type)+':'+str(arg_name)+" and id:"+str(id)
            print "removed "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list))
            print " current LR:"+str(lr)
            continue
         i += 1
      if self.rules_list == self.final_rules:
         return self.base_rules, self.final_rules
      #append rules that cant be optimized
      self.final_rules += self.rules_list
      #remove duplicate
      tmp_list = []
      for i in self.final_rules:
         if i not in tmp_list:
            tmp_list.append(i)
      self.final_rules = tmp_list
     #try to reoptimize
      self.rules_list = self.final_rules
      self.opti_rules_back()
      return self.base_rules, self.final_rules
            
   def write_rules(self, filename = '/tmp/naxsi_wl.rules'):
      try:
         fd = open(filename, 'w')
      except:
         print 'Cant open rules file !'
         return
      r = '########### Rules Before Optimisation ##################\n'
      pprint.pprint(self.base_rules)
      for i in self.base_rules:
         r += '#BasicRule wl' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
      r += '########### End Of Rules Before Optimisation ###########\n'
      fd.write(r)
      print r
      r = ''
      if not len(self.final_rules):
         for i in self.rules_list:
            r += 'BasicRule wl:' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
         print r.rstrip()
         fd.write(r)
      else:
         for i in self.final_rules:
            r += 'BasicRule wl:' + i['id'] + ' "mz:'
            if i['url'] is not None:
               r += '$URL:' + i['url'] + '|'
            r += i['arg'] + '";\n'
         fd.write(r)
         print r.rstrip()
      fd.close()
      
   def generate_stats(self):
      stats = ""
      self.cursor.execute("select count(distinct md5) as uniq_exception from exception")
      uniq_ex = self.cursor.fetchall()[0]['uniq_exception']
      self.cursor.execute("select count(distinct peer_ip) as uniq_peer from peer where peer_ip is not NULL")
      uniq_peer = self.cursor.fetchall()[0]['uniq_peer']
      self.cursor.execute("select count(distinct peer_ip) as uniq_peer_mon from http_monitor where peer_ip is not NULL")
      uniq_peer_mon = self.cursor.fetchall()[0]['uniq_peer_mon']
      self.cursor.execute("select count(distinct md5) as uniq_exception_mon from http_monitor where md5 is not NULL")
      uniq_exception = self.cursor.fetchall()[0]['uniq_exception_mon']
      return "<ul><li>There is currently %s unique exceptions.</li></ul><ul><li>There is currently %s different peers that triggered rules.</li></ul><ul><li>There is currently %s peers being monitored</li></ul><ul><li>There is currently %s exceptions being monitored</li></ul>" % (uniq_ex, uniq_peer, uniq_peer_mon, uniq_exception)

               

class InterceptHandler(http.Request):   
   def create_js_array(self, res):
      array = '['
      for i in res:
         date_begin = str(i).split('-')
         date_begin[1] = str(int(date_begin[1]) - 1)
         date_begin = ','.join(date_begin)
         array += '[Date.UTC(' + date_begin  + '),' + str(res[i]) + '],'
      if array != '[':
         array = array[:-1] + ']'
      else:
         array += ']'
      return array

   def build_dict(self, res):
      d = OrderedDict()
      for i in res:
         if i['d'] not in d.keys():
            d[i['d']] = i['ex']
      return d


   def build_js_array(self, id_beg = None, id_end = None):
      if id_beg is None or id_end is None:
         self.ex.cursor.execute('select date(date) as d, count(exception_id) as ex from connections group by date(date)')
      else:
         self.ex.cursor.execute('select date(date) as d, count(co.exception_id) as ex from connections as co join match_zone as m on (co.match_id = m.match_id) where m.rule_id >= %s and m.rule_id <= %s group by date(date);', (str(id_beg), str(id_end)))
      count = self.ex.cursor.fetchall()      
      mydict = self.build_dict(count)
      total_hit = 0
      for i in count:
         total_hit += i['ex']
      myarray = self.create_js_array(mydict)
      return myarray, total_hit

   def handle_request(self):
      self.ex = rules_extractor(0,0, None)

      if self.path == '/get_rules':
         self.setHeader('content-type', 'text/plain')
         ex = rules_extractor(int(self.args.get('page_hit', ['10'])[0]), 
                              int(self.args.get('rules_hit', ['10'])[0]), 
                              glob_rules_file)
         ex.gen_basic_rules()
         base_rules, opti_rules = ex.opti_rules_back()
         r = '########### Rules Before Optimisation ##################\n'

         for i in base_rules:
            r += '#%s hits on rule %s (%s) on url %s from %s different peers\n' % (i['count'], i['id'], 
                                                                                   ex.core_msg.get(i['id'], 
                                                                                                   'Unknown id. Check the path to the core rules file and/or the content.'), 
                                                                                   i['url'], i['cnt_peer'])
            r += '#BasicRule wl:' + i['id'] + ' "mz:$URL:' + i['url'] 
            if '|NAME' in i['arg']:
               i['arg'] = i['arg'].split('|')[0] + '_VAR|NAME'
            if i['arg'] is not None and len(i['arg']) > 0:
               r += '|' + i['arg']
            r +=  '";\n'
         r += '########### End Of Rules Before Optimisation ###########\n'

         for i in opti_rules:
            r += 'BasicRule wl:' + i['id'] + ' "mz:'
            if i['url'] is not None and len(i['url']) > 0:
               r += '$URL:' + i['url']
            if i['arg'] is not None and len(i['arg']) > 0:
               if i['url'] is not None and len(i['url']):
                  r += '|'+i['arg']
               else:
                  r += i['arg']
            r += '";\n'

         self.write(r)
         self.finish()

      elif self.path == '/':
         fd = open('index.tpl', 'r')
         helpmsg = ''
         for i in fd:
            helpmsg += i
         fd.close()
         helpmsg = helpmsg.replace('__STATS__', self.ex.generate_stats())
         helpmsg = helpmsg.replace('__HOSTNAME__', self.getHeader('Host'))
         self.setHeader('content-type', 'text/html')
         self.write(helpmsg)
         self.finish()

      elif self.path == '/graphs':
         fd = open('graphs.tpl')
         html = ''
         for i in fd:
            html += i
         fd.close()

         array_excep, _ = self.build_js_array()
         sqli_array, sql_count = self.build_js_array(1000, 1099)
         xss_array, xss_count = self.build_js_array(1300, 1399)
         rfi_array, rfi_count = self.build_js_array(1100, 1199)
         upload_array, upload_count = self.build_js_array(1500, 1599)
         dt_array, dt_count = self.build_js_array(1200, 1299)
         evade_array, evade_count = self.build_js_array(1400, 1499)
         intern_array, intern_count = self.build_js_array(0, 10)

         self.ex.cursor.execute('select p.peer_ip as ip, count(distinct exception_id) as c from connections join peer as p on (src_peer_id = p.peer_id) group by p.peer_ip order by count(distinct exception_id) DESC limit 10;')
         top_ten = self.ex.cursor.fetchall()
         top_ten_html = '<table border="1" ><tr><td>IP</td><td>Rules Hits</td></tr>'
         for i in top_ten:
            top_ten_html += '<tr><td>' + cgi.escape(i['ip']) + ' </td><td> ' + str(i['c']) + '</td></tr>'
         top_ten_html += '</table>'

         self.ex.cursor.execute('select distinct url, count(exception_id) as c from exception  group by url order by count(exception_id) DESC limit 10;')
         top_ten_page = self.ex.cursor.fetchall()
         top_ten_page_html = '<table border="1" ><tr><td>URI</td><td>Exceptions count</td></tr>'

         for i in top_ten_page:
            top_ten_page_html += '<tr><td>' + cgi.escape(i['url']) + ' </td><td> ' + str(i['c']) + '</td></tr>'
         top_ten_page_html += '</table>'

         dict_replace = {'__TOPTEN__': top_ten_html, '__TOPTENPAGE__': top_ten_page_html, '__TOTALEXCEP__': array_excep, '__SQLCOUNT__': str(sql_count),  '__XSSCOUNT__': str(xss_count), '__DTCOUNT__': str(dt_count), '__RFICOUNT__': str(rfi_count), '__EVCOUNT__': str(evade_count), '__UPCOUNT__': str(upload_count), '__INTCOUNT__': str(intern_count), '__SQLIEXCEP__': sqli_array, '__XSSEXCEP__': xss_array, '__RFIEXCEP__': rfi_array, '__DTEXCEP__': dt_array, '__UPLOADEXCEP__': upload_array, '__EVADEEXCEP__': evade_array, '__INTERNEXCEP__': intern_array}

         html = reduce(lambda html,(b, c): html.replace(b, c), dict_replace.items(), html)
         self.write(html)
         self.finish()

      else:
         try:
            if self.path.endswith('.js'):
               self.setHeader('content-type', 'text/javascript')
            fd = open(self.path[1:], 'rb')
            for i in fd:
               self.write(i)
            fd.close()
         except IOError, e:
            pass
         self.finish()

   def process(self):
      threads.deferToThread(self.handle_request)

class InterceptProtocol(http.HTTPChannel):
   requestFactory = InterceptHandler
   
class InterceptFactory(http.HTTPFactory):
   protocol = InterceptProtocol
      
def usage():
   print 'Usage : python nx_extract /path/to/conf/file'
   
if __name__  == '__main__':
   if len(sys.argv) != 2:
      usage()
      exit(42)
   glob_conf_file = sys.argv[1]
   fd = open(sys.argv[1], 'r')
   conf = ConfigParser()
   conf.readfp(fd)
   try:
      port = int(conf.get('nx_extract', 'port'))
   except:
      print "No port in conf file ! Using default port (8081)"
      port = 8081
   try:
      glob_rules_file = conf.get('nx_extract', 'rules_path')
   except:
      print "No rules path in conf file ! Using default (/etc/nginx/sec-rules/core.rules)"
   fd.close()
         
   reactor.listenTCP(port, InterceptFactory())
   reactor.run()
