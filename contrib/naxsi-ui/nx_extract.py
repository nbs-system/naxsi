from __future__ import print_function
import MySQLdb
import MySQLConnector
import pprint
import re
import getopt
import sys
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor
import datetime
import time

glob_allow=False
glob_rules_file="/etc/nginx/naxsi_core.rules"

class rules_extractor(object):
   def __init__(self, page_hit, rules_hit, rules_file):
      self.db = MySQLConnector.MySQLConnector().connect()
      self.cursor = self.db.cursor(MySQLdb.cursors.DictCursor)
      self.rules_list = []
      self.final_rules = []
      self.base_rules = []
      self.page_hit = page_hit
      self.rules_hit = rules_hit
      self.core_msg = {}
      if glob_allow is True and rules_file is not None:
         print("glob allow from"+rules_file)
         self.extract_core(rules_file)
      else:
         if glob_rules_file is not None:
            self.extract_core(glob_rules_file)
   def extract_core(self, rules_file):
      try:
         fd = open(rules_file, 'r')
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
            print("*) "+str(len(matching))+" hits for same mz:"+arg_type+':'+arg_name+" and id:"+str(id))
            print("removed "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list)))
            continue
         matching = filter(lambda l: url == l['url'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
         if len(matching) >= self.rules_hit:
            #whitelist all id on url with arg_name and arg_type -> BasicRule wl:0 "mz:$url:xxx|argtype:argname"
            self.final_rules.append({'url': url, 'id': str(0), 'arg': arg_type + ':' + arg_name})
            print("about to del "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list)))
            for bla in matching:
               self.rules_list.remove(bla)
            lr -= len(matching)
            i = 0
            print("*) "+str(len(matching))+" hits for same mz:"+str(url)+'|'+str(arg_type)+':'+str(arg_name)+" and id:"+str(id))
            print("removed "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list)))
            print(" current LR:"+str(lr))
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
      
   def opti_rules(self):
      lr = len(self.rules_list)
      i = 0
      while i < lr:
         matching = []
         if (self.rules_list[i]['arg'].split(':')[0] != "URL"):
            arg_type, arg_name = tuple(self.rules_list[i]['arg'].split(':'))
         else:
            arg_name = ""
            arg_type = "URL"
         id = self.rules_list[i]['id']
         url = self.rules_list[i]['url']
         matching = filter(lambda l: id == l['id'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
         if len(matching) >= self.page_hit:
            #whitelist the ids on every url with arg_name and arg_type -> BasicRule wl:id "mz:argtype:argname"
            self.final_rules.append({'url': None, 'id': id, 'arg': arg_type + ':' + arg_name})
            for bla in matching:
               self.rules_list.remove(bla)
            lr -= len(matching)
            i = -1
#         else:
         matching = filter(lambda l: url == l['url'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
         if len(matching) >= self.rules_hit:
            #whitelist all id on url with arg_name and arg_type -> BasicRule wl:0 "mz:argtype:argname"
            self.final_rules.append({'url': url, 'id': str(0), 'arg': arg_type + ':' + arg_name})
            for bla in matching:
               self.rules_list.remove(bla)
            lr -= len(matching)
            i = -1
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
      self.opti_rules()
      return self.base_rules, self.final_rules
      
   def write_rules(self, filename = '/tmp/naxsi_wl.rules'):
      try:
         fd = open(filename, 'w')
      except:
         print('Cant open rules file !')
         return
      r = '########### Rules Before Optimisation ##################\n'
      pprint.pprint(self.base_rules)
      for i in self.base_rules:
         r += '#BasicRule wl' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
      r += '########### End Of Rules Before Optimisation ###########\n'
      fd.write(r)
      print(r)
      r = ''
      if not len(self.final_rules):
         for i in self.rules_list:
            r += 'BasicRule wl:' + i['id'] + ' "mz:$URL:' + i['url'] + '|' + i['arg'] + '";\n'
         print(r.rstrip())
         fd.write(r)
      else:
         for i in self.final_rules:
            r += 'BasicRule wl:' + i['id'] + ' "mz:'
            if i['url'] is not None:
               r += '$URL:' + i['url'] + '|'
            r += i['arg'] + '";\n'
         fd.write(r)
         print(r.rstrip())
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

   def get_oldest_hit(self, limit = 60):
      self.cursor.execute("select date from connections order by date ASC LIMIT 1")
      return self.cursor.fetchall()[0]['date']

   def get_excep_per_day(self):
      self.cursor.execute('select DATE(date) as d,count(distinct exception_id) as c from connections group by DATE(date);')
      return self.cursor.fetchall()
               

class InterceptHandler(http.Request):
   def process(self):
      ex = rules_extractor(0,0, None)

      if self.path == '/get_rules':
         self.setHeader('content-type', 'text/plain')         
         ex = rules_extractor(int(self.args.get('page_hit', ['10'])[0]), 
                              int(self.args.get('rules_hit', ['10'])[0]), 
                              self.args.get('rules_file', [None])[0])
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

      elif self.path == '/':
         fd = open('help.tpl', 'r')
         helpmsg = ''
         for i in fd:
            helpmsg += i
         fd.close()
         helpmsg = helpmsg.replace('__STATS__', ex.generate_stats())
         helpmsg = helpmsg.replace('__HOSTNAME__', self.getHeader('Host'))
         self.setHeader('content-type', 'text/html')
         self.write(helpmsg)

      elif self.path == '/graphs':
         fd = open('graphs.tpl')
         html = ''
         for i in fd:
            html += i
         fd.close()
         excep = ex.get_excep_per_day()
         array_excep = '['
         for i in excep:
            date_begin = str(i['d']).split('-')
            date_begin[1] = str(int(date_begin[1]) - 1)
            date_begin = ','.join(date_begin)
            array_excep += '[Date.UTC(' + date_begin  + '),' + str(i['c']) + '],'
         array_excep = array_excep[:-1] + ']'
         ex.cursor.execute('select (select count(distinct rule_id) as c from match_zone where rule_id >= 1000 and rule_id <= 1099) as sql_count, (select count(distinct rule_id) as c from match_zone where rule_id >= 1300 and rule_id <= 1399) as xss_count, (select count(distinct rule_id) as c from match_zone where rule_id >= 1100 and rule_id <= 1199) as rfi_count, (select count(distinct rule_id) as c from match_zone where rule_id >= 1200 and rule_id <= 1299) as dt_count, (select count(distinct rule_id) as c from match_zone where rule_id >= 1400 and rule_id <= 1499) as evade_count, (select count(distinct rule_id) as c from match_zone where rule_id >= 1500 and rule_id <= 1599) as upload_count, (select count(distinct rule_id) as c from match_zone where rule_id >= 0 and rule_id <= 10) as intern_count;')
         count_dict = ex.cursor.fetchall()[0]
         ex.cursor.execute('select p.peer_ip as ip, count(distinct exception_id) as c from connections join peer as p on (src_peer_id = p.peer_id) group by p.peer_ip order by count(distinct exception_id) DESC limit 10;')
         top_ten = ex.cursor.fetchall()
         top_ten_html = '<table border="1" ><tr><td>IP</td><td>Rules Hits</td></tr>'
         for i in top_ten:
            top_ten_html += '<tr><td>' + i['ip'] + ' </td><td> ' + str(i['c']) + '</td></tr>'
         top_ten_html += '</table>'
         ex.cursor.execute('select distinct url, count(exception_id) as c from exception  group by url order by count(exception_id) DESC limit 10;')
         top_ten_page = ex.cursor.fetchall()
         top_ten_page_html = '<table border="1" ><tr><td>URI</td><td>Exceptions count</td></tr>'
         for i in top_ten_page:
            top_ten_page_html += '<tr><td>' + i['url'] + ' </td><td> ' + str(i['c']) + '</td></tr>'
         top_ten_page_html += '</table>'
         dict_replace = {'__TOPTEN__': top_ten_html, '__TOPTENPAGE__': top_ten_page_html, '__ARRAYEXCEP__': array_excep, '__SQLCOUNT__': str(count_dict['sql_count']),  '__XSSCOUNT__': str(count_dict['xss_count']), '__DTCOUNT__': str(count_dict['dt_count']), '__RFICOUNT__': str(count_dict['rfi_count']), '__EVCOUNT__': str(count_dict['evade_count']), '__UPCOUNT__': str(count_dict['upload_count']), '__INTCOUNT__': str(count_dict['intern_count'])}
         html = reduce(lambda html,(b, c): html.replace(b, c), dict_replace.items(), html)
         self.write(html)

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

class InterceptProtocol(http.HTTPChannel):
   requestFactory = InterceptHandler
   
class InterceptFactory(http.HTTPFactory):
   protocol = InterceptProtocol
      
def usage():
   print('Usage : python nx_extract [-h,--help] [-p|--port portnumber] '
         '[-r|--rules /path/to/naxsi_core.rules] [-a|--allow allow user to specify rules path]')

if __name__  == '__main__':
    try:
       opts, args = getopt.getopt(sys.argv[1:], 'hp:r:a', ['help','port', 'rules', 'allow'])
    except getopt.GetoptError, err:
       print(str(err))
       usage()
       sys.exit(42)    
    port = 8081
    for o, a in opts:
       if o in ('-h', '--help'):
          usage()
          sys.exit(0)
       if o in ('-p', '--port'):
          port = int(a)
       if o in ('-r', '--rules'):
          glob_rules_file = a
       if o in ('-a', '--allow'):
          glob_allow = True
       
    reactor.listenTCP(port, InterceptFactory())
    reactor.run()
