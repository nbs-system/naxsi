#!/usr/bin/env python

from ConfigParser import ConfigParser
from twisted.web import http
from twisted.internet import protocol
from twisted.internet import reactor, threads
from twisted.web.server import Site
from twisted.web.static import File
from twisted.web.resource import Resource
from twisted.web.error import NoResource
from zope.interface import implements
from twisted.cred.portal import IRealm, Portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse, ICredentialsChecker
from twisted.web.guard import HTTPAuthSessionWrapper, DigestCredentialFactory
from twisted.web.resource import IResource
from twisted.cred import credentials
from ordereddict import OrderedDict # don't lose compatibility with python < 2.7

import SQLWrapper
import pprint
import re
import getopt
import sys
import datetime
import time
import cgi
import os


glob_allow=True
glob_rules_file="/etc/nginx/naxsi_core.rules"
glob_conf_file = ''
glob_username = ''
glob_pass = ''
glob_fileList = []

class rules_extractor(object):
   def __init__(self, page_hit, rules_hit, rules_file, conf_file='naxsi-ui.conf'):
       
       self.wrapper = SQLWrapper.SQLWrapper(glob_conf_file)
       self.wrapper.connect()
       self.wrapper.setRowToDict()
           
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
     self.rules_list = self.wrapper.getWhitelist()
     
     self.base_rules = self.rules_list[:]
#      for i in tmp_rules:
#          if i['match_zones'] is None:
#             continue
#          for j in i['match_zones'].split(','):
#             if len(j.split(':')) < 2:
#                continue
#             da_dict = {}
#             da_dict['url'] = i['url']
#             da_dict['arg'] = ':'.join(j.split(':')[2:])            
#             # fix exception of URL
#             da_dict['arg'] = da_dict['arg'].replace("$URL_VAR:", "URL")
#             da_dict['id'] = j.split(':')[1]
#             da_dict['count'] = i['count']
# #            da_dict['cnt_peer'] = i['cnt_peer']
#             if da_dict not in self.rules_list:
#                self.rules_list.append(da_dict)
#      self.base_rules = self.rules_list[:]

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


   def get_partial_match_dict(self, d, to_find):
      for i, current_dict in enumerate(d):
        if all(key in current_dict and current_dict[key] == val 
                for key, val in to_find.iteritems()):
            return i


   def opti_rules_back(self):
     #   lr = len(self.rules_list)
     #   i = 0
     #   while i < lr:
     #       matching = []
     #       if (len(self.rules_list[i]['arg'].split(':')) > 1):
     #           arg_type, arg_name = tuple(self.rules_list[i]['arg'].split(':'))
     #       else:
     #        # Rules targeting URL zone
     #           if self.rules_list[i]['arg'] == "URL":
     #               arg_name = ""
     #               arg_type = "URL"
     #        # Internal rules have small IDs
     #           elif self.rules_list[i]['id'] < 10:
     #               arg_name = ""
     #               arg_type = ""
     #       id = self.rules_list[i]['id']
     #       url = self.rules_list[i]['url']
     #       matching = filter(lambda l: (l['arg'] == arg_type + ':' + arg_name) and id == l['id'] , self.rules_list)
     #       if len(matching) >= self.page_hit:
     #        #whitelist the ids on every url with arg_name and arg_type -> BasicRule wl:id "mz:argtype:argname"
     #           self.final_rules.append({'url': None, 'id': id, 'arg': arg_type + ':' + arg_name})
     #           for bla in matching:
     #               self.rules_list.remove(bla)
     #           lr -= len(matching)
     #           i = 0
     #           print "*) "+str(len(matching))+" hits for same mz:"+arg_type+':'+arg_name+" and id:"+str(id)
     #           print "removed "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list))
     #           continue
     #       matching = filter(lambda l: url == l['url'] and l['arg'] == arg_type + ':' + arg_name, self.rules_list)
     #       if len(matching) >= self.rules_hit:
     #        #whitelist all id on url with arg_name and arg_type -> BasicRule wl:0 "mz:$url:xxx|argtype:argname"
     #           self.final_rules.append({'url': url, 'id': str(0), 'arg': arg_type + ':' + arg_name})
     #           print "about to del "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list))
     #           for bla in matching:
     #               self.rules_list.remove(bla)
     #           lr -= len(matching)
     #           i = 0
     #           print "*) "+str(len(matching))+" hits for same mz:"+str(url)+'|'+str(arg_type)+':'+str(arg_name)+" and id:"+str(id)
     #           print "removed "+str(len(matching))+" items from biglist, now :"+str(len(self.rules_list))
     #           print " current LR:"+str(lr)
     #           continue
     #       i += 1
     #   if self.rules_list == self.final_rules:
     #       return self.base_rules, self.final_rules
     #  #append rules that cant be optimized
     #   self.final_rules += self.rules_list
     #  #remove duplicate
     #   tmp_list = []
     #   for i in self.final_rules:
     #       if i not in tmp_list:
     #           tmp_list.append(i)
     #   self.final_rules = tmp_list
     # #try to reoptimize
     #   self.rules_list = self.final_rules
       #   self.opti_rules_back()
       return self.base_rules, self.final_rules


#       url_dict = {}
      
#       # if more than 10 rules are triggered on the same url and the same args -> BasicRule wl:0 "mz:$URL:urlname|argtype:argname"
#       for pos, content in enumerate(self.rules_list):
#          #we build a dict with url as key and a list of tuple as value ([(argtype:name, rule_id), ....])
#          key  = content['url']
#          if not url_dict.has_key(key):
#             url_dict[key] = []
#          url_dict[key].append((self.rules_list[pos]['arg'], self.rules_list[pos]['id']))

#       for url in url_dict:
#          d = self.transform_to_dict(url_dict[url])
#          for arg in d:
#             if len(d[arg]) >= self.rules_hit:
#                #we will whitelist all id on this url and this arg
#                self.final_rules.append({'id': '0', 'url': url, 'arg': arg})
#                #remove the match in base_rule
#                for id in d[arg]:
#                   self.base_rules.pop(self.get_partial_match_dict(self.base_rules, {'arg': arg, 'url': url, 'id': id}))

#       #if more than 10 pages trigerred the same exception on the same arg -> BasicRule wl:ruleid "mz:argtype:argname"               
#       id_dict = {}
#       for pos, content in enumerate(self.rules_list):
#          #we build a dict with url as key and a list of tuple as value ([(argtype:name, rule_id), ....])
#          key  = content['id']
#          if not id_dict.has_key(key):
#             id_dict[key] = []
#          id_dict[key].append((self.rules_list[pos]['arg'], self.rules_list[pos]['url']))


#       for id in id_dict:
#           print id_dict[id]
#           d = self.transform_to_dict(id_dict[id])
#           for url in d:
#              if len(d[url]) >= self.rules_hit:
# #               we will whitelist all id on this url and this arg
#                  self.final_rules.append({'id': id, 'url': url, 'arg': arg})
#              remove the match in base_rule
#                 for id in d[url]:
#                     print arg, url, id
#                     self.base_rules.pop(self.get_partial_match_dict(self.base_rules, {'arg': arg, 'url': url, 'id': id}))


#      pprint.pprint(url_dict)
#      pprint.pprint(self.base_rules)
#      print 'base_rule : ', len(self.base_rules), ' rules_list ', len(self.rules_list)
      
#      self.final_rules.extend(self.base_rules)
#      return self.base_rules, self.final_rules
                  
   def generate_stats(self):
      stats = ""
      self.wrapper.execute("select count(distinct exception_id) as uniq_exception from exceptions")
      uniq_ex = self.wrapper.getResults()[0]['uniq_exception']
      self.wrapper.execute("select count(distinct peer_ip) as uniq_peer from connections")
      uniq_peer = self.wrapper.getResults()[0]['uniq_peer']
      return "<ul><li>There is currently %s unique exceptions.</li></ul><ul><li>There is currently %s different peers that triggered rules.</li></ul>" % (uniq_ex, uniq_peer)


class NaxsiUI(Resource):
   def __init__(self):
      Resource.__init__(self)
      #twisted will handle static content for me
      self.putChild('bootstrap', File('./bootstrap'))
      self.putChild('js', File('./js'))
      #make the correspondance between the path and the object to call
      self.page_handler = {'/' : Index, '/graphs': GraphView, '/get_rules': GenWhitelist}

   def getChild(self, name, request):
      handler = self.page_handler.get(request.path)
      if handler is not None:
         return handler()
      else:
         return NoResource()
         

class Index(Resource):
   def __init__(self):
      Resource.__init__(self)
      self.ex = rules_extractor(0,0, None)

   def render_GET(self, request):
      fd = open('index.tpl', 'r')
      helpmsg = ''
      for i in fd:
         helpmsg += i
      fd.close()
      helpmsg = helpmsg.replace('__STATS__', self.ex.generate_stats())
      helpmsg = helpmsg.replace('__HOSTNAME__', request.getHeader('Host'))
      return helpmsg


class GraphView(Resource):
   isLeaf = True

   def __init__(self):
      Resource.__init__(self)
      self.ex = rules_extractor(0,0, None)


   def render_GET(self, request):

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

      self.ex.wrapper.execute('select peer_ip as ip, count(id_exception) as c from connections group by peer_ip order by count(id_exception) DESC limit 10')
      top_ten = self.ex.wrapper.getResults()
      top_ten_html = '<table class="table table-bordered" border="1" ><thead><tr><th>IP</th><th>Rule Hits</th></tr></thead><tbody>'
      for i in top_ten:
         top_ten_html += '<tr><td>' + cgi.escape(i['ip']) + ' </td><td> ' + str(i['c']) + '</td></tr>'
      top_ten_html += '</tbody></table>'

      top_ten_page_html = ''

      self.ex.wrapper.execute('select distinct u.url as url, count(id_exception) as c from connections  join urls as u on (u.url_id = connections.url_id) group by u.url order by count(id_exception) DESC limit 10;')
      top_ten_page = self.ex.wrapper.getResults()
      top_ten_page_html = '<table class="table table-bordered" border="1" ><thead><tr><th>URI</th><th>Exceptions Count</th></tr></thead><tbody>'
      
      for i in top_ten_page:
          top_ten_page_html += '<tr><td>' + cgi.escape(i['url']).replace('\'', '\\\'') + ' </td><td> ' + str(i['c']) + '</td></tr>'
      top_ten_page_html += '</tbody></table>'

      dict_replace = {'__TOPTEN__': top_ten_html, '__TOPTENPAGE__': top_ten_page_html, '__TOTALEXCEP__': array_excep, '__SQLCOUNT__': str(sql_count),  '__XSSCOUNT__': str(xss_count), '__DTCOUNT__': str(dt_count), '__RFICOUNT__': str(rfi_count), '__EVCOUNT__': str(evade_count), '__UPCOUNT__': str(upload_count), '__INTCOUNT__': str(intern_count), '__SQLIEXCEP__': sqli_array, '__XSSEXCEP__': xss_array, '__RFIEXCEP__': rfi_array, '__DTEXCEP__': dt_array, '__UPLOADEXCEP__': upload_array, '__EVADEEXCEP__': evade_array, '__INTERNEXCEP__': intern_array}

      html = reduce(lambda html,(b, c): html.replace(b, c), dict_replace.items(), html)
      return html

   def create_js_array(self, res):
      array = '['
      for i in res:
          
          d = i.replace('/', '-')
          date_begin = str(d).split('-')
          date_begin[1] = str(int(date_begin[1]) - 1)
          date_begin = ','.join(date_begin)
          array += '[Date.UTC(' + date_begin  + '),' + str(res[i]).replace('/', '-') + '],'
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
         self.ex.wrapper.execute('select substr(date,1,10) as d, count(id_exception) as ex from connections group by substr(date,1,10)')
      else:
          self.ex.wrapper.execute('select substr(date,1, 10) as d, count(id_exception) as ex from connections join exceptions as e on (e.exception_id = id_exception) where e.rule_id >= %s and e.rule_id <= %s group by substr(date, 1, 10)', (str(id_beg), str(id_end)))
      count = self.ex.wrapper.getResults()
      mydict = self.build_dict(count)
      total_hit = 0
      for i in count:
         total_hit += i['ex']
      myarray = self.create_js_array(mydict)
      return myarray, total_hit

class GenWhitelist(Resource):

   def render_GET(self, request):
      request.setHeader('content-type', 'text/plain')
      ex = rules_extractor(int(request.args.get('page_hit', ['10'])[0]), 
                           int(request.args.get('rules_hit', ['10'])[0]), 
                           glob_rules_file)
      ex.gen_basic_rules()
      base_rules, opti_rules = ex.opti_rules_back()
      r = '########### Rules Before Optimisation ##################\n'
      
      for i in base_rules:
#         r += '#%s hits on rule %s (%s) on url %s from ? different peers\n' % (i['count'], i['id'], 
#                                                                                ex.core_msg.get(i['id'], 
#                                                                                                'Unknown id. Check the path to the core rules file and/or the content.'), 
 #                                                                               i['url'])
         r += '#BasicRule wl:' + str(i['rule_id']) + ' "mz:$URL:' + i['url']
         r += '|$' + i['zone'] + '_VAR' + ':' + i['var_name'] + ('|NAME' if '|NAME' in i['zone'] else '')
         # if '|NAME' in i['arg']:
         #     i['arg'] = i['arg'].split('|')[0] + '_VAR:' +  i['arg'].split('|')[1].split(':')[1] + '|NAME'
         # if i['arg'] is not None and len(i['arg']) > 0:
         #    r += '|' + i['arg']
         r +=  '";\n'
      r += '########### End Of Rules Before Optimisation ###########\n'
      return r
      for i in opti_rules:
         r += 'BasicRule wl:' + i['rule_id'] + ' "mz:'
         if i['url'] is not None and len(i['url']) > 0:
            r += '$URL:' + i['url']
         if i['arg'] is not None and len(i['arg']) > 0:
            if i['url'] is not None and len(i['url']):
               r += '|'+i['arg']
            else:
               r += i['arg']
            r += '";\n'      
      return r

class HTTPRealm(object):
   implements(IRealm)

   def requestAvatar(self, avatarID, mind, *interfaces):
      return (IResource, NaxsiUI(), lambda: None)

def daemonize (stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)
    except OSError, e: 
        sys.stderr.write ("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

#    os.chdir("/") 
    os.umask(0) 
    os.setsid() 

    try: 
        pid = os.fork() 
        if pid > 0:
            sys.exit(0)
    except OSError, e: 
        sys.stderr.write ("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    si = open(stdin, 'r')
    so = open(stdout, 'a+')
    se = open(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
         

      
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

   try:
      glob_user = conf.get('nx_extract', 'username')
   except:
      print 'No username for web access ! Nx_extract will exit.'
      exit(-1)

   try:
      glob_pass = conf.get('nx_extract', 'password')
   except:
      print 'No password for web access ! Nx_extract will exit.'
      exit(-1)
   fd.close()

   credshandler = InMemoryUsernamePasswordDatabaseDontUse()  # i know there is DontUse in the name
   credshandler.addUser(glob_user, glob_pass)
   portal = Portal(HTTPRealm(), [credshandler])
   credentialFactory = DigestCredentialFactory("md5", "Naxsi-UI")

   webroot = HTTPAuthSessionWrapper(portal, [credentialFactory])
   
   factory = Site(webroot)
   reactor.listenTCP(port, factory)

#   daemonize(stdout = '/tmp/nx_extract_output', stderr = '/tmp/nx_extract_error')
   reactor.run()
