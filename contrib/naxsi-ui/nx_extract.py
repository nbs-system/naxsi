#!/usr/bin/env python

# twisted imports
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


# nx* imports
from NaxsiLib.ordereddict import OrderedDict
from NaxsiLib.nx_commons import nxlogger
from NaxsiLib.nx_commons import nxdaemonizer
from NaxsiLib.nx_parser import rules_extractor


# system imports
from ConfigParser import ConfigParser
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


class NaxsiUI(Resource):
   def __init__(self):
      Resource.__init__(self)
      #twisted will handle static content for me
      self.putChild('bootstrap', File(data_path+'/bootstrap'))
      self.putChild('js', File(data_path+'/js'))
      #make the correspondance between the path and the object to call
      self.page_handler = {'/' : Index, '/graphs': GraphView, '/get_rules': GenWhitelist, '/map': WootMap}

   def getChild(self, name, request):
      handler = self.page_handler.get(request.path)
      if handler is not None:
         return handler()
      else:
         return NoResource()
         

class Index(Resource):
   def __init__(self):
      Resource.__init__(self)
      self.ex = rules_extractor(0,0, glob_rules_file, glob_conf_file, log)
         
   def render_GET(self, request):
      try:
         fd = open(data_path+'/index.tpl', 'r')
      except:
         log.critical("Unable to open index template.")
         return "Unable to open index template, please check your setup."
      helpmsg = ''
      for i in fd:
         helpmsg += i
      fd.close()
      if self.ex.wrapper.checkDB() is False:
         log.critical("Database is empty, nx_extract won't work.")
         return "Your database seems to be empty."
      
      helpmsg = helpmsg.replace('__STATS__', "<ul><li>"+self.ex.generate_stats()+"</li></ul>")
      helpmsg = helpmsg.replace('__HOSTNAME__', request.getHeader('Host'))
      return helpmsg


class WootMap(Resource):
   isLeaf = True
   def __init__(self):
      self.has_geoip = False
      try:
         import GeoIP
         self.has_geoip = True
      except:
         log.critical("No GeoIP module, no map")
         return
      Resource.__init__(self)
      self.ex = rules_extractor(0,0, glob_rules_file, glob_conf_file, log)
      self.gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
   def render_GET(self, request):
      if self.has_geoip is False:
         return "No GeoIP module/database installed."
      try:
         render = open(data_path+'/map.tpl').read()
      except:
         log.critical("Unable to open map template.")
         return "Unable to open map template, please check your setup."
      
      self.ex.wrapper.execute('select peer_ip as p, count(*) as c from connections group by peer_ip')
      ips = self.ex.wrapper.getResults()
      try:
         fd = open(data_path+"/country2coords.txt", "r")
      except:
         log.critical("Unable to open GeoLoc database.")
         return "Unable to open GeoLoc database, please check your setup."
      bycn = {}
      for ip in ips:
         country = self.gi.country_code_by_addr(ip['p'])
         if country is None or len(country) < 2:
            country = "CN"
         if country not in bycn:
            bycn[country] = {'count': int(ip['c']), 'coords': ''}
            fd.seek(0)
            for cn in fd:
               if country in cn:
                  bycn[country]['coords'] = cn[len(country)+1:-1]
                  break
            if len(bycn[country]['coords']) < 1:
               bycn[country]['coords'] = "37.090240,-95.7128910"
         else:
            bycn[country]['count'] += ip['c']
            pprint.pprint(bycn[country])
      base_array = 'citymap["__CN__"] = {center: new google.maps.LatLng(__COORDS__), population: __COUNT__};\n'
      citymap = ''
      for cn in bycn.keys():
         citymap += base_array.replace('__CN__', cn).replace('__COORDS__', bycn[cn]['coords']).replace('__COUNT__', 
                                                                                                       str(bycn[cn]['count']))
      render = render.replace('__CITYMAP__', citymap)
      return render
   
class GraphView(Resource):
   isLeaf = True
   
   def __init__(self):
      Resource.__init__(self)
      self.ex = rules_extractor(0,0, glob_rules_file, glob_conf_file, log)


   def render_GET(self, request):

      try:
         fd = open(data_path+'/graphs.tpl')
      except:
         log.critical("Unable to open graphs template.")
         return "Unable to open graphs template, please check your setup."
      html = ''
      for i in fd:
         html += i
      fd.close()
      
      array_excep, array_count = self.build_js_array()
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
         if i is None:
            continue
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
         if i is not None:
            total_hit += i['ex']
      myarray = self.create_js_array(mydict)
      return myarray, total_hit

class GenWhitelist(Resource):

   def render_GET(self, request):
      request.setHeader('content-type', 'text/plain')
      ex = rules_extractor(int(request.args.get('page_hit', ['10'])[0]), 
                           int(request.args.get('rules_hit', ['10'])[0]), 
                           glob_rules_file, glob_conf_file, log)
      ex.gen_basic_rules()
      base_rules, opti_rules = ex.opti_rules_back()
      opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
      r = ex.format_rules_output(ex.final_rules)
      return r

class HTTPRealm(object):
   implements(IRealm)

   def requestAvatar(self, avatarID, mind, *interfaces):
      return (IResource, NaxsiUI(), lambda: None)
      
def usage():
   print 'Usage : python nx_extract -c /path/to/conf/file [-o] [-s] [-p] [-r] [-h]'
   print '[-o --output]'
   print '\tDo not daemonize, output whitelists on stdout and exit.'
   print '[-s --status]'
   print '\tDo not daemonize, display exceptions count on stdout and exit.'
   print '[-p --pages-hit NUMBER]'
   print '\tSpecify pages hit limit for -o option. Defaults to 10.'
   print '[-r --rules-hit NUMBER]'
   print '\tSpecify rules hit limit for -o option. Defaults to 10.'
   print "[-n : Don't demonize]"


if __name__  == '__main__':
   try:
      opts, args = getopt.getopt(sys.argv[1:], 'c:hosp:r:n', ['conf-file', 'help', 'output', 'status', 'pages-hit', 'rules-hit', ''])
   except getopt.GetoptError, err:
      print str(err)
      usage()
      sys.exit(-1)
      
   has_conf = single_run = stats_run = False
   logs_path = []
   rules_hit = pages_hit = 10
   daemonize = True

   for o, a in opts:
      if o in ('-h', '--help'):
         usage()
         sys.exit(0)
      if o in ('-c', '--conf-file'):
         has_conf = True
         glob_conf_file = a
      if o in ('-o', '--output'):
         single_run = True
      if o in ('-s', '--status'):
         stats_run = True
      if o in ('-p', '--pages-hit'):
         pages_hit = int(a)
      if o in ('-r', '--rules-hit'):
         rules_hit = int(a)
      if o in ('-n'):
         daemonize = False

   if has_conf is False:
      usage()
      sys.exit(-1)
   
   fd = open(glob_conf_file, 'r')
   conf = ConfigParser()
   conf.readfp(fd)
   
   try:
      iface = conf.get('nx_extract', 'interface')
   except:
      iface = ''

   try:
      port = int(conf.get('nx_extract', 'port'))
   except:
      print "No port in conf file ! Using default port (8081)"
      port = 8081
   try:
      glob_rules_file = conf.get('nx_extract', 'rules_path')
   except:
      print "No rules path in conf file ! Using default (/etc/nginx/naxsi_core.rules)"
      glob_rules_file = "/etc/nginx/naxsi_core.rules"

   try:
      glob_user = conf.get('nx_extract', 'username')
   except:
      print 'No username for web access ! Nx_extract will exit.'
      sys.exit(-1)

   try:
      log_path = conf.get('nx_extract', 'log_path')
   except:
      print 'No log_path provided, using stdout.'
      log_path = sys.stdout

   try:
      data_path = conf.get('nx_extract', 'data_path')
   except:
      print 'No data_path provided ! Nx_extract will exit..'
      sys.exit(-1)

   try:
      pid_path = conf.get('nx_extract', 'pid_path')
   except:
      print 'No pid_path provided, using /tmp/nx_extract.pid.'
      pid_path = "/tmp/nx_extract.pid"

   try:
      glob_pass = conf.get('nx_extract', 'password')
   except:
      print 'No password for web access ! Nx_extract will exit.'
      sys.exit(-1)
   fd.close()
   



   # log
   log = nxlogger(log_path, "nx_extract")
   log.warning("Starting nx_extract.")
   
   # handle case where we should not daemonize
   if single_run is True:
      ex = rules_extractor(pages_hit, rules_hit,  
                           glob_rules_file, glob_conf_file, log)
      ex.gen_basic_rules()
      base_rules, opti_rules = ex.opti_rules_back()
      opti_rules.sort(lambda a,b: (b['hratio']+(b['pratio']*3)) < (a['hratio']+(a['pratio']*3)))
      r = ex.format_rules_output(ex.final_rules)
      print r
      sys.exit(0)
      
   # handle case where we should not daemonize
   if stats_run is True:
      ex = rules_extractor(pages_hit, rules_hit,  
                           glob_rules_file, glob_conf_file, log)
      print ex.generate_stats()
      sys.exit(0)
      
   credshandler = InMemoryUsernamePasswordDatabaseDontUse()  # i know there is DontUse in the name
   credshandler.addUser(glob_user, glob_pass)
   portal = Portal(HTTPRealm(), [credshandler])
   credentialFactory = DigestCredentialFactory("md5", "Naxsi-UI")
   
   webroot = HTTPAuthSessionWrapper(portal, [credentialFactory])
   
   factory = Site(webroot)

   try:
      reactor.listenTCP(port, factory, interface=iface)
      log.warning("Listening on port "+str(port)+" iface:"+iface)
   except:
      log.critical ("Unable to listen on "+str(port)+" iface:"+iface)
      sys.exit (-1)

   # & daemonize !
   if daemonize is True:
      daemon = nxdaemonizer(pid_path)
      daemon.daemonize()
      daemon.write_pid()
         
   reactor.run()
