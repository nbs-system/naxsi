#!/usr/bin/env python
import pprint
import os
import cgi
import sys
from ordereddict import OrderedDict
# This code is dirty :)
# This code needs to be replaced, but so far is doing its job,
# it will be discarded when we add filters.

# Top level class
class NxReportGen(object):
    def __init__(self, dst_file, data_dir, sql):
        # if not os.path.exists(dst_dir):
        #     try:
        #         os.mkdir(dst_dir)
        #     except:
        #         print "Unable to create dir :"+self.dst_dir
        #         os.exit(-1)
        # self.dst_dir = dst_dir
        self.dst_file = dst_file
        self.data_dir = data_dir
        self.sql = sql
        return
#map_canvas
    def write(self):
        generators = [NxReport, WorldMap]
        render = ""        
        try:
            rfd = open(self.data_dir+"/map.tpl")
            for i in rfd:
                render += i
            rfd.close()
        except:
            print "Unable to open/read tpl file :"+self.data_dir+"/map.tpl"
            sys.exit(-1)
        target = self.dst_file
        for gen in generators:
            nxr = gen(self.data_dir, self.sql)
            render = nxr.render_GET(render)
        try:
            dstfd = open(target, "w+")
            dstfd.write(render)
            dstfd.close()
        except:
            print "Unable to create dst file "+target
            sys.exit(-1)
        
            
        
class NxReport(object):
    # move file creation to top level
    def __init__(self, data_dir, sql):
        self.sql = sql
        self.data_dir = data_dir
        self.gi = None
        try:
            import GeoIP
            self.has_geoip = True
            self.gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        except:
            pass
    def render_topten(self):
        top_ten = self.sql.execute('select peer_ip as ip, count(id_exception) as c from connections group by peer_ip order by count(id_exception) DESC limit 10')
        self.top_ten_html = '</br></br><table class="table table-bordered" border="1" ><thead><tr><th>IP</th><th>Rule Hits</th></tr></thead><tbody>'
        for i in top_ten:
            if self.gi is not None:
                country = self.gi.country_code_by_addr(i['ip'])
            else:
                country = "??"
            self.top_ten_html += '<tr><td>' + cgi.escape(i['ip']) + '('+country+') </td><td> ' + str(i['c']) + '</td></tr>'
        self.top_ten_html += '</tbody></table>'

#        top_ten_page_html = ''

        top_ten_page = self.sql.execute('select distinct u.url as url, count(id_exception) as c from connections  join urls as u on (u.url_id = connections.url_id) group by u.url order by count(id_exception) DESC limit 10;')
        self.top_ten_html += '<table class="table table-bordered" border="1" ><thead><tr><th>URI</th><th>Exceptions Count</th></tr></thead><tbody>'
      
        for i in top_ten_page:
            self.top_ten_html += '<tr><td>' + cgi.escape(i['url']).replace('\'', '\\\'') + ' </td><td> ' + str(i['c']) + '</td></tr>'
        self.top_ten_html += '</tbody></table>'


    def render_GET(self, render):
        html = render
        array_excep, array_count = self.build_js_array()
        sqli_array, sql_count = self.build_js_array(1000, 1099)
        xss_array, xss_count = self.build_js_array(1300, 1399)
        rfi_array, rfi_count = self.build_js_array(1100, 1199)
        upload_array, upload_count = self.build_js_array(1500, 1599)
        dt_array, dt_count = self.build_js_array(1200, 1299)
        evade_array, evade_count = self.build_js_array(1400, 1499)
        intern_array, intern_count = self.build_js_array(0, 10)
        self.render_topten()
        dict_replace = {'__TOPTEN__': self.top_ten_html, 
                        '__TOTALEXCEP__': array_excep, 
                        '__SQLCOUNT__': str(sql_count),  
                        '__XSSCOUNT__': str(xss_count), 
                        '__DTCOUNT__': str(dt_count), 
                        '__RFICOUNT__': str(rfi_count), 
                        '__EVCOUNT__': str(evade_count), 
                        '__UPCOUNT__': str(upload_count), 
                        '__INTCOUNT__': str(intern_count), 
                        '__SQLIEXCEP__': sqli_array, 
                        '__XSSEXCEP__': xss_array, 
                        '__RFIEXCEP__': rfi_array, 
                        '__DTEXCEP__': dt_array, 
                        '__UPLOADEXCEP__': upload_array, 
                        '__EVADEEXCEP__': evade_array, 
                        '__INTERNEXCEP__': intern_array}
        for x in dict_replace.keys():
            if dict_replace[x] is None:
                dict_replace[x] = str(0)
        html = reduce(lambda html,(b, c): html.replace(b, c), 
                      dict_replace.items(), html)
        required_files = [(self.data_dir+"/bootstrap.min.css", "__CSS_BOOTSTRAP__"),
                          (self.data_dir+"/bootstrap-responsive.min.css", "__CSS_BOOTSTRAP_RESPONSIVE_"),
                          (self.data_dir+"/bootstrap.min.js", "__JS_BOOTSTRAP__"),
                          (self.data_dir+"/highcharts.js", "__JS_HIGHCHARTS__")]
        for data in required_files:
            fd = open(data[0], 'r')
            html = html.replace(data[1], fd.read())
            fd.close()
        return html

    def create_js_array(self, res):
        array = '['
        for i in res:
            if i is None:
                continue
            d = i
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
            count = self.sql.execute('select substr(date,1,10) as d, count(id_exception) as ex from connections group by substr(date,1,10)')
        else:
            count = self.sql.execute('select substr(date,1,10) as d, count(id_exception) as ex from connections join exceptions as e on (e.exception_id = id_exception) where e.rule_id >= ? and e.rule_id <= ? group by substr(date, 1, 10)', (str(id_beg), str(id_end)))
        mydict = self.build_dict(count)
        total_hit = 0
        for i in count:
            if i is not None:
                total_hit += i['ex']
        myarray = self.create_js_array(mydict)
        return myarray, total_hit
    
class WorldMap():
    isLeaf = True
    def __init__(self, data_dir, sql, circle_ratio=1000):
        self.has_geoip = False
        self.gi = None
        try:
            import GeoIP
            self.has_geoip = True
            self.gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        except:
            print "No geoip, no map."
        self.data_dir = data_dir
        self.sql = sql
        self.ratio = circle_ratio
    def render_GET(self, render):
        if self.has_geoip is False:
            return render
        ips = self.sql.execute('select peer_ip as p, count(*) as c from connections group by peer_ip')
        try:
            fd = open(self.data_dir+"/country2coords.txt", "r")
        except:
            return "Unable to open GeoLoc database, please check your setup."
        bycn = {}
        for ip in ips:
            country = self.gi.country_code_by_addr(ip['p'])
           # pun intended
            if country is None or len(country) < 2:
                country = "CN"
            if country not in bycn:
                bycn[country] = {'count': int(ip['c']), 'coords': ''}
                fd.seek(0)
                for cn in fd:
                    if cn.startswith(country+":"):
                        bycn[country]['coords'] = cn[len(country)+1:-1]
                        break
                if len(bycn[country]['coords']) < 1:
                    bycn[country]['coords'] = "37.090240,-95.7128910"
                else:
                    bycn[country]['count'] += ip['c']
        base_array = 'citymap["__CN__"] = {center: new google.maps.LatLng(__COORDS__), population: __COUNT__};\n'
        citymap = ''
        for cn in bycn.keys():
            citymap += base_array.replace('__CN__', cn).replace('__COORDS__', bycn[cn]['coords']).replace('__COUNT__', 
                                                                                                          str(bycn[cn]['count']))
        render = render.replace('__CITYMAP__', citymap)
        render = render.replace('__CIRCLE_RATIO__', str(self.ratio))
        return render
    
