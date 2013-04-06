import datetime
import time


# supported syntax
# == [item]
# != [item]
# =~ [item]
# >= [item]
# <= [item]
# >  [item]
# <  [item]
# switch :
# or, and

# variables :
# server
# ip
# uri
# zone
# id
# var_name
# country => geo(ip)


class NxFilterx(object):
    
    def GetMatchesFromValues(self, filters, data):
        self.__filters = filters
        self.__data = data
        ret_dict = []
        for row in self.__data:
            row = dict(row)
            l = {}
            match = 0
            for var in self.__filters:
                if isinstance(self.__filters[var], list):
                    for val in self.__filters[var]:
                        if val == row[var]:
                            match += 1
                            l.update(row)
                            break
                else:
                    if row[var] == self.__filters[var]:
                        match += 1
                        l.update(row)
            if match < len(self.__filters):
                l = {}

            if l != {}:
                ret_dict.append(l)
        return ret_dict

    def GetMatchesFromDates(self, date_range, data):
        if data[0].get('date') is None:
            raise Exception, "No date field !"

        if date_range.startswith('-'):
            end =  time.strptime(date_range[1:], "%Y/%m/%d")
            start = time.strptime(str(datetime.date.min), "%Y-%m-%d")
        elif date_range.endswith('-'):
            start = time.strptime(date_range[:-1], "%Y/%m/%d")
            end = time.strptime(str(datetime.date.today()), "%Y-%m-%d")
        else:
            start, end = date_range.split('-')
            start =  time.strptime(start, "%Y/%m/%d")
            end =  time.strptime(end, "%Y/%m/%d")

        print start, end
    


import pprint
import re
self.kw = {
    "ip" : {"methods" : "=,!=,=~"},
    "date" : {"methods" : "=,!=,=~,>,<"},
    "server" : {"methods" : "=,!=,=~"},
    "uri" : {"methods" : "=,!=,=~"},
    "zone" : {"methods" : "=,!="},
    "var_name" : {"methods" : "=,!=,=~"},
    "content" : {"methods" : "=,!=,=~"},
    "country" : {"methods" : "=,!="}
    }


def subfil(src, sub):
    if sub[0] not in src:
        print "Unable to filter : key "+sub[0]+" does not exist in dict"
        return False
    srcval = src[sub[0]]
    filval = sub[2]

    if sub[1] == "=" and srcval == filval:
        return True
    elif sub[1] == "!=" and srcval != filval:
        return True
    elif sub[1] == "=~" and re.match(filval, srcval):
        return True
    return False

def dofilter(src, filters):
    last = False
    ok_fail = False
    print "TESTING ARRAY :"
    pprint.pprint(src)
    while last is False:
        print "ok_fail status :"+str(ok_fail)
        sub = filters[0:3]
        filters = filters[3:]
        if len(filters) == 0:
            last = True
        print "test vs:"+str(sub)+"",
        result = subfil(src, sub)
        print "==>"+str(result)
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
        if result is False and filters[0] == "and":
            return False
        # remove and/or
        filters = filters[1:]
        ok_fail = False
    return True
def word(w, res):
    if w not in kw.keys():
        return -1
    res.append(w)
    return 1

def check(w, res):
    if w not in kw[res[-1]]["methods"].split(","):
        print "operator "+w+" not allowed for var "+res[-1]
        return -1
    res.append(w)
    return 2

def checkval(w, res):
    res.append(w)
    return 3

def synt(w, res):
    if w != "or" and w != "and":
        return -1
    res.append(w)
    return 0

def str2filt(instr):
    words = instr.split(' ')
    res_op = []
    # -1 : err, 0 : var, 1 : check, 2 : syntax (and/or), 3 : value
    state = 0
    for w in words:
        if state == -1:
            print "Unable to build filter, check your syntax."
            break
        elif state == 0:
            state = word(w, res_op)
            continue
        elif state == 1:
            state = check(w, res_op)
            continue
        elif state == 2:
            state = checkval(w, res_op)
            continue
        elif state == 3:
            state = synt(w, res_op)
            continue
    return res_op

        
if __name__ == "__main__":

    tofilter = [
        {"ip" : "127.0.0.1",
         "uri" : "/notcomments/",
         "zone" : "BODY",
         "id" : "1301",
         "country" : "CN"},

        {"ip" : "127.0.0.2",
         "uri" : "/notcomments/",
         "zone" : "BODY",
         "id" : "1301",
         "country" : "FR"},

        {"ip" : "127.0.0.1",
         "uri" : "/comment/1",
         "zone" : "BODY",
         "id" : "1301",
         "country" : "FR"},

        {"ip" : "127.0.0.1",
         "uri" : "/comment/2",
         "zone" : "BODY",
         "id" : "1301",
         "country" : "XE"},

        {"ip" : "127.0.0.2",
         "uri" : "/comment/2",
         "zone" : "BODY",
         "id" : "1301",
         "country" : "US"},
        ]
#    ufil = "ip != 127.0.0.1 and uri =~ /comment/* and zone = BODY"
#    ufil = "uri =~ /.*comm* and zone != HEADERS"
    ufil = "country = FR or country = US" 
    filt = str2filt(ufil)
    
    for x in tofilter:
        if dofilter(x, filt) is True:
            print ":True"
#            pprint.pprint(x)
        else:
            print ":False"
