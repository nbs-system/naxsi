'''
This modules generate types for url parameters.
'''
import re
import sys
import collections
from elasticsearch import Elasticsearch

# Each regexp is a subset of the next one
REGEXPS = [
    [r'^$', 'empty'],
    [r'^[01]$', 'boolean'],
    [r'^\d+$', 'integer'],
    [r'^#[0-9a-f]+$', 'colour'],  # hex + '#'
    [r'^[0-9a-f]+$', 'hexadecimal'],
    [r'^[0-9a-z]+$', 'alphanum'],
    [r'^https?://([0-9a-z-.]+\.)+[\w?+-=&/ ]+$', 'url'],  # like http://pouet.net?hello=1&id=3
    [r'^\w+$', 'alphanumdash'],
    [r'^[0-9a-z?&=+_-]+$', 'url parameter'],
    [r'^[\w[] ,&=+-]+$', 'array'],
    [r'^[' + r'\s\w' + r'!$%^&*()[]:;@~#?/.,' + r']+$', 'plaintext'],
    [r'', 'none'],  # untypables parameters
]


class Typificator(object):
    ''' Classes that:
        1. Fetch data from ES
        2. Generate types for parameters
        3. Returns a dict of dict
    '''
    def __init__(self, es, cfg):
        self.es_instance = es
        self.cfg = cfg

    def __get_data(self, nb_samples=1e5):
        ''' Get (in a lazy way) data from the ES instance
        '''
        data = set()
        position = 0
        size = min(10000, nb_samples)  # if nb_samples if inferiour to our size, we'll get it in a single request.
        while nb_samples:
            if not data:
                body = {'query': {}}
                for k,v in self.cfg['global_filters'].iteritems():
                    body['query'].update({'match':{k:v}})
                data = self.es_instance.search(index=self.cfg["elastic"]["index"], doc_type='events',
                                               size=size, from_=position,
                                               body=body)
                data = data['hits']['hits']  # we don't care about metadata
                if not data:  # we got all data from ES
                    return
                position += size
            nb_samples -= size
            for log in data:
                yield log['_source']

    def get_rules(self, nb_samples=1e5):
        ''' Generate (in a lazy way) types for parameters
        '''
        # Thank you defaultdict <3
        # rules = {zone1: {var1:0, var2:0}, zone2: {var6:0, ...}, ...}
        rules = collections.defaultdict(lambda: collections.defaultdict(int))

        # Compile regexp for speed
        regexps = [re.compile(reg, re.IGNORECASE) for reg, _ in REGEXPS]

        for line in self.__get_data(nb_samples):
            try:  # some events are fucked up^w^w empty
                #naxsi inverts the var_name and the content
                #when a rule match on var_name
                if line['zone'].endswith('|NAME'):
                    continue
                zone = line['zone']
                content = line['content']
                var_name = line['var_name']
            except KeyError as e:
                print 'Error with : {0} ({1})'.format(line, e)
                continue

            if not var_name:  # No types for empty varnames.
                continue

            # Bump regexps until one matches
            # Since every regexp is a subset of the next one,
            # this works great.
            while not regexps[rules[zone][var_name]].match(content):
                rules[zone][var_name] += 1

        for zone, zone_data in rules.iteritems():
            for var_name, index in zone_data.iteritems():
                if index < len(REGEXPS) - 1:  #  Don't return untyped things
                    yield [REGEXPS[index][0], REGEXPS[index][1], zone, var_name]


if __name__ == '__main__':

    nb_samples = 1e6 if len(sys.argv) == 1 else int(sys.argv[1])
    
    for rule in Typificator().get_rules(nb_samples):
        print 'TypeRule "rx:{0}" "msg:typed ({1}) parameter" "mz:${2}_VAR:{3}"'.format(rule[0], rule[1], rule[2], rule[3])
