'''
    This is a simple script intended to be run on nginx
    access logs to generate whitelists based on parameters types.

    Usage example:
        $ python typer.py nbs-system.com.acces.log

'''

import argparse
import re
import urlparse
import collections


# Each regexp is a subset of the next one
REGEXPS = [
    [r'^$', 'empty'],
    [r'^[01]$', 'boolean'],
    [r'^\d+$', 'integer'],
    [r'^#[0-9a-f]+$', 'colour'],  # '#' + hex
    [r'^[0-9a-f]+$', 'hexadecimal'],
    [r'^[0-9a-z]+$', 'alphanum'],
    [r'^https?://([0-9a-z-.]+\.)+[\w?+-=&/ ]+$', 'url'],  # like http://pouet.net?hello=1&id=3
    [r'^\w+$', 'alphanumdash'],
    [r'^[0-9a-z?&=+_-]+$', 'url parameter'],
    [r'^[\w[] ,&=+-]+$', 'array'],
    [r'^[\s\w!$%^&*()[]:;@~#?/.,]+$', 'plaintext'],  # plain text
    [r'', 'none'],  # untypables parameters
]
regexps = [re.compile(reg, re.IGNORECASE) for reg, _ in REGEXPS]
regexp_nginx_log = re.compile(r'''[^"]+ "[^ ]+ ([^ ]+)''')
rules = collections.defaultdict(int)

parser = argparse.ArgumentParser(description='Typificator for naxsi')
parser.add_argument('logfile')
args = parser.parse_args()

with open(args.logfile, 'r') as logfile:
    for line in logfile:
        match = regexp_nginx_log.search(line).group(1) 

        if not match:  # Because no one care about HEAD
            continue

        # Get query parameters
        query = urlparse.parse_qsl(urlparse.urlparse(match).query)

        for name, value in query:  # Iterate through regexps
            while not regexps[rules[name]].match(value):
                rules[name] += 1

for name, index in rules.iteritems():
    if index < len(REGEXPS) - 1:
        print 'BasicRule negative "rx:{0}" "msg:typed ({1}) parameter" "mz:$ARGS_VAR:{name}" "s:BLOCK";'.format(*REGEXPS[index], name=name)
