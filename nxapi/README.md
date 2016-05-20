# A quick word

nxapi/nxtool is the new learning tool, that attempts to perform the following :
  * Events import : Importing naxsi events into an elasticsearch database
  * Whitelist generation : Generate whitelists, from templates rather than from purely statistical aspects
  * Events management : Allow tagging of events into database to exclude them from wl gen process
  * Reporting : Display information about current DB content

# Configuration file : nxapi.json

nxapi uses a JSON file for its settings, such as :


$ cat nxapi.json 


    {
    # elasticsearch setup, must point to the right instance.
    "elastic" : {
     "host" : "127.0.0.1:9200",
     "index" : "nxapi",
     "doctype" : "events",
     "default_ttl" : "7200",
     "max_size" : "1000"
    },
    # filter used for any issued requests, you shouldn't modify it yet
    "global_filters" : {
     "whitelisted" : "false"
    },
    # global warning and global success rules, used to distinguish good and 'bad' whitelists
    "global_warning_rules" : {
     "rule_uri" : [ ">", "5" ],
     "rule_var_name" : [ ">", "5" ],
     "rule_ip" : ["<=", 10 ],
     "global_rule_ip_ratio" : ["<", 5]
    },
    "global_success_rules" : {
     "global_rule_ip_ratio" : [">=", 30],
     "rule_ip" : [">=", 10]
    },
    # path to naxsi core rules, path to template files,
    # path to geoloc database.
    "naxsi" : {
     "rules_path" : "/etc/nginx/naxsi_core.rules",
     "template_path" : "tpl/",
     "geoipdb_path" : "nx_datas/country2coords.txt"
    },
    # controls default colors and verbosity behavior
    "output" : {
     "colors" : "true",
     "verbosity" : "5"
    }
    }

# Prequisites

## Set up ElasticSearch
* Download the archive with the binary files from https://www.elastic.co/downloads/elasticsearch
* Extract the archive
* Start ElasticSearch by executing `bin/elasticsearch` in the extracted folder
* Check whether ElasticSearch is running correctly:  
	`curl -XGET http://localhost:9200/`
* Add a nxapi index with the following command:  
	`curl -XPUT 'http://localhost:9200/nxapi/'`

## Populating ElasticSearch with data
* Enable learning mode
* Browse website to generate data in the logfile
* Change into nxapi directory
* Load the data from the log file into ElasticSearch with the following command:  
	`./nxtool.py -c nxapi.json --files=/PATH/TO/LOGFILE.LOG`
* Check if data was added correctly:  
	`curl -XPOST "http://localhost:9200/nxapi/events/_search?pretty" -d '{}' `
* Check if nxtool sees it correctly:
  	`./nxtool.py -c nxapi.json -x`
# Simple usage approach

##1. Get info about db

    $ ./nxtool.py -x --colors -c nxapi.json
Will issue a summary of database content, including :

  * Ratio between tagged/untagged events.

Tagging of events is an important notion that allows you to know how well you are doing on learning.
Let's say you just started learning. You will have a tag ratio of 0%, which means you didn't write any
whitelists for recent events. Once you start generating whitelists, you can provide those (`-w /tmp/wl.cf --tag`)
and nxapi will mark those events in the database as whitelisted, excluding them from future generation process.
It allows you to speed up the generation process, but mainly to know how well you dealt with recent false positives.

You can also use the tagging mechanism to exclude obvious attack patterns from learning. If X.Y.Z.W keeps hammering my website and polluting my log, I can provide nxapi with the ip (`-i /tmp/ips.txt --tag`) to tag and exclude them from process.

  * Top servers.
A TOP10 list of dst hosts raising the most exceptions.
  * Top URI(s).
A TOP10 list of dst URIs raising the most exceptions. It is very useful in combination with --filter to generate whitelists for specific URI(s).
  * Top Zones.
List of most active zones of exceptions.

##2. Generate whitelists
Let's say I had the following output :

    ./nxtool.py -c nxapi.json  -x --colors
    # Whitelist(ing) ratio :
    # false 79.96 % (total:196902/246244)
    # true 20.04 % (total:49342/246244)
    # Top servers :
    # www.x1.fr 21.93 % (total:43181/196915)
    # www.x2.fr 15.21 % (total:29945/196915)
    ...
    # Top URI(s) :
    # /foo/bar/test 8.55 % (total:16831/196915)
    # /user/register 5.62 % (total:11060/196915)
    # /index.php/ 4.26 % (total:8385/196915)
    ...
    # Top Zone(s) :
    # BODY 41.29 % (total:81309/196924)
    # HEADERS 23.2 % (total:45677/196924)
    # BODY|NAME 16.88 % (total:33243/196924)
    # ARGS 12.47 % (total:24566/196924)
    # URL 5.56 % (total:10947/196924)
    # ARGS|NAME 0.4 % (total:787/196924)
    # FILE_EXT 0.2 % (total:395/196924)
    # Top Peer(s) :
    # ...

I want to generate whitelists for x1.fr, so I will get more precise statistics first :

    ./nxtool.py -c nxapi.json  -x --colors -s www.x1.fr
    ...
    # Top URI(s) :
    # /foo/bar/test 8.55 % (total:16831/196915)
    # /index.php/ 4.26 % (total:8385/196915)
    ...

I will then attempt to generate whitelists for the `/foo/bar/test` page, that seems to trigger most events :

`Take note of the --filter option, that allows me to work whitelists only for this URI.
Filters can specify any field : var_name, zone, uri, id, whitelisted, content, country, date ...
However, take care, they don't support regexp yet.
Take note as well of --slack usage, that allows to ignore success/warning criterias, as my website has too few
visitors, making legitimate exceptions appear as false positives.`

    ./nxtool.py -c nxapi.json -s www.x1.fr -f --filter 'uri /foo/bar/test' --slack
    ...
    #msg: A generic whitelist, true for the whole uri
    #Rule (1303) html close tag
    #total hits 126
    #content : lyiuqhfnp,+<a+href="http://preemptivelove.org/">Cialis+forum</a>,+KKSXJyE,+[url=http://preemptivelove.org/]Viagra+or+cialis[/url],+XGRgnjn,+http
    #content : 4ThLQ6++<a+href="http://aoeymqcqbdby.com/">aoeymqcqbdby</a>,+[url=http://ndtofuvzhpgq.com/]ndtofuvzhpgq[/url],+[link..
    #peers : x.y.z.w
    ...
    #uri : /faq/
    #var_name : numcommande
    #var_name : comment
    ...
    # success : global_rule_ip_ratio is 58.82
    # warnings : rule_ip is 10
    BasicRule  wl:1303 "mz:$URL:/foo/bar/test|BODY";


nxtool attempts to provide extra information to allow user to decides wether it's a false positive :
  * content : actual HTTP content, only present if $naxsi_extensive_log is set to 1
  * uri : example(s) of URI on which the event was triggered
  * var_name : example(s) of variable names in which the content was triggered
  * success and warnings : nxapi will provide you with scoring information (see 'scores').

##3. Interactive whitelist generation

Another way of creating whitelists is to use the -g option. This option provide
an interactive way to generate whitelists. This option use the EDITOR env
variable and uses it to iterate over all the servers available inside your elastic
search instance (if the EDITOR env variable isn't set it will try to use `vi`.
You can either delete or comment with a `#` at the beginning the line you don't
want to keep. After the server selection, it will iterate on each available uri
and zone for earch server. If you want to use regex, only available for uri,
you can add a `?` at the beginning of each line where you want to use a regex:

    uri /fr/foo/ ...
    ?uri /[a-z]{2,}/foo ...

The -g options once all the selection is done, will attempt to generate the wl
with the same behaviour as -f option, and write the result inside the path the
typical output when generating wl is:

    generating wl with filters {u'whitelisted': u'false', 'uri': '/fr/foo', 'server': 'x.com'}
    Writing in file: /tmp/server_x.com_0.wl

As you can see you'll see each filter and each file for each selections.

##4. Tagging events

Once I chose the whitelists that I think are appropriate, I will write them in a whitelist file. 
Then, I can tag corresponding events :
    nxtool.py -c nxapi.json -w /tmp/whitelist.conf --tag

And then, if I look at the report again, I will see a bump in the tagged ratio of events.
Once the ratio is high enough or the most active URLs & IPs are false positives, it's done!


# Tips and tricks for whitelist generation

  * `--filter`

--filter is your friend, especially if you have a lot of exceptions.
By narrowing the search field for whitelists, it will increase speed, and reduce false positives.

  * use `-t` instead of `-f`

-f is the "dumb" generation mode, where all templates will be attempted.
if you provide something like `-t "ARGS/*"` only templates specific to ARGS whitelists will be attempted.

  * Create your own templates

If you manage applications that do share code/framework/technology, you will quickly find yourself 
generating the same wl again and again. Stop that! Write your own templates, improving generation time, 
accuracy and reducing false positives. Take a practical example: 
I'm dealing with magento, like a *lot*. One of the recurring patterns is the "onepage" checkout, so I created specific templates:

    {
	"_success" : { "rule_ip" : [ ">", "1"]},
        "_msg" : "Magento checkout page (BODY|NAME)",
        "?uri" : "/checkout/onepage/.*",
        "zone" : "BODY|NAME",
        "id" : "1310 OR 1311"
    }


# Supported options

## Scope/Filtering options

`-s SERVER, --server=SERVER`

Restrict context of whitelist generation or stats display to specific FQDN.

`--filter=FILTER`

A filter (in the form of a dict) to merge with 
existing templates/filters: 'uri /foobar zone BODY'.
You can combine several filters, for example : `--filter "country FR" --filter "uri /foobar"`.


## Whitelist generation options

`-t TEMPLATE, --template=TEMPLATE`

Given a path to a template file, attempt to generate matching whitelists.
Possible whitelists will be tested versus database, only the ones with "good" scores will be kept.
if TEMPLATE starts with a '/' it's treated as an absolute path. Else, it's expanded starting in tpl/ directory.

`-f, --full-auto`

Attempts whitelist generation for all templates present in rules_path.

`--slack`

Sets nxtool to ignore scores and display all generated whitelists.


## Tagging options

`-w WL_FILE, --whitelist-path=WL_FILE`

Given a whitelist file, finds matching events in database.

`-i IPS, --ip-path=IPS`

Given a list of ips (separatated by \n), finds matching events in database.

`--tag`

Performs tagging. If not specified, matching events are simply displayed.


## Statistics generation options

`-x, --stats`

Generate statistics about current database.

## Importing data

**Note:** All acquisition features expect naxsi EXLOG/FMT content.


` --files=FILES_IN    Path to log files to parse.̀`


Supports glob, gz bz2, ie. --files "/var/log/nginx/*mysite.com*error.log*"


`--fifo=FIFO_IN      Path to a FIFO to be created & read from. [infinite]`
Creates a FIFO, increases F_SETPIPE_SZ, and reads on it. mostly useful for reading directly from syslog/nginx logs.

`--stdin             Read from stdin.`

`--no-timeout        Disable timeout on read operations (stdin/fifo).̀


# Understanding templates

Templates do have a central role within nxapi.
By default only generic ones are provided, you should create your own.
First, look at a generic one to understand how it works :

        {
                "zone" : "HEADERS",
                "var_name" : "cookie",
                "id" : "?"
        }

Here is how nxtool will use this to generate whitelists:
  1. extract global_filters from nxapi.json, and create the base ES filter :
     { "whitelisted" : "false" }
  2. merge base ES filter with provided cmd line filter (--filter, -s www.x1.fr)
     { "whitelisted" : "false", "server" : "www.x1.fr" }
  3. For each static field of the template, merge it in base ES filter :
     { "whitelisted" : "false", "server" : "www.x1.fr", "zone" : "HEADERS", "var_name" : "cookie" }
  4. For each field to be expanded (value is `?`) :
   4.1. select all possible values for this field (id) matching base ES filter, (ie. 1000 and 1001 here)
   4.2. attempt to generate a whitelist for each possible value, and evaluate its scores.
	{ "whitelisted" : "false", "server" : "www.x1.fr", "zone" : "HEADERS", "var_name" : "cookie", "id" : "1000"}
	{ "whitelisted" : "false", "server" : "www.x1.fr", "zone" : "HEADERS", "var_name" : "cookie", "id" : "1001"}
  5. For each final set that provided results, output a whitelist.


Templates support :
  * `"field" : "value"` : A static value that must be present in exception for template to be true.
  * `"field" : "?"` : A value that must be expanded from database content (while matching static&global filters).
    	       unique values for "field" will then be used for whitelist generation (one whitelist per unique value).
  * `"?field" : "regexp"` : A regular expression for a field content that will be searched in database.
    	       unique values matching regexp for "field" will then be used for whitelist generation (one whitelist per unique value).
  * `"_statics" : { "field" : "value" }` : A static value to be used at whitelist generation time. Does not take part in search process,
    		only at 'output' time. ie. `"_statics" : { "id" : "0" }` is the only way to have a whitelist outputing a 'wl:0'.
  * `"_msg" : "string" ` : a text message to help the user understand the template purpose.
  * `"_success" : { ... }` : A dict supplied to overwrite/complete 'global' scoring rules.
  * `"_warnings" : { ... }` : A dict supplied to overwrite/complete 'global' scoring rules.


# Understanding scoring

Scoring mechanism :
  * Scoring mechanism is a very trivial approach, relying on three kinds of "scoring" expressions : _success, _warning, _deny.
  * Whenever a _success rule is met while generating a whitelist, it will INCREASE the "score" of the whitelist by 1.
  * Whenever a _warning rule is met while generating a whitelist, it will DECREASE the "score" of the whitelist by 1.
  * Whenever a _deny rule is met while generating a whitelist, it will disable the whitelist output.

_note:_
In order to understand scoring mechanism, it is crucial to tell the difference between a template and a rule.
A template is a .json file which can match many events. A rule is usually a subpart of a template results.
For example, if we have this data : 

    [ {"id" : 1, "zone" : HEADERS, ip:A.A.A.A},
      {"id" : 2, "zone" : HEADERS, ip:A.A.A.A},
      {"id" : 1, "zone" : ARGS, ip:A.B.C.D}
    ]


And this template :

    {"id" : 1, "zone" : "?"}

Well, template_ip would be 2, as 2 peers triggered events with ID:1.
However, rule_ip would be 1, as the two generated rules ('id:1 mz:ARGS' and 'id:1 mz:HEADERS'),
were triggered each by one unique peer.

If --slack is present, scoring is ignored, and all possible whitelists are displayed.
In normal conditions, whitelists with more than 0 points are displayed.
The default filters enabled in nxapi, from nxapi.json :


    "global_warning_rules" : {
      "rule_ip" : ["<=", 10 ],
      "global_rule_ip_ratio" : ["<", 5]
      },
    "global_success_rules" : {
      "global_rule_ip_ratio" : [">=", 10],
      "rule_ip" : [">=", 10]
      },
    "global_deny_rules" : {
     "global_rule_ip_ratio" : ["<", 2]
      },


  * rule_N <= X : "at least" X uniq(N) where present in the specific events from which the WL is generated.
    * '"rule_ip" : ["<=", 10 ],' : True if less than 10 unique IPs hit the event
    * '"rule_var_name" : [ "<=", "5" ]' : True if less than 5 unique variable names hit the event
  * template_N <= X : "at least" X uniq(N) where present in the specific events from which the WL is generated.
    * Note the difference with "rule_X" rules. 
  * global_rule_ip_ratio < X : "at least" X% of the users that triggered events triggered this one as well.
    * however, ration can theorically apply to anything, just ip_ratio is the most common.







