# Introduction

nxtool is a whitelist generation tool for naxsi.
It provides the following features :
  * Generating whitelists, based on templates, along with "rating"
  * Providing minimal statistics aiming at helping user in whitelist choices
  * Tag existing events matching provided whitelists for exclusion of whitelist generation
  * Tag existing events matching provided IPs for exclusion of whitelist generation

Tagging is important as it will exclude events from whitelist generation process and provide tracking.

# Supported options

## Scope/Filtering options

`-s SERVER, --server=SERVER`


## Whitelist generation options

`-t TEMPLATE, --template=TEMPLATE`

Given a path to a template file, attempt to generate matching whitelists.
Possible whitelists will be tested versus database, only the ones with "good" scores will be kept.

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

Performs the actual tagging. If not specified, matching events are simply displayed.


## Statistics generation options

`-x, --stats`

Generate statistics about current's db content.


# Rating system

  * rule_ip_count : nb of peers hitting rule
  * rule_uri_count : nb of uri the rule hitted on
  * template_ip_count : nb of peers hitting template
  * template_uri_count : nb of uri the rule  hitted on
  * ip_ratio_template : ratio of peers hitting the template vs peers hitting the rule
  * uri_ratio_template : ratio of uri hitting the template vs uri hitting the rule
  * ip_ratio_global : ratio of peers hitting the rule vs all peers
  * uri_ratio_global : ratio of uri hitting the rule vs all uri

# Terms

## Whitelist

A valid naxsi whitelist, ie. `BasicRule wl:X "mz:ARGS";`

## Template

A template for whitelist generation, ie. 

`
{
"zone" : "HEADERS",
"var_name" : "cookie",
"id" : "?"}
`

This template means that nxapi will extract all possible rule IDs found in zone `$HEADERS_VAR:cookie`,
and attempt to generate whitelists from it :

`
BasicRule wl:X "mz:$HEADERS_VAR:cookie";
..
`

templates so far support :
  * `"key" : "?"` : Expand key values to all values matching other template's criterias.
    keep in mind that having several '?' fields will seriously increase processing time `(uniques(key1) * uniques(key2) ..)`
  * `"?key" : ".*p.*w.*d.*"` : Expand key values to all values matching regex.
    In outputed rule, `key` is set to matching data, `BasicRule wl:X "mz:$BODY_VAR:user_password";`
  * `_statics : { "id" : "0" }` : If '_statics' is present, it will override fields values in final rule.
  * `_success : {}` and `_warnings : {}` : _success and _warning allow to expand ratings rules.



# Example usage

## Check/understand your paramters

`
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
# controls default colors and verbosity behaviour
"output" : {
 "colors" : "true",
 "verbosity" : "5"
}
}
`


## Obtain statistics about the global state of database

`
$ python nxtool.py  -c nxapi.json  --colors -x
`

Understanding the output :

`
# Whitelist(ing) ratio :
# false 100.0 % (total:122647/122647)
`

Provides the ratio of tagged events versus untagged events.
Tagging happens on user request, when providing whitelist files.


`
# Top servers :
# www.x.y 43.41 % (total:53241/122647)
# www.x.y 10.84 % (total:13298/122647)
# www.x.y 4.57 % (total:5611/122647)
# x.y 4.43 % (total:5430/122647)
# www.x.y 4.3 % (total:5273/122647)
# x.y 4.11 % (total:5046/122647)
# www.x.y 4.09 % (total:5013/122647)
# www.x.y 3.81 % (total:4669/122647)
# www.x.y 3.76 % (total:4609/122647)
# www.x.y 3.02 % (total:3699/122647)
# www.x.y 2.47 % (total:3035/122647)
`

A top-10 list of servers (fqdn) with most exceptions.

`
# Top URI(s) :
# /foo/bar 12.66 % (total:15532/122647)
# /foo/bar 8.18 % (total:10028/122647)
# /foo/bar 6.14 % (total:7535/122647)
# /foo/bar 4.35 % (total:5331/122647)
# /foo/bar 4.12 % (total:5055/122647)
# /foo/bar 3.74 % (total:4583/122647)
# /foo/bar 3.71 % (total:4556/122647)
# /foo/bar 3.16 % (total:3871/122647)
# /foo/bar 3.12 % (total:3829/122647)
# /foo/bar/ 2.67 % (total:3275/122647)
# /foo/bar 2.64 % (total:3243/122647)
`


A top-10 list of unique uris with most exceptions.


`
# Top Zone(s) :
# BODY 53.07 % (total:65092/122648)
# ARGS 16.58 % (total:20332/122648)
# HEADERS 13.49 % (total:16548/122648)
# BODY|NAME 12.75 % (total:15636/122648)
# URL 3.57 % (total:4384/122648)
# ARGS|NAME 0.4 % (total:488/122648)
# FILE_EXT 0.14 % (total:168/122648)
`

A list of zones in which most exceptions where triggered.

Note: These informations should help you determine on which URIs, servers or zones you might
      have the most learning work to do.


## Analyze events for a specific site for whitelist generation


