  _   _                _ 
 | \ | | __ ___  _____(_)
 |  \| |/ _` \ \/ / __| |
 | |\  | (_| |>  <\__ \ |
 |_| \_|\__,_/_/\_\___/_|
 v0.1 alpha

[[[!!! PLEASE REFER TO THE WIKI INSTEAD !!!]]]
Yes, this readme is for v0.1 alpha, now is 0.46-1

 
|--{ Introduction }------------------------------------------------------------|


NAXSI is a module for nginx, the famous webserver/reverse-proxy/...
Its goal is to help people to secure their web application against attacks 
such as SQL Injection, Cross Site Scripting, Cross Site Request Forgery, 
Local & Remote file inclusions and such. 
The difference with most WAF (Web Applicative Firewalls) out there is that 
it does not rely on signatures to detect attacks. It is using a simpler model, 
where instead of trying to detect "known" attacks, it will detect unexpected 
characters in the HTTP request/arguments. Each kind of unusual character will 
increase the score of the request. If the request reaches a score that's 
considered "too high", the request will be denied, and the user will be 
redirected to a "forbidden" page. Yes, it works a bit like a spam system.


|--{  Why is it different ? }--------------------------------------------------|

NAXSI is different, because it works on a learning mode (read whitelist). 
Set the module in learning mode, scroll your site, and it will generate the 
necessaries whitelists to avoid false positives !
NAXSI doesn't relies on signatures, so it should be capable of defeating 
complex/unknown/obfuscated attack 
patterns.


|--{  How does it work  }------------------------------------------------------|


NAXSI relies on two separate configuration parts. 
		  * Core Rules : Located at HTTP server level configuration.
		  * WhiteLists & Specific Rules : Located at the HTTP location 
		    level configuration.

The first one is what we called 'core rules'. 
It's a set of rules that will contain all characters or regular expression 
that will increase the score of the request, for exemple :

MainRule "rx:<|>" "msg:html tag ?" "mz:ARGS|URL|BODY" "s:$XSS:8" id:1302;

This rule, will match on both < and > characters (rx:<|>), and will increase 
the score associated to the XSS threat (s:$XSS:8). This pattern will be matched
 against various zones of the request : ARGS (GET arguments), 
URL (the full URI), and BODY (POST arguments). Each rule is associated to 
unique ID (here, 1302), that is used for whitelisting. 
There is not "many" core rules (34 at the time of writting), and this set 
should normally not evolve.


On the other hand, we have a "local" configuration, which is to be defined 
"per site" (as NAXSI main goal is to work with NGINX as a RP), and which will 
define "how strict" the security policy of the site will be, as well as 
putting exceptions (whitelists) according the site specificities :

-----------------------------------8<-------------------------------------------
# Define to which "location" the user will be redirected when a request is
# denied.
DeniedUrl "/RequestDenied";

# Whitelist '|', as it's used on the /report/ page, in argument 'd'
BasicRule wl:1005 "mz:$URL:/report/|$ARGS_VAR:d";
# Whitelist ',' on URL zone as it's massively used for URL rewritting !
BasicRule wl:1008 "mz:URL";

# Check rules
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
-----------------------------------8<-------------------------------------------

Let's see this configuration again to clarify things :

* 'BasicRule' : This directive is used here to whitelist some rules. 
   As you can see (and expect !) you can be more or less laxist.
   For exemple, there is a directive (BasicRule wl:1008 ...) that will totally 
   disable the rule 1008 checking against URL. This rule is normally matching 
   the ',' character.

On the other hand, you can make extremly precise rules, as this one :
   BasicRule wl:1005 "mz:$URL:/report/|$ARGS_VAR:d";
   In the last exemple, we are whitelisting a rule, but only on one specific 
   argument of one specific webpage (the argument named 'd' of the page 
   '/report/').

As stated earlier, "local" configuration is also used to decide how 
"strict" one site (or one part of one site) will be, that is, what is 
the maximal tolerated page score before a request is denied :

CheckRule "$SQL >= 8" BLOCK;

This directive tells NAXSI that every request that has a 'SQL' score superior 
or equal to 8 will be denied.


|--{  Denied requests and whitelist generation  }------------------------------|

When a user's request is denied, he will be (internally) redirected to the page
defined in the configuration :
DeniedUrl "/RequestDenied";
This page will receive detailed informations on the rules that matched 
(it's logued in log files too), as well as both the request and the user 
context, without giving information to the user (thanks to nginx internal 
redirects). Actually the page at /RequestDenied will be called with arguments, 
like :

server=xxxx&uri=/vulnerable.php&ip=127.0.0.1&zone0=ARGS&id0=1010&var_name0=foo1&zone1=ARGS&id1=1011&...

If you have a closer look to the URL above, you will understand that the 
following information will be transmitted to the forbidden page :
 - Which rule matched on which argument, in which part of the request (ARGS, 
   BODY, URL, HEADERS ...)
 - Original URL and hostname
 - Client IP adress

Those information are given for both statistics generation purpose, as well as
for whitelist generation purposes.

Yes, actually that's a very important aspect of NAXSI : As it is heavily 
relying on whitelist for configuration, the easiest the whitelist generation is
, the easier the configuration is ! The thing being that the DeniedUrl page 
receives enough information to generate a set of whitelisting rules that will 
allow the request that was blocked to be allowed in the future.

To make it clear : you can generate the whole NAXSI configuration, only by 
naviguating to the site, or even better, by using a clever crawler !
When you will do a navigation session on the website you want to create rules 
for, if you are in "LearningMode", some requests might be (and will be) tagued
 as blocked. They should be blocked, because, for example, the developpers 
(damn!) decided to massively use '|' for URL rewritting, and NAXSI 
will dislike this.

So, as you are in learning mode (but the idea is the same when LearningMode is
disabled), NAXSI will log the fact that the request was blocked because of the
presence of multiples '|' in the URL. Then, with a simple script (a python 
script is provided), you can parse the log files and generate the appropriate 
whiterules to allow legitimate (false positive) requests.

The more tricky part when talking about NAXSI and its whitelist, is when we 
come to sites that allows a LOT of wide user input : Comments, Registration 
forms and things like this. For this, either a carefull navigation, submitting 
real content is required (so that NAXSI will trigger every plausible rule on 
each kind of form field) or the usage of a clever crawler is required. 
In the worst, case, it will require to do a real navigation session to generate
the appropriate whitelists.

|--{  Statistics, Reporting and so on ...  }-----------------------------------|

This is a crucial part of any WAF, and this is not done yet ! 
But the good point is that, thanks to the principle of calling an external page
 that receives all the informations about every denied request, it is fairly 
simple to write your custom <insert your favorite language here> webpage to 
take care of the statistics / reporting.


|--{  3 .. 2 .. 1 .. practice !  }---------------------------------------------|

Ok, now, let's have a look at the practice ! Let's admit we want to create a 
setup for a website. I won't cover the basics of setting up nginx as a reverse 
proxy, but rather focus on NAXSI configuration. If you have a "normal" web 
site, with no fancy URL rewritting or strange things, the default configuration
should do the work, but let's have a look at website with fancy rewritting, 
and complex user forms.


To make things easier, a good point is that we can 'fool' nginx and the OS into
 thinking that he is already the reverse proxy for the website, so that we can
setup the configuration without any risk of impacting the production servers, 
so here we go :


/etc/nginx/site-enabled/default:
-----------------------------------8<-------------------------------------------
server {
proxy_set_header Proxy-Connection "";
resolver X.Y.Z;
listen       *:80;
access_log  /tmp/nginx_access.log;
error_log  /tmp/nginx_error.log debug;

location / {
# specific site config
  LearningMode;
  SecRulesEnabled;
  DeniedUrl "/RequestDenied";

  ## check rules
  CheckRule "$SQL >= 8" BLOCK;
  CheckRule "$RFI >= 8" BLOCK;
  CheckRule "$TRAVERSAL >= 4" BLOCK;
  CheckRule "$XSS >= 8" BLOCK;
# /specific site config
  proxy_pass http://xx.xx.xx.xx;
  proxy_set_header Host "www.xxx.com";
}

location /RequestDenied {
     proxy_pass http://127.0.0.1:4242/denied_page.php;
   }
}
-----------------------------------8<-------------------------------------------


Our configuration file is extremly similar to any nginx configuration, except:
- We defined a NAXSI "per site" configuration. This is what will determine  how
  NAXSI will behave for this site.
- We define a location that will be used to redirect fobidden pages. Here, 
  I have an apache instance listening on lo:4242

The NAXSI "per location" configuration, simply defines :
- CheckRule : The maximum score for each kind of "threat"
- The "LearningMode" directive is here to make the learning easier. By default,
  NAXSI will stop processing a request as soon as it hits one of the 'BLOCK' 
  scores. With this directive, it will go through every rules, making 
  whitelist generation easier, while allowing the request to pass, even if 
  tagued as "BLOCKED", to make learning easier.

- The 'SecRulesEnabled' directives tells that NAXSI should be activated for 
  this location. In this way, you can decide to active / desactivate it easily
  for location X or Y. (For exemple, you might not want a WAF on your 
  back-office ?)
- DeniedUrl : We tell NAXSI were to redirect the user when a request is blocked.

and we need to add this line in the http section of nginx.conf :
--------------------------------8<--------------------------------------
include	   /etc/nginx/sec-rules/core.rules;
--------------------------------8<--------------------------------------
The "core.rules" file is provided with NAXSI, and contains all the "patterns".

So, here we go ! Let's start

We can now fool the OS into thinking that xxx.com is on 127.0.0.1, edit /etc/hosts. We are ready for configuration ! Fire up your favorite browser at xxx.com and start navigation. 

<roll roll>

As you should be in "learningmode", NAXSI will allow all the request, even if 
they reach a blocking score. As well as letting them pass, it will, as well, 
"forward" the request (like nginx's post_action directive) to your DeniedUrl,
as well as the original blocked URL (in headers) and the generated blocking 
details. In this way, the web backend is abble to generate the white-lists, 
and reload nginx 'on the fly' with the new generated whitelist rules ;)

The 'web' part is not written yet (I suck at html), but you can yet proceed
in a different way :


In your nginx's log file (if set as debug), you will see a lot of lines like
this one appear :
-----------------------------------8<-------------------------------------------
2011/07/11 17:12:27 [debug] 18653#0: *7 NAXSI_FMT: server=&uri=/skin/frontend/default/xxx/images/interface/fleche-grise.gif&ip=127.0.0.1&zone0=HEADERS&id0=1005&var_name0=cookie&zone1=HEADERS&id1=1008&var_name1=cookie&zone2=HEADERS&id2=1009&var_name2=cookie&zone3=HEADERS&id3=1010&var_name3=cookie&zone4=HEADERS&id4=1011&var_name4=cookie&zone5=HEADERS&id5=1308&var_name5=cookie&zone6=HEADERS&id6=1309&var_name6=cookie&zone7=HEADERS&id7=1313&var_name7=cookie
-----------------------------------8<-------------------------------------------

So, once you think you've done a reasonable crawling on your site, you can 
launch the "rules generator" [destination rules file] [nginx's log file]:
-----------------------------------8<-------------------------------------------
bui@zeroed:~$ ./rules_generator.py
RANGE for ID=1000,ZONE=URL, range=0-4
# for rule 1000, we have 4 elements in zone URL
#duplicate for id 1000, delete (4 elems)
RANGE for ID=1002,ZONE=URL, range=1-89
...
{'id': '1313', 'uri': '', 'var_name': 'cookie', 'zone': 'HEADERS'}]
-----------------------------------8<-------------------------------------------

Rules generator default output file is /tmp/RT_naxsi.tmp, and looks like :
-----------------------------------8<-------------------------------------------
bui@zeroed:/home/bui/secdev/nginx/web: cat /tmp/RT_naxsi.tmp  | grep ^Basic
BasicRule wl:1000 "mz:$URL:/skin/frontend/default/lepape/images/titre_notre_selection2.gif|URL";
BasicRule wl:1002 "mz:URL";
BasicRule wl:1008 "mz:URL";
BasicRule wl:1005 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1008 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1009 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1010 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1011 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1308 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1309 "mz:$HEADERS_VAR:cookie";
BasicRule wl:1313 "mz:$HEADERS_VAR:cookie";
-----------------------------------8<-------------------------------------------

What happened just here ?  The Rule Generator parsed nginx log file,
extracted all the "denied urls", and generated (and then factorized)
whitelist rules from your session !  If you did an exhaustive enough
crawling / browsing session, your ruleset might be complete enough and
ready for production !


|--{  Detail configuration  }--------------------------------------------------|

Here, I will go through all the directives supported by NAXSI.

|--{  Location configuration  }------------------------------------------------|

LearningMode : By default, NAXSI will stop parsing a request as soon
	     as it reaches a score that will block the request.  When
	     LearningMode is enabled, the request will be matched
	     against every possible rules. This directive should be
	     used when configuring NAXSI ONLY (a.k.a : generating
	     whitelists)

SecRulesEnabled : If the directive is not present, NAXSI will not
inspect anything.  SecRulesDisabled : If the directive is present,
NAXSI will not inspect anything.  (The two rules above are here for
easier usage in production environnment, when you want to be abble to
simply enable / disable the module)



DeniedUrl "/location" : This directive is used to tell NAXSI where the
	  	        user should be redirected when a request is
	  	        blocked.  The location should be present in
	  	        NGINX configuration for this to work, as we
	  	        are relying on nginx's internal redirect
	  	        feature.


BasicRule : The 'main' thing you should care about. This can be used,
	    either to add some whitelist, or to create some specific
	    rules for a location (might be usefull if you have super
	    crappy websites).  Here are some examples of possible
	    BasicRule syntaxes :

- BasicRule wl:1005 "mz:$URL:/bar/|$ARGS_VAR:foo" : Whitelist rule 1005 on 
  the GET "foo" arg of page /bar/
- BasicRule wl:1005 "mz:$URL:/bar/|ARGS" : Whitelist rule 1005 on the every 
  GET arg of page /bar/
- BasicRule wl:1005 : Globally disable rule 1005 on the location
- BasicRule wl:1005 "mz:HEADERS" : Whitelist rule 1005 for all HEADERS
- mz supports keywords like ARGS (global GET args), BODY (global POST args), 
  URL (url, rly), $ARGS_VAR (named GET arg), $BODY_VAR (named POST arg), 
  HEADERS (HTTP headers), $HEADERS_VAR (named header var)


CheckRule : Used to determine when the request should be blocked, for
example : CheckRule "$SQL >= 8" BLOCK : If the $SQL score is superior
or equal to 8, the request will be blocked.


|--{  Main configuration  }----------------------------------------------------|


In main configuration, a.k.a core rules, there is only one directive :

MainRule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS" "s:$SQL:8" id:1003;
This specific rule for example, will be matched against GET,POST
arguments, as well as the URL. If the '/*' string is found, the $SQL
score will be increased by 8.  Sounds pretty simple right ? But you
can as well do some tricky things !

MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADER_VAR:Content-type" "s:$SQL:42" id:1999; 
This one is a negative rule (means that the score will be applied if the rule 
DOES NOT match). This one is used to prevent strange content types on POSTs.
To litteraly translate it, it means : If a "Content-type" HTTP header is 
present, check weither it's 'application/x-www-form-urlencoded' or 
'multipart/form-data' (you noticed the rx: keyword, yes it means that it's a 
regular expression). If the content-type is different, then increase $SQL score
by 42.


