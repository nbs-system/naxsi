#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== WL TEST 1.0: [ARGS zone WhiteList] Adding a test rule in http_config (ARGS zone) and disable rule.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 200
=== WL TEST 1.0.1: [ARGS zone WhiteList] Adding a test rule in http_config (ARGS zone) and disable rule.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?foobar=a
--- error_code: 200
=== WL TEST 1.1: Adding a test rule in http_config (ARGS zone) and WL it on arg name only.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$ARGS_VAR:a";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 200
=== WL TEST 1.2: Adding a test rule in http_config (ARGS zone) and WL it on arg name only (case sensitiveness check).
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$ARGS_VAR:AbCd";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?abcd=foobar
--- error_code: 200
=== WL TEST 1.3: Adding a test rule in http_config (ARGS zone) and WL it on arg name only (case sensitiveness check #2).
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$ARGS_VAR:abcd";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?AbCd=foobar
--- error_code: 200
=== WL TEST 1.4: Adding a test rule in http_config (ARGS zone) and WL it on $URL + ZONE.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 200
=== WL TEST 1.5: Adding a test rule in http_config (ARGS zone) and WL it on $URL + ZONE (wrong URL).
--- user_files
>>> index2
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /index2?a=foobar
--- error_code: 412
=== WL TEST 1.6: Adding a test rule in http_config (ARGS zone) and WL it on $URL + $ARG_VAR.
--- user_files
>>> index2
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/|$ARGS_VAR:AbCd";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /index2?ABCD=foobar
--- error_code: 412
=== WL TEST 2.0: Adding a rule that will match on headers
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:HEADERS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Cookie: foobar
--- request
GET /
--- error_code: 412
=== WL TEST 2.1: Adding a rule that will match on headers, WL it on $HEADERS_VAR
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:HEADERS" "s:$SQL:42" id:1999;
--- user_files
>>> another-page
ANOTHER CONTENT
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$HEADERS_VAR:cookie";
}
location /RequestDenied {
	 return 412;
}
--- more_headers
cookie: foobar
--- request
GET /another-page
--- error_code: 200
=== WL TEST 2.2: Adding a rule that will match on headers specific header name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:$HEADERS_VAR:cookie" "s:$SQL:42" id:1999;
--- user_files
>>> another-page
ANOTHER CONTENT
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
COOKIE: foobar
--- request
GET /another-page
--- error_code: 412
=== WL TEST 2.3: Adding a rule that will match on headers, WL it by $URL + zone
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:HEADERS" "s:$SQL:42" id:1999;
--- user_files
>>> another-page
ANOTHER CONTENT
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule "wl:1999" "mz:$URL:/another-page|HEADERS";
}
location /RequestDenied {
	 return 412;
}
--- more_headers
COOKIE: foobar
--- request
GET /another-page
--- error_code: 200
=== WL TEST 2.4 : Adding a rule that will match on headers, WL it by $URL + $HEADERS_VAR
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:HEADERS" "s:$SQL:42" id:1999;
--- user_files
>>> another-page
ANOTHER CONTENT
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/another-page|$HEADERS_VAR:cookie";
}
location /RequestDenied {
	 return 412;
}
--- more_headers
cookie: foobar
--- request
GET /another-page
--- error_code: 200
=== WL TEST 2.5 : Adding a rule that will match on headers, WL it by $URL + $HEADERS_VAR (WRONG URL)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:HEADERS" "s:$SQL:42" id:1999;
--- user_files
>>> another-page
ANOTHER CONTENT
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/another-page|$HEADERS_VAR:cookie";
}
location /RequestDenied {
	 return 412;
}
--- more_headers
COOKIE: foobar
--- request
GET /another-pag
--- error_code: 412
=== WL TEST 2.6 : Adding a rule that will match on headers, WL it by $URL + $HEADERS_VAR (WRONG HEADER NAME)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:HEADERS" "s:$SQL:42" id:1999;
--- user_files
>>> another-page
ANOTHER CONTENT
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/another-page|$HEADERS_VAR:cookie";
}
location /RequestDenied {
	 return 412;
}
--- more_headers
COOKI: foobar
--- request
GET /another-page
--- error_code: 412
=== URL WL TEST 3.0: Adding a test rule on ARGS (testing case sensitivness)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:bra" "msg:test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?a=BrA
--- error_code: 412
=== URL WL TEST 3.1: Adding a test rule on ARGS (testing case sensitivness #2)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:BrA" "msg:test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?a=bRa
--- error_code: 412
=== URL WL TEST 3.2: Adding a test rule on URI (testing case sensitivness #2)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:BrA" "msg:test pattern" "mz:$URL:/foobar|ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /FoObar?a=bRa
--- error_code: 412
=== WL TEST 5.0: Testing the POST content-type rule !
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-typz" "s:BLOCK" id:1402;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Typz: application/x-www-form-urlencoded
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /foobar
foo1=bar1&foo2=bar2"
--- error_code: 200
=== WL TEST 5.1: Testing the POST content-type rule #2
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:content-typz" "s:BLOCK" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
Content-Typz: application/z-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /foobar
foo1=bar1&foo2=bar2"
--- error_code: 412
=== WL TEST 5.1: Testing the POST content-type rule #3
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:content-typz" "s:BLOCK" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
cOnTeNT-TYpZ: application/x-www-form-evilencoded
--- request eval
use URI::Escape;
"POST /foobar
foo1=bar1&foo2=bar2"
--- error_code: 412
=== WL TEST 5: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong arg name.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?baron=foobar
--- error_code: 412
=== WL TEST 6: Adding a test rule in http_config (ARGS zone) and WL it.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 200
=== WL TEST 7: Adding a test rule in http_config (URL zone) and WL it on url + zone.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:URL" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|URL";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?aa
--- error_code: 200
=== WL TEST 8: Adding a test rule in http_config (URL zone).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:URL" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?aa
--- error_code: 412
=== WL TEST 8.1 : Adding a test rule in http_config (URL zone) and whitelist it with $URL:|URL.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:URL" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|URL";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?aa
--- error_code: 200
=== WL TEST 8.2 : Adding a test rule in http_config (URL zone) and whitelist it with URL and no $URL.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:URL" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:URL";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?aa
--- error_code: 200
=== WL TEST 8: Adding a test rule in http_config (ARGS zone) and WL it on url + arg name.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?barone=foobar
--- error_code: 200
=== WL TEST 9: Adding a test rule in http_config (ARGS zone) and WL it on $ARGS_VAR only.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$ARGS_VAR:barone";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?barone=foobar
--- error_code: 200
=== WL TEST 10: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong arg name.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?baron=foobar
--- error_code: 412
=== WL TEST 11: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong URL.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobarx?baron=foobar
--- error_code: 412
=== WL TEST 12: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong arg name.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?baron=foobar
--- error_code: 412
=== WL TEST 13: Whitelisting multiple rules in one WL.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1998;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=yesone&b=yestwo
--- error_code: 412
=== WL TEST 14 : Whitelist on ARG_NAME.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 BasicRule wl:1999 "mz:$ARGS_VAR:b";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?b=yestwo
--- error_code: 200
=== WL TEST 14.1 : Whitelist on ARG_NAME.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:BLOCK" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1002 "mz:ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?b=yesone
--- error_code: 412
=== WL TEST 15 : Whitelisting multiple rules in one WL.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1998;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:1999,1998;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=yesone&b=yestwo
--- error_code: 200
=== WL TEST 16 : Whitelisting all rules on one arg (wl:0).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1998;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 BasicRule wl:0 "mz:$ARGS_VAR:a";
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=yesoneyestwo
--- error_code: 200
=== WL TEST 17 : Whitelisting all rules on one arg (wl:0) NOT.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:4" id:1998;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=yesoneyestwo
--- error_code: 412

=== WL TEST 18 : Whitelisting rule id 1
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- request
POST /

--- error_code: 412
=== WL TEST 18.1 : Whitelisting internal rule
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 BasicRule wl:16 "mz:$URL:/|BODY";
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- request
POST /

--- error_code: 200
=== WL TEST 19.0 : Rule in variable name
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
MainRule id:4242 "str:123" "mz:ARGS" s:BLOCK;
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a123a=foobar
--- error_code: 412
=== WL TEST 19.1 : Rule in variable name (whitelisted)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4242 "str:123" "mz:ARGS" s:BLOCK;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
	 BasicRule wl:4242 "mz:ARGS|NAME";
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a123a=lol
--- error_code: 200
=== WL TEST 20.0 : wl:0 in cookies (#405)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4242 "str:123" "mz:$HEADERS_VAR:cookie" s:BLOCK;
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Cookie: 123
--- request
GET /
--- error_code: 412
=== WL TEST 20.1 : wl:0 in cookies (#405)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4242 "str:123" "mz:$HEADERS_VAR:cookie" s:BLOCK;
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Cookie: 124
--- request
GET /
--- error_code: 200
=== WL TEST 20.0 : wl:0 in cookies (#405)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule id:4242 "str:123" "mz:$HEADERS_VAR:cookie" s:BLOCK;
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 BasicRule wl:0 "mz:$HEADERS_VAR:cookie";
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Cookie: 123
--- request
GET /
--- error_code: 200


