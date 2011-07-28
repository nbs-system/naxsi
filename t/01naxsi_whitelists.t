#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(3);

plan tests => repeat_each(2) * 2 * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
####################################
# ARGS ZONE WHITELIST TESTS :   
# - WL on full zone
# - WL on arg name only
# - WL on URL + zone
# - WL on URL + arg name
# - Case sensitiveness tests
# - ??
####################################
=== WL TEST 1.0: [ARGS zone WhiteList] Adding a test rule in http_config (ARGS zone) and disable rule.
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=foobar
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== WL TEST 1.1: Adding a test rule in http_config (ARGS zone) and WL it on arg name only.
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=foobar
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== WL TEST 1.2: Adding a test rule in http_config (ARGS zone) and WL it on arg name only (case sensitiveness check).
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?abcd=foobar
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== WL TEST 1.3: Adding a test rule in http_config (ARGS zone) and WL it on arg name only (case sensitiveness check #2).
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?AbCd=foobar
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"


=== WL TEST 1.4: Adding a test rule in http_config (ARGS zone) and WL it on $URL + ZONE.
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=foobar
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== WL TEST 1.5: Adding a test rule in http_config (ARGS zone) and WL it on $URL + ZONE (wrong URL).
--- user_files
>>> index2
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /index2?a=foobar
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 1.6: Adding a test rule in http_config (ARGS zone) and WL it on $URL + $ARG_VAR.
--- user_files
>>> index2
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /index2?ABCD=foobar
--- response_body eval
"FORBIDDEN.#
"

####################################
# HEADERS ZONE WHITELIST TESTS :   
# - WL on full zone
# - WL on arg name only
# - WL on URL + zone
# - WL on URL + arg name
# - Case sensitiveness tests
# - ??
####################################
=== WL TEST 2.0: Adding a rule that will match on headers
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
Cookie: foobar
--- request
GET /
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 2.1: Adding a rule that will match on headers, WL it on $HEADERS_VAR
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
Cookie: foobar
--- request
GET /another-page
--- response_body eval
"ANOTHER CONTENT
"

=== WL TEST 2.2: Adding a rule that will match on headers specific header name
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
COOKIE: foobar
--- request
GET /another-page
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 2.3: Adding a rule that will match on headers, WL it by $URL + zone
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
COOKIE: foobar
--- request
GET /another-page
--- response_body eval
"ANOTHER CONTENT
"

=== WL TEST 2.4 : Adding a rule that will match on headers, WL it by $URL + $HEADERS_VAR
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
COOKIE: foobar
--- request
GET /another-page
--- response_body eval
"ANOTHER CONTENT
"
=== WL TEST 2.5 : Adding a rule that will match on headers, WL it by $URL + $HEADERS_VAR (WRONG URL)
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
COOKIE: foobar
--- request
GET /another-pag
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 2.6 : Adding a rule that will match on headers, WL it by $URL + $HEADERS_VAR (WRONG HEADER NAME)
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
COOKI: foobar
--- request
GET /another-page
--- response_body eval
"FORBIDDEN.#
"
#############################
## Test de WL sur les URLs
#############################
=== URL WL TEST 3.0: Adding a test rule on ARGS (testing case sensitivness)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?a=BrA
--- response_body eval
"FORBIDDEN.#
"

=== URL WL TEST 3.1: Adding a test rule on ARGS (testing case sensitivness #2)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?a=bRa
--- response_body eval
"FORBIDDEN.#
"

=== URL WL TEST 3.2: Adding a test rule on URI (testing case sensitivness #2)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /FoObar?a=bRa
--- response_body eval
"FORBIDDEN.#
"

############################
## Other tests ?
## - Add tests on BODY
##
##
=== WL TEST 5.0: Testing the POST content-type rule !
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." \
"mz:$HEADERS_VAR:Content-typz" "s:BLOCK" id:1402;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
Content-Typz: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /foobar
foo1=bar1&foo2=bar2"
--- response_body eval
"eh yo
"
=== WL TEST 5.1: Testing the POST content-type rule #2
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
Content-Typz: application/z-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /foobar
foo1=bar1&foo2=bar2"
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 5.1: Testing the POST content-type rule #3
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
cOnTeNT-TYpZ: application/x-www-form-evilencoded
--- request eval
use URI::Escape;
"POST /foobar
foo1=bar1&foo2=bar2"
--- response_body eval
"FORBIDDEN.#
"

=== WL TEST 5: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong arg name.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?baron=foobar
--- response_body eval
"FORBIDDEN.#
"

=== WL TEST 6: Adding a test rule in http_config (ARGS zone) and WL it.
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=foobar
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== WL TEST 7: Adding a test rule in http_config (URL zone) and WL it on url + zone.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?aa
--- response_body eval
"eh yo
"

=== WL TEST 8: Adding a test rule in http_config (URL zone).
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?aa
--- response_body eval
"FORBIDDEN.#
"

=== WL TEST 8.1 : Adding a test rule in http_config (URL zone) and whitelist it with $URL:|URL.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?aa
--- response_body eval
"eh yo
"

=== WL TEST 8.2 : Adding a test rule in http_config (URL zone) and whitelist it with URL and no $URL.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?aa
--- response_body eval
"eh yo
"


=== WL TEST 8: Adding a test rule in http_config (ARGS zone) and WL it on url + arg name.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?barone=foobar
--- response_body eval
"eh yo
"


=== WL TEST 9: Adding a test rule in http_config (ARGS zone) and WL it on $ARGS_VAR only.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?barone=foobar
--- response_body eval
"eh yo
"


=== WL TEST 10: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong arg name.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?baron=foobar
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 11: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong URL.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobarx?baron=foobar
--- response_body eval
"FORBIDDEN.#
"

=== WL TEST 12: Adding a test rule in http_config (ARGS zone) and WL it on url + wrong arg name.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /foobar?baron=foobar
--- response_body eval
"FORBIDDEN.#
"

=== WL TEST 13: Whitelisting multiple rules in one WL.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=yesone&b=yestwo
--- response_body eval
"FORBIDDEN.#
"
=== WL TEST 14 : Whitelist on ARG_NAME.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?b=yestwo
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"
=== WL TEST 14.1 : Whitelist on ARG_NAME.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?b=yesone
--- response_body eval
"FORBIDDEN.#
"

=== WL TEST 15 : Whitelisting multiple rules in one WL.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=yesone&b=yestwo
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

