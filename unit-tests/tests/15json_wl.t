#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== json wl 0.1 : no rulematch
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : \"bar\"
}
"
--- error_code: 200
=== json wl 0.2 : rulematch
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : \"foobar\"
}
"
--- error_code: 412
=== json wl 0.3 : rulematch + wl on full zone
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 BasicRule wl:1999 "mz:BODY";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : \"foobar\"
}
"
--- error_code: 200
=== json wl 0.4 : rulematch + wl on zone + varname
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 BasicRule wl:1999 "mz:$BODY_VAR:lol";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : \"foobar\"
}
"
--- error_code: 200

=== json wl 0.5 : rulematch + wl on zone + varname + url
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 BasicRule wl:1999 "mz:$BODY_VAR:lol|$URL:/test_uri";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
 \"lol\" : \"foobar\"
}
"
--- error_code: 200

=== json wl 0.6 : rulematch + wl on zone + varname + url [fail]
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 BasicRule wl:1999 "mz:$BODY_VAR:lol|$URL:/test_uri";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : \"foobar\"
}
"
--- error_code: 412

=== json wl 0.7 : rulematch + wl on zone + varname (in sub-json element)
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 BasicRule wl:1999 "mz:$BODY_VAR:test_123|$URL:/test_uri";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
  \"oh\" : [\"there\", \"is\", \"no\", \"way\"],
  \"this\" : { \"will\" : [\"work\", \"does\"],
  \"it\" : \"??\" },
  \"trigger\" : {\"test_123\" : [\"foobar\", \"will\", \"trigger\", \"it\"]},
  \"foo\" : \"baar\"
}
"
--- error_code: 200

=== json wl 0.8 : rulematch + wl on zone + varname (in sub-json element) [fail]
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 BasicRule wl:1999 "mz:$BODY_VAR:test_123|$URL:/test_uri";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
  \"oh\" : [\"there\", \"is\", \"no\", \"way\"],
  \"this\" : { \"will\" : [\"work\", \"does\"],
  \"it\" : \"??\" },
  \"trigger\" : {\"test_1234\" : [\"foobar\", \"will\", \"trigger\", \"it\"]},
  \"foo\" : \"baar\"
}
"
--- error_code: 412
=== json wl 0.9 : match in varname
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
  \"oh\" : [\"there\", \"is\", \"no\", \"way\"],
  \"this\" : { \"will\" : [\"work\", \"does\"],
  \"it\" : \"??\" },
  \"tr<igger\" : {\"test_1234\" : [\"foobar\", \"will\", \"trigger\", \"it\"]},
  \"foo\" : \"baar\"
}
"
--- error_code: 412
=== json wl 1.0 : match in varname + wl on varname
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 BasicRule wl:1302 "mz:$BODY_VAR:tr<igger|NAME";
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
  \"oh\" : [\"there\", \"is\", \"no\", \"way\"],
  \"this\" : { \"will\" : [\"work\", \"does\"],
  \"it\" : \"??\" },
  \"tr<igger\" : {\"test_1234\" : [\"foobar\", \"will\", \"trigger\", \"it\"]},
  \"foo\" : \"baar\"
}
"
--- error_code: 200
=== json wl 1.1 : match (empty variable name)
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
  \"\" : [\"there\", \"is\", \"no\", \"way\"]
}
"
--- error_code: 200
=== json wl 1.1 : match (no variable name)
--- user_files
>>> test_uri
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /test_uri
{
  [\"there\", \"is\", \"no\", \"way\"]
}
"
--- error_code: 200
=== json wl 2.0 : malformed json (missing opening {)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /

 \"lol\" : \"bar\"
}
"
--- error_code: 412
=== json wl 2.1 : Numeric content json
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : 372
}
"
--- error_code: 200
=== json wl 2.2 : true/false content json
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : false,
 \"serious_stuff\" : true,
 \"extra_coverage\" : null
}
"
--- error_code: 200

=== json wl 2.3 : malformed json
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"lol\" : false,
 \"serious_stuff\" : true,
 \"extra_coverage\" : null
"
--- error_code: 412


