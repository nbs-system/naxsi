#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

#repeat_each(3);

plan tests => repeat_each(1) * 2 * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1: Basic GET request
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
GET /?a=buibui
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"


=== TEST 2: DENY : Obvious GET XSS
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
GET /?a="><ScRiPt>alert(1)</scRiPt>
--- response_body eval
"FORBIDDEN.#
"
=== TEST 2.1: DENY : Obvious RFI
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 2" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=http://evil.com/eva.txt
--- response_body eval
"FORBIDDEN.#
"
=== TEST 2.3: DENY : Obvious LFI
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 2" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=../../../../../bar.txt
--- response_body eval
"FORBIDDEN.#
"
=== TEST 3: OBVIOUS GET SQL INJECTION
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
GET /?a=1'+Or+'1'='1
--- response_body eval
"FORBIDDEN.#
"
=== TEST 3bis: OBVIOUS (quoteless) GET SQL INJECTION
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
GET /?a=1+UnIoN+SeLeCt+1
--- response_body eval
"FORBIDDEN.#
"

=== TEST 4: VERY STRANGE GET REQUEST
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
GET /?a=[]();--
--- response_body eval
"FORBIDDEN.#
"
=== TEST 5: SIMPLE POST (www-form style)
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
--- request eval
use URI::Escape;
"POST /
foo1=bar1&foo2=bar2"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== TEST 7 : SQLi POST (www-form style)
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
--- request eval
use URI::Escape;
"POST /
foo1=' OR '1'='1"
--- response_body eval
"FORBIDDEN.#
"
=== TEST 8 : XSS POST (www-form style)
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
--- request eval
use URI::Escape;
"POST /
foo1='><script>alert(1)</script>"
--- response_body eval
"FORBIDDEN.#
"
=== TEST 9: Adding a test rule in http_config (ARGS zone).
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
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?a=foobar
--- response_body eval
"FORBIDDEN.#
"
=== TEST 10: Adding a test rule in http_config (URL zone).
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
=== TEST 11: Adding a test rule in http_config (BODY zone).
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=foobar"
--- response_body eval
"FORBIDDEN.#
"

=== TEST 17: Negative RX rule on header:content-type.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== TEST 17: Negative RX rule on header:content-type.
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== TEST 18: Negative RX rule on header:content-type (again).
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
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
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: application/OBSCURE_EVIL_CONTENT_TYPE
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- response_body eval
"FORBIDDEN.#
"

=== TEST 19: Negative RX rule on header:content-type (again & last, I promise !).
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
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
GET /?a=buibui
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"
=== TEST 19.2: Negative RX rule on header:content-type (I LIED !).
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
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
Content-Type: ApPlIcaTiOn/x-wWw-fORm-urlEnCoDed
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"



=== TEST 22: CUSTOM SCORE RULES !
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:1999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:1998;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
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

=== TEST 23: CUSTOM SCORE RULES, bis
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:2999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:2998;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
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



=== TEST 24: Testing MULTIPART POSTs -- INVALID FORMAT
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- response_body eval
"FORBIDDEN.#
"


=== TEST 24: Testing MULTIPART POSTs
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 355
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"





=== TEST 25: Testing MULTIPART POSTs (NO CONTENT LEN)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"




=== TEST 26: Testing MULTIPART POSTs (BAD CONTENT LEN)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 42
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"FORBIDDEN.#
"


=== TEST 27: Obvious POST XSS (multipart)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\naz\"><script>alert(1)</script>\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"FORBIDDEN.#
"

=== TEST 28: Obvious POST SQLi (multipart)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\naz\" OR \"1\"=\"1\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"FORBIDDEN.#
"

=== TEST 29: Malformed POST / BoF try #1 (missing some boundaries)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nNaaaaaa\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"FORBIDDEN.#
"
=== TEST 30 : Malformed POST / BoF try #3 (random overflow trigger n1)
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nazzzo\r\n\r\n\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n-----------------------------103832778631715--\r\n"
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"

=== TEST 31: enc0ding phun ?
--- http_config
include /etc/nginx/sec-rules/core.rules;
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
--- request eval
use URI::Escape;
"POST /
foo1=ba%%2f%3c%3D%3%D%33%DD%FF%2F%3cr1&foo2=bar2"
--- response_body eval
"FORBIDDEN.#
"

=== TEST 32: fucked up URLs #1
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?a&&z=yesone&&
--- response_body eval
"FORBIDDEN.#
"


=== TEST 33: fucked up URLs #2
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?z=&yesone
--- response_body eval
"FORBIDDEN.#
"
=== TEST 33: fucked up URLs #2bis
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?z=&==yesone&&&
--- response_body eval
"FORBIDDEN.#
"
=== TEST 33: fucked up URLs #2ter
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?==yesone&&&
--- response_body eval
"FORBIDDEN.#
"

=== TEST 33: fucked up URLs #3
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?z=&AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbuiyesone&&
--- response_body eval
"FORBIDDEN.#
"
=== TEST 33: fucked up URLs #4
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?z=&%00yesone
--- response_body eval
"FORBIDDEN.#
"


=== TEST 33: fucked up URLs #4
--- user_files
>>> foobar
eh yo
--- http_config
include /etc/nginx/sec-rules/core.rules;
MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 echo "FORBIDDEN.#";
}
--- request
GET /?z=&y%00esone
--- response_body eval
"<html><head><title>It works!</title></head><body>It works!</body></html>"



