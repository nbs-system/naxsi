#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;
use Env;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: Basic GET request
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
}
location /RequestDenied {
	return 412;
	# return 412;
}
--- request
GET /?a=buibui
--- error_code: 200


=== TEST 2: DENY : Obvious GET XSS
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
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a="><ScRiPt>alert(1)</scRiPt>
--- error_code: 412


=== TEST 2.1: DENY : Obvious RFI
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
	CheckRule "$RFI >= 2" BLOCK;
	CheckRule "$TRAVERSAL >= 4" BLOCK;
	CheckRule "$XSS >= 8" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=http://evil.com/eva.txt
--- error_code: 412


=== TEST 2.3: DENY : Obvious LFI
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
	CheckRule "$RFI >= 2" BLOCK;
	CheckRule "$TRAVERSAL >= 4" BLOCK;
	CheckRule "$XSS >= 8" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=../../../../../bar.txt
--- error_code: 412


=== TEST 3: OBVIOUS GET SQL INJECTION
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
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=1'+Or+'1'='1
--- error_code: 412


=== TEST 3bis: OBVIOUS (quoteless) GET SQL INJECTION
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
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=1+UnIoN+SeLeCt+1
--- error_code: 412


=== TEST 4: VERY STRANGE GET REQUEST
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
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=[]();--
--- error_code: 412


=== TEST 5: SIMPLE POST (www-form style)
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=bar1&foo2=bar2"
--- error_code: 200


=== TEST 7 : SQLi POST (www-form style)
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=' OR '1'='1"
--- error_code: 412


=== TEST 8 : XSS POST (www-form style)
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1='><script>alert(1)</script>"
--- error_code: 412


=== TEST 9: Adding a test rule in http_config (ARGS zone).
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
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=foobar
--- error_code: 412


=== TEST 10: Adding a test rule in http_config (URL zone).
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


=== TEST 11: Adding a test rule in http_config (BODY zone).
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=foobar"
--- error_code: 412


=== TEST 17: Negative RX rule on header:content-type.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 200


=== TEST 18: Negative RX rule on header:content-type (again).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- more_headers
Content-Type: application/OBSCURE_EVIL_CONTENT_TYPE
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 412


=== TEST 19: Negative RX rule on header:content-type (again & last, I promise !).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?a=buibui
--- error_code: 200


=== TEST 19.2: Negative RX rule on header:content-type (I LIED !).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- more_headers
Content-Type: ApPlIcaTiOn/x-wWw-fORm-urlEnCoDed
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 200


=== TEST 22: CUSTOM SCORE RULES !
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?a=yesone&b=yestwo
--- error_code: 412


=== TEST 23: CUSTOM SCORE RULES, bis
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	CheckRule "$TESTSCORE >= 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
}
location /RequestDenied {
	return 412;
}
--- request
GET /?a=yesone&b=yestwo
--- error_code: 412


=== TEST 24: Testing MULTIPART POSTs -- INVALID FORMAT
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 412


=== TEST 24: Testing MULTIPART POSTs
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 355
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n\r\n"
--- error_code: 200


=== TEST 25: Testing MULTIPART POSTs (NO CONTENT LEN)
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n\r\n"
--- error_code: 200


=== TEST 26: Testing MULTIPART POSTs (BAD CONTENT LEN)
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 42
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412


=== TEST 26.1: Testing MULTIPART POSTs (BAD CONTENT LEN)
#nginx changed his way, no data is cut to content lenght header, so this test is obsolete
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 42
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMy<aaaaa>Name\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\ny<alert>es\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412


=== TEST 27: Obvious POST XSS (multipart)
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\naz\"><script>alert(1)</script>\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412


=== TEST 28: Obvious POST SQLi (multipart)
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\naz\" OR \"1\"=\"1\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412


=== TEST 29: Malformed POST / BoF try #1 (missing some boundaries)
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nNaaaaaa\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412


=== TEST 30 : Malformed POST / BoF try #3 (random overflow trigger n1)
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
	CheckRule "$TESTSCORE > 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nazzzo\r\n\r\n\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n-----------------------------103832778631715--\r\n"
--- error_code: 200


=== TEST 31: enc0ding phun ?
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=ba%%2f%3c%3D%3%D%33%DD%FF%2F%3cr1&foo2=bar2"
--- error_code: 412


=== TEST 32: fucked up URLs #1
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?a&&z=yesone&&
--- error_code: 412


=== TEST 33: fucked up URLs #2
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?z=&yesone
--- error_code: 412


=== TEST 33: fucked up URLs #2bis
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?z=&==yesone&&&
--- error_code: 412


=== TEST 33: fucked up URLs #2ter
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?==yesone&&&
--- error_code: 412


=== TEST 33: fucked up URLs #3
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?z=&AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbuiyesone&&
--- error_code: 412


=== TEST 33: fucked up URLs #4
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
	return 412;
}
--- request
GET /?z=&%00yesone
--- error_code: 412


=== TEST 33: fucked up URLs #4
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
#MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
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
	return 412;
}
--- request
GET /?z=&y%00esone
--- error_code: 412


=== TEST 34: pushing in ARGS only
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
	CheckRule "$TESTSCORE >= 42" BLOCK;
	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
}
location /RequestDenied {
	return 412;
}
--- request
GET /?z=&yesone
--- error_code: 412


=== TEST 34.1: pushing in ARGS only
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	BasicRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:BLOCK" id:1999;
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
	return 412;
}
--- request
GET /?z=&yesone
--- error_code: 412


=== TEST 35: pushing in ARGS + uri only
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	BasicRule "str:yesone" "msg:foobar test pattern" "mz:ARGS|$URL:/z" "s:BLOCK" id:1999;
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
	return 412;
}
--- request
GET /z?z=&yesone
--- error_code: 412


=== TEST 36: pushing uri rules
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	BasicRule "str:yesone" "msg:foobar test pattern" "mz:ARGS|$URL:/z" "s:BLOCK" id:1999;
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
	return 412;
}
--- request
GET /z?&yesone=a
--- error_code: 412


=== TEST 37: pushing uri malformed rules
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	BasicRule "str:yesone" "msg:foobar test pattern" "mz:ARGS|$URL:/z" "s:BLOCK" id:1999;
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
	return 412;
}
--- request
GET /z?&yesonea
--- error_code: 412


=== TEST 37: multipart, MainRule BODY|FILE_EXT blocked
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "id:4241" "s:DROP" "str:matchme" "mz:BODY|FILE_EXT";
--- config
location / {
	 #LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 CheckRule "$UPLOAD >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- raw_request eval
"POST /foobar HTTP/1.1\r
Host: 127.0.0.1\r
Connection: Close\r
User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r
Accept-Language: en-us,en;q=0.5\r
Accept-Encoding: gzip, deflate\r
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r
Referer: http://127.0.0.1/\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 38\r
\r
txtName=matchme&btnSign=Sign+Guestbook\r
"
--- error_code: 412


=== TEST 37: multipart, BasicRule BODY|FILE_EXT blocked
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
	 CheckRule "$UPLOAD >= 8" BLOCK;
	 BasicRule "id:4241" "s:DROP" "str:matchme" "mz:BODY|FILE_EXT";


	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- raw_request eval
"POST /foobar HTTP/1.1\r
Host: 127.0.0.1\r
Connection: Close\r
User-Agent: Mozilla/5.0 (iPad; U; CPU OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B334b Safari/531.21.10\r
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r
Accept-Language: en-us,en;q=0.5\r
Accept-Encoding: gzip, deflate\r
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r
Referer: http://127.0.0.1/\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 38\r
\r
txtName=matchme&btnSign=Sign+Guestbook\r
"
--- error_code: 412

=== TEST 38: SIMPLE PATCH (www-form style)
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"PATCH /
foo1=bar1&foo2=bar2"
--- error_code: 200

=== TEST 39 : SQLi PATCH (www-form style)
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"PATCH /
foo1=' OR '1'='1"
--- error_code: 412

=== TEST 40 : XSS PATCH (www-form style)
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
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"PATCH /
foo1='><script>alert(1)</script>"
--- error_code: 412
