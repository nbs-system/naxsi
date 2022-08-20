#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 2.0: utf8 overlong
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
	CheckRule "$TEST_LOG >= 8" DROP;
  	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
	# return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
--- request eval
use URI::Escape;
"POST /
ww=%2F%C0%AE%2E%2F&foo2=bar2"
--- error_code: 412

=== TEST 2.1: utf8 overlong
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
	CheckRule "$TEST_LOG >= 8" DROP;
  	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
	# return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
--- request eval
use URI::Escape;
"POST /
ww=%c0%80"
--- error_code: 412

=== TEST 2.2: valid utf8
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
	CheckRule "$TEST_LOG >= 8" DROP;
  	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
	# return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
--- request eval
use URI::Escape;
"POST /
ww=%61%73%64%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%71%c3%b9%c3%b9%c3%b9%c3%a2%c3%a2"
--- error_code: 200

=== TEST 2.3: valid utf8
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
	CheckRule "$TEST_LOG >= 8" DROP;
  	root $TEST_NGINX_SERVROOT/html/;
	index index.html index.htm;
	error_page 405 = $uri;
}
location /RequestDenied {
	return 412;
	# return 412;
}
--- raw_request eval
"POST /index.html HTTP/1.1\r
Host: 127.0.0.1\r
Connection: Close\r
Content-Type: application/json\r
Content-Length: 69\r
\r
{\"BANK_NAME\":\"建设银行\",\"NAME\":\"山西测试有限责任公司\"}
"
--- error_code: 200
