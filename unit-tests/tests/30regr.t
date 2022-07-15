#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1: rule target body|name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 SecRulesEnabled;
	 LearningMode;
	 BasicRule id:100054 "msg:Weird binary content" "rx:[^-0-9a-z_+.\[\]]" "mz:BODY|NAME" "s:$TEST_LOG:8";
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
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
9p7jslna,ire(ul\)v`2q8u]h)bfuzpcgsa_3`s\twfw)gy)\%3Fc=]@&foo2=bar2"
--- error_code: 412

=== TEST 1: rule target body|name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 SecRulesEnabled;
	 LearningMode;
	 BasicRule id:100054 "msg:Weird binary content" "rx:[^-0-9a-z_+.\[\]]" "mz:BODY|NAME" "s:$TEST_LOG:8";
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
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
9p7jslna,ire(ul\)v`2q8u]h)bfuzpcgsa_3`s\twfw)gy)\%3Fc=ww&foo2=bar2"
--- error_code: 412


=== TEST 1: rule target body|name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 SecRulesEnabled;
	 LearningMode;
	 BasicRule id:100054 "msg:Weird binary content" "rx:[^-0-9a-z_+.\[\]]" "mz:BODY|NAME" "s:$TEST_LOG:8";
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
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
ww=9p7jslna,ire(ul\)v`2q8u]h)bfuzpcgsa_3`s\twfw)gy)\%3Fc&foo2=bar2"
--- error_code: 200





