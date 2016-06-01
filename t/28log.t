#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);
log_level('debug');
plan tests => repeat_each(1) * blocks();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1.1 : learning + block score, NAXSI_FMT
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:foobar" "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
location /xx {
         SecRulesEnabled;
	 LearningMode;
         DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /xx?uuu=bfoobarc
--- error_log
['.*NAXSI_FMT: .*']
--- error_code: 404




