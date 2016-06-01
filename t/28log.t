#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(2);
log_level('debug');
plan tests => repeat_each(1) * blocks();
no_root_location();
#no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1.1 : learning + block score, NAXSI_FMT
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
MainRule "str:x" "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
--- config
location /x {
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
GET /x/?uuu=bxcxd
--- no_error_log eval
['NAXSI_FMT: ']
--- error_code: 404

