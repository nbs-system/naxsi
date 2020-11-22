#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(1);

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__

=== TEST 1: SQLI in POST body
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
	SecRulesEnabled;
	LibInjectionSql;
	LibInjectionXss;

	DeniedUrl "/RequestDenied";
	CheckRule "$SQL >= 8" BLOCK;
	CheckRule "$RFI >= 8" BLOCK;
	CheckRule "$TRAVERSAL >= 5" BLOCK;
	CheckRule "$UPLOAD >= 5" BLOCK;
	CheckRule "$XSS >= 8" BLOCK;
    return 200 '{"message": "not blocked"}';
}
location /RequestDenied {
	return 412 '{"message": "blocked"}';
}
--- raw_request eval
"POST / HTTP/1.1\r
Host: 127.0.0.1\r
Accept: */*\r
Content-Length: 28\r
Content-Type: application/x-www-form-urlencoded\r
\r
{\"a\":\"select * from table1;\"}\r
"
--- error_code: 412

=== TEST 2: SQLI in PATCH body
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
	SecRulesEnabled;
	LibInjectionSql;
	LibInjectionXss;

	DeniedUrl "/RequestDenied";
	CheckRule "$SQL >= 8" BLOCK;
	CheckRule "$RFI >= 8" BLOCK;
	CheckRule "$TRAVERSAL >= 5" BLOCK;
	CheckRule "$UPLOAD >= 5" BLOCK;
	CheckRule "$XSS >= 8" BLOCK;
    return 200 '{"message": "not blocked"}';
}
location /RequestDenied {
	return 412;
}
--- raw_request eval
"PATCH / HTTP/1.1\r
Host: 127.0.0.1\r
Accept: */*\r
Content-Length: 28\r
Content-Type: application/x-www-form-urlencoded\r
\r
{\"a\":\"select * from table1;\"}\r
"
--- error_code: 412

=== TEST 3: SQLI in PUT body
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
	SecRulesEnabled;
	LibInjectionSql;
	LibInjectionXss;

	DeniedUrl "/RequestDenied";
	CheckRule "$SQL >= 8" BLOCK;
	CheckRule "$RFI >= 8" BLOCK;
	CheckRule "$TRAVERSAL >= 5" BLOCK;
	CheckRule "$UPLOAD >= 5" BLOCK;
	CheckRule "$XSS >= 8" BLOCK;
    return 200 '{"message": "not blocked"}';
}
location /RequestDenied {
	return 412;
}
--- raw_request eval
"PUT / HTTP/1.1\r
Host: 127.0.0.1\r
Accept: */*\r
Content-Length: 43\r
Content-Type: application/x-www-form-urlencoded\r
\r
{\"a\":\"select * from table1 where aaaa = 1;\"}\r
"
--- error_code: 412

