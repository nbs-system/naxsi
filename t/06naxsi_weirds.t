#vi:filetype=perl


use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== WL TEST 1.0: weird request in URL
--- http_config
include /etc/nginx/naxsi_core.rules;
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
--- request
GET /?&&&&a&&&&&
--- error_code: 412

=== WL TEST 1.01: weird request in URL (wl on fullzone)
--- http_config
include /etc/nginx/naxsi_core.rules;
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
	 BasicRule wl:1 "mz:ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?&&&&a&&&&&
--- error_code: 200

=== WL TEST 1.02: weird request in URL (wl on zone+URL)
--- http_config
include /etc/nginx/naxsi_core.rules;
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
	 BasicRule wl:1 "mz:$URL:/|ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?&&&&a&&&&&
--- error_code: 200

=== WL TEST 1.03: weird request in URL (fail wl on zone+bad URL)
--- http_config
include /etc/nginx/naxsi_core.rules;
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
	 BasicRule wl:1 "mz:$URL:/a|ARGS";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?&&&&a&&&&&
--- error_code: 412

=== WL TEST 1.04: weird request in URL (fail wl on bad zone+URL)
--- http_config
include /etc/nginx/naxsi_core.rules;
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
	 BasicRule wl:1 "mz:$URL:/|URL";
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?&&&&a&&&&&
--- error_code: 412
