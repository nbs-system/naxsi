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
=== TEST 1: IgnoreIP defined
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP  "1.1.1.1";
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

=== TEST 1.1: IgnoreIP request 
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP  "1.1.1.1";
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

=== TEST 1.2: IgnoreIP request with X-Forwarded-For allow (ipv4) 
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP  "1.1.1.1";
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
--- more_headers
X-Forwarded-For: 1.1.1.1
--- request
GET /?a=buibui
--- error_code: 200

=== TEST 1.3: IgnoreIP request with X-Forwarded-For allow (ipv6)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP "2001:4860:4860::8844";
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
--- more_headers
X-Forwarded-For: 2001:4860:4860::8844
--- request
GET /?a=buibui
--- error_code: 200

=== TEST 1.4: IgnoreIP request with X-Forwarded-For deny (ipv4)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP  "1.1.1.1";
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
--- more_headers
X-Forwarded-For: 2.2.2.2
--- request
GET /?a=<>
--- error_code: 412

=== TEST 1.5: IgnoreIP request with X-Forwarded-For deny (ipv6)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP "2001:4860:4860::8844";
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
--- more_headers
X-Forwarded-For: 2001:4860:4860::8888
--- request
GET /?a=<>
--- error_code: 412

=== TEST 1.6: Multiple IgnoreIP defined
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP  "1.1.1.1";
     IgnoreIP  "1.2.3.4";
     IgnoreIP  "2.3.4.1";
     IgnoreIP  "2606:4700:4700::1111";
     IgnoreIP  "2606:4700:4700::1001";
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

=== TEST 1.7: Verify IgnoreIP (IPv4) works
--- user_files
>>> foobar
foobar text
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
MainRule "str:/foobar" "mz:URL" "s:$TRAVERSAL:4" id:123456;
--- config
location / {
     SecRulesEnabled;
     IgnoreIP  "127.0.0.1";
     #IgnoreIP  "2606:4700:4700::1001"; # IPv6 can't be tested.
     DeniedUrl "/RequestDenied";
     CheckRule "$TRAVERSAL >= 4" BLOCK;
     root $TEST_NGINX_SERVROOT/html/;
     index index.html index.htm;
}
location /RequestDenied {
     return 412;
}
--- request
GET /foobar
--- error_code: 200
