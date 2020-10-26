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
=== TEST 1: IgnoreCIDR defined (no file)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreCIDR "1.1.1.0/24";
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

=== TEST 1.1: IgnoreCIDR request (no file)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreCIDR "1.1.1.0/24";
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

=== TEST 1.2: IgnoreCIDR request with X-Forwarded-For allow (no file) 
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreCIDR "1.1.1.0/24";
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

=== TEST 1.3: IgnoreCIDR request with X-Forwarded-For deny (no file)
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
     SecRulesEnabled;
     IgnoreCIDR "1.1.1.0/24";
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

=== TEST 1.4: Verify IgnoreCIDR works
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
     IgnoreCIDR  "127.0.0.0/24";
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


=== TEST 1.5: Verify IgnoreCIDR x.x.x.x./32 is converted to IgnoreIP
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
     IgnoreCIDR  "127.0.0.1/32";
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


