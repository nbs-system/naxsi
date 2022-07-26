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
=== Load All Rules
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
include $TEST_NGINX_NAXSI_BLOCKING_RULES/*;
--- config
location / {
    include $TEST_NGINX_NAXSI_WHITELISTS_RULES/*;
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
--- request eval
"GET /"
--- error_code: 200


=== Whitelist robots.txt
--- user_files
>>> robots.txt
User-agent: *
Allow: /
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
include $TEST_NGINX_NAXSI_BLOCKING_RULES/*;
MainRule wl:20000003 "mz:$URL:/robots.txt|URL";
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
--- request eval
"GET /"
--- error_code: 200

