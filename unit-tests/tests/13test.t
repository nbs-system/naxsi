#vi:filetype=perl
# This File is used for broken tests.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(4) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__

=== TEST: 1 UnioN SeLEct 1
--- main_config
working_directory /tmp/;
worker_rlimit_core 25M;
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
--- raw_request eval
"GET /?a=1%20UnioN%20SeLEct%201 HTTP/1.0

"
--- error_code: 412


