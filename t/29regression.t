#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(2) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== WL TEST 1.0: [ARGS zone WhiteList] Adding a test rule in http_config (ARGS zone) and disable rule.
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- http_config
include /tmp/naxsi_ut/naxsi_core.rules;
--- config
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?driveOnDate=2016-11-29
--- error_code: 200

