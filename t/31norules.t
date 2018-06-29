#vi:filetype=perl


# A AJOUTER :
# TEST CASE AVEC UNE REGLE SUR UN HEADER GENERIQUE
# La même sur des arguments :)

use lib 'lib';
use Test::Nginx::Socket;

repeat_each(3);

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1: Basic GET request with no rules, drop
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- config
location / {
	 SecRulesEnabled;
	 LearningMode;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 LibInjectionXss;
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
	 LibInjectionSql;
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=buibui
--- error_code: 412
=== TEST 1.1: Basic GET request with no rules, whitelist the special rule.
--- main_config
load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;
--- config
location / {
	 SecRulesEnabled;
	 BasicRule wl:19;
	 LearningMode;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 CheckRule "$RFI >= 8" BLOCK;
	 CheckRule "$TRAVERSAL >= 4" BLOCK;
	 CheckRule "$XSS >= 8" BLOCK;
	 LibInjectionXss;
	 CheckRule "$LIBINJECTION_XSS >= 8" BLOCK;
	 LibInjectionSql;
	 CheckRule "$LIBINJECTION_SQL >= 8" BLOCK;

  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=buibui
--- error_code: 200
