#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;


plan tests => 2 * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
$ENV{TEST_NGINX_MAIN_CONF} = "load_module /tmp/naxsi_ut/modules/ngx_http_naxsi_module.so;";
$ENV{TEST_NGINX_HTTP_CONF} = "include /tmp/naxsi_ut/naxsi_core.rules;";
$ENV{TEST_NGINX_CONF} = <<_EOC_;
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "\$SQL >= 8" BLOCK;
	 CheckRule "\$RFI >= 8" BLOCK;
	 CheckRule "\$TRAVERSAL >= 4" BLOCK;
	 CheckRule "\$XSS >= 8" BLOCK;
	 return 200 \$naxsi_attack_family;
}
location /RequestDenied {
	 return 412 \$naxsi_attack_family;
}
_EOC_

run_tests();


__DATA__


=== TEST 1: Basic GET request
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
$TEST_NGINX_CONF
--- request
GET /
--- error_code: 200
--- response_body:


=== TEST 2: One tag
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
$TEST_NGINX_CONF
--- request
GET /?a=--select
--- error_code: 412
--- response_body: $SQL


=== TEST 2: Two tags
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
$TEST_NGINX_CONF
--- request
GET /?a=--[]
--- error_code: 412
--- response_body: $SQL,$XSS


=== TEST 3: Others tag
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
$TEST_NGINX_CONF
--- request
POST /
--- error_code: 412
--- response_body: $OTHERS


=== TEST 4: Custom tag
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
MainRule "str:abc" "msg:foobar test pattern" "mz:ARGS" "s:$XYZ:5" id:2000;
MainRule "str:xyz" "msg:foobar test pattern" "mz:ARGS" "s:$XYZ:5" id:2001;
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$XYZ >= 5" BLOCK;
	 return 200 $naxsi_attack_family;
}
location /RequestDenied {
	 return 412 $naxsi_attack_family;
}
--- request
GET /?a=abc&b=xyz
--- error_code: 412
--- response_body: $XYZ

=== TEST 5: Learning mode Pass
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
	 LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 return 200 $naxsi_attack_action;
}
location /RequestDenied {
	 return 412 $naxsi_attack_action;
}
--- request
GET /
--- error_code: 200
--- response_body: $LEARNING-PASS

=== TEST 6: Learning mode Block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
	 LearningMode;
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 return 200 $naxsi_attack_action;
}
location /RequestDenied {
	 return 412 $naxsi_attack_action;
}
--- request
GET /?a=--select
--- error_code: 200
--- response_body: $LEARNING-BLOCK

=== TEST 7: Pass
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 return 200 $naxsi_attack_action;
}
location /RequestDenied {
	 return 412 $naxsi_attack_action;
}
--- request
GET /
--- error_code: 200
--- response_body: $PASS

=== TEST 8: Block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
	 SecRulesEnabled;
	 DeniedUrl "/RequestDenied";
	 CheckRule "$SQL >= 8" BLOCK;
	 return 200 $naxsi_attack_action;
}
location /RequestDenied {
	 return 412 $naxsi_attack_action;
}
--- request
GET /?a=--select
--- error_code: 412
--- response_body: $BLOCK

=== TEST 9: Both variables - Block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
        SecRulesEnabled;
        DeniedUrl "/RequestDenied";
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$RFI >= 8" BLOCK;
        CheckRule "$TRAVERSAL >= 4" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
        return 200 "[$naxsi_attack_family - $naxsi_attack_action]";
}
location /RequestDenied {
        return 412 "[$naxsi_attack_family - $naxsi_attack_action]";
}
--- request
GET /?a=--select
--- error_code: 412
--- response_body: [$SQL - $BLOCK]

=== TEST 10: Both variables - Learning (would) Block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
        LearningMode;
        SecRulesEnabled;
        DeniedUrl "/RequestDenied";
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$RFI >= 8" BLOCK;
        CheckRule "$TRAVERSAL >= 4" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
        return 200 "[$naxsi_attack_family - $naxsi_attack_action]";
}
location /RequestDenied {
        return 412 "[$naxsi_attack_family - $naxsi_attack_action]";
}
--- request
GET /?a=--select
--- error_code: 200
--- response_body: [$SQL - $LEARNING-BLOCK]

=== TEST 11: Both variables - Pass
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
        SecRulesEnabled;
        DeniedUrl "/RequestDenied";
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$RFI >= 8" BLOCK;
        CheckRule "$TRAVERSAL >= 4" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
        return 200 "[$naxsi_attack_family - $naxsi_attack_action]";
}
location /RequestDenied {
        return 412 "[$naxsi_attack_family - $naxsi_attack_action]";
}
--- request
GET /
--- error_code: 200
--- response_body: [ - $PASS]

=== TEST 12: Both variables - Learning Pass
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
        LearningMode;
        SecRulesEnabled;
        DeniedUrl "/RequestDenied";
        CheckRule "$SQL >= 8" BLOCK;
        CheckRule "$RFI >= 8" BLOCK;
        CheckRule "$TRAVERSAL >= 4" BLOCK;
        CheckRule "$XSS >= 8" BLOCK;
        return 200 "[$naxsi_attack_family - $naxsi_attack_action]";
}
location /RequestDenied {
        return 412 "[$naxsi_attack_family - $naxsi_attack_action]";
}
--- request
GET /
--- error_code: 200
--- response_body: [ - $LEARNING-PASS]

=== TEST 13.1: Vars - naxsi_server, naxsi_uri, naxsi_learning, naxsi_block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    LearningMode;
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    return 200 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
location /RequestDenied {
    return 412 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
--- request
GET /bla
--- error_code: 200
--- response_body: localhost /bla 1 0

=== TEST 13.2: Vars - naxsi_server, naxsi_uri, naxsi_learning, naxsi_block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    LearningMode;
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    return 200 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
location /RequestDenied {
    return 412 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
--- request
GET /bla?a=--select
--- error_code: 200
--- response_body: localhost /bla 1 1

=== TEST 13.3: Vars - naxsi_server, naxsi_uri, naxsi_learning, naxsi_block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    return 200 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
location /RequestDenied {
    return 412 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
--- request
GET /bla
--- error_code: 200
--- response_body: localhost /bla 0 0

=== TEST 13.4: Vars - naxsi_server, naxsi_uri, naxsi_learning, naxsi_block
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    return 200 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
location /RequestDenied {
    return 412 "$naxsi_server $naxsi_uri $naxsi_learning $naxsi_block";
}
--- request
GET /bla?a=--select
--- error_code: 412
--- response_body: localhost /RequestDenied 0 1

=== TEST 14: Vars - naxsi_total_processed, naxsi_total_blocked - HTF test that?
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    return 200 "$naxsi_total_processed $naxsi_total_blocked";
}
location /RequestDenied {
    return 412 "$naxsi_total_processed $naxsi_total_blocked";
}
--- request
GET /bla?a=--select
--- error_code: 412
--- response_body: 0 0

=== TEST 14.1: Vars - naxsi_score
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$RFI >= 8" BLOCK;
    CheckRule "$TRAVERSAL >= 4" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    return 200 "$naxsi_score";
}
location /RequestDenied {
    return 412 "$naxsi_score";
}
--- request
GET /bla?a=--select
--- error_code: 412
--- response_body: 0:$SQL:8

=== TEST 14.2: Vars - naxsi_score
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    LearningMode;
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$RFI >= 8" BLOCK;
    CheckRule "$TRAVERSAL >= 4" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    return 200 "$naxsi_score";
}
location /RequestDenied {
    return 412 "$naxsi_score";
}
--- request eval
use URI::Escape;
"POST /select--?a=../..

"
--- error_code: 200
--- response_body: $OTHERS,0:$SQL:8,1:$TRAVERSAL:8

=== TEST 15.1: Vars - naxsi_match
--- main_config
$TEST_NGINX_MAIN_CONF
--- http_config
$TEST_NGINX_HTTP_CONF
--- config
location / {
    LearningMode;
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$RFI >= 8" BLOCK;
    CheckRule "$TRAVERSAL >= 4" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    return 200 "$naxsi_match";
}
location /RequestDenied {
    return 412 "$naxsi_match";
}
--- request eval
use URI::Escape;
"POST /select--?a=../..

"
--- error_code: 200
--- response_body: 0:1000:URL:-,1:1007:URL:-,2:1200:ARGS:a,3:16:BODY:-
