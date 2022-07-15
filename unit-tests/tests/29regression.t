#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== WL TEST 1.0: [ARGS zone WhiteList] Adding a test rule in http_config (ARGS zone) and disable rule.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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

=== WL TEST 1.1: testing multiple alternate matching/non-matching rules
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:zz" "mz:$URL_X:/foo/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
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
GET /wp-json/wp/v2/?id=a
--- error_code: 412

=== WL TEST 1.2: testing multiple alternate matching/non-matching rules
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:zz" "mz:$URL_X:/foo/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
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
GET /wp-json/wp/v2?id=a
--- error_code: 404

=== WL TEST 1.3: testing multiple alternate matching/non-matching rules
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:zz" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
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
GET /wp-json/wp/v2?id=11
--- error_code: 404

=== WL TEST 1.4: testing multiple alternate matching/non-matching rules
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:zz" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
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
GET /wp-json/wp/v2/?id=zz
--- error_code: 412

=== WL TEST 1.5: testing multiple alternate matching/non-matching rules
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:zz" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242001;
MainRule "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$ARGS_VAR_X:^id$" "s:DROP" id:4242002;
MainRule "str:iyxnlnjrf" "mz:$URL_X:^(/index.php)?/qquoteadv|ARGS|BODY" "s:DROP" "msg:base64_" id:42000526;
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
GET /qquoteadv?id=iyxnlnjrf1
--- error_code: 412
=== WL TEST 2.0: log + drop
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule negative "rx:^[\d_-]+$" "mz:$ARGS_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000530;
MainRule negative "rx:^[\d_-]+$" "mz:$BODY_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000529;
MainRule negative "rx:^\d+$" "mz:$ARGS_VAR_X:^id$|$URL_X:/wp-json/wp/v2/" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000531;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$BODY_VAR_X:^id$" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000532;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" DROP;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /wp-json/wp/v2/posts/111
id=1a&foo2=bar2"
--- error_code: 412
=== WL TEST 2.01: log + block
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;

--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule negative "rx:^[\d_-]+$" "mz:$ARGS_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000530;
MainRule negative "rx:^[\d_-]+$" "mz:$BODY_VAR:id" "s:$LOG_TEST:1" "msg:wordpress < 4.7.2 wp-json" id:42000529;
MainRule negative "rx:^\d+$" "mz:$ARGS_VAR_X:^id$|$URL_X:/wp-json/wp/v2/" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000531;
MainRule negative "rx:^\d+$" "mz:$URL_X:/wp-json/wp/v2/|$BODY_VAR_X:^id$" "s:$UWA:8" "msg:wordpress < 4.7.2 wp-json" id:42000532;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /wp-json/wp/v2/posts/111
id=1a&foo2=bar2"
--- error_code: 412
=== WL TEST 3.0: false-positive on virtual-patch with empty var name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:FOOBAR" "mz:$URL:/wp-includes/js/plupload/plupload.flash.swf|ARGS" "msg:Wordpress PlUpload XSS" "s:$UWA:8,$XSS_UWA:1"  id:42000485;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /?a=bui&FOOBAR
--- error_code: 200
=== WL TEST 3.0: false-positive on virtual-patch with empty var name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:FOOBAR" "mz:$URL:/wp-includes/js/plupload/plupload.flash.swf|ARGS" "msg:Wordpress PlUpload XSS" "s:$UWA:8,$XSS_UWA:1"  id:42000485;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-includes/js/plupload/plupload.flash.swf?a=bui&FOOBAR
--- error_code: 412
=== WL TEST 3.01: false-positive on virtual-patch with empty var name
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule "rx:FOOBAR" "mz:$URL:/wp-includes/js/plupload/plupload.flash.swf|ARGS" "msg:Wordpress PlUpload XSS" "s:$UWA:8,$XSS_UWA:1"  id:42000485;
--- config
location / {
         SecRulesEnabled;
	 CheckRule "$LOG_TEST >= 1" LOG;
	 CheckRule "$UWA >= 8" BLOCK;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 4" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
         return 412;
}
--- request
GET /wp-includes/js/plupload/plupload.flash.swf/xxx/?a=bui&FOOBAR
--- error_code: 404

=== TEST 4 - regression on FILE_EXT being detected in BODY
--- user_files
>>> my-account/profile
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
MainRule negative "rx:^[\.a-z0-9_\- ]+$" "mz:FILE_EXT" "s:$UPLOAD:8" id:1502;
MainRule "rx:\.ph|\.asp|\.hta|\.htp" "mz:FILE_EXT" "s:$UWA:8" id:123456;
--- config
set $naxsi_json_log 1;
location / {
   BasicRule wl:1000,1001,1002,1005,1007,1010,1011,1015,1016,1100,1101,1200,1315 "mz:$HEADERS_VAR:cookie";
   BasicRule wl:1310,1311 "mz:$URL_X:^/my-account/profile|BODY|NAME";
   BasicRule wl:17,1010,1011,1015,1200 "mz:$URL_X:^/my-account/profile|$BODY_VAR_X:^sportactivities\[[0-9]\]\.";
   BasicRule wl:17,1010,1011,1015,1200 "mz:$URL_X:^/my-account/profile|$BODY_VAR_X:^addresses\[[0-9]\]\.";
   BasicRule wl:1009,1101 "mz:$URL_X:^/my-account/profile|$BODY_VAR_X:^return";

   SecRulesEnabled;
   LearningMode;
   LibInjectionSql;
   LibInjectionXss;

   DeniedUrl "/RequestDenied";
   CheckRule "$SQL >= 8" BLOCK;
   CheckRule "$RFI >= 8" BLOCK;
   CheckRule "$TRAVERSAL >= 5" BLOCK;
   CheckRule "$UPLOAD >= 5" BLOCK;
   CheckRule "$XSS >= 8" BLOCK;
   CheckRule "$UWA >= 8" DROP;
   CheckRule "$EVADE >= 8" BLOCK;
   CheckRule "$LOG >= 1" LOG;

   root $TEST_NGINX_SERVROOT/html/;
   index index.html index.htm;
   error_page 405 = $uri;
}
location /RequestDenied {
    return 412;
}
--- raw_request eval
"POST /my-account/profile HTTP/1.1\r
Host: 127.0.0.1\r
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0\r
Accept: */*\r
Accept-Language: en-US,en;q=0.5\r
Accept-Encoding: gzip, deflate\r
Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r
X-Requested-With: XMLHttpRequest\r
Content-Length: 2772\r
Origin: https://127.0.0.1\r
Connection: close\r
Referer: http://127.0.0.1/my-account/profile/\r
Cookie: t2s-p=ca0ac96b-6177-4e4a-f554-3f0a10469d9e; _gcl_au=1.1.1782048568.1605605979; gtm_nbpv=8; gtm_cookieConsent=1; __trossion=1605605980_1800_1__caa5d2de-ec72-4c61-b1c4-96bf4b22f5da%3A1605605980_1605607565_8_; __troRUID=caa5d2de-ec72-4c61-b1c4-96bf4b22f5da; __troSYNC=1; _pin_unauth=dWlkPU1EUTBZVFZqTXpNdE1EQTNOeTAwTURNd0xXSmlORGd0TTJZeU1EWmlaVGsxT1RCag; JSESSIONID=D426452D0BFCCAD4D384E972D7770861.Agassi; miniCartCount=0; _ga=GA1.2.243283519.1605605987; _gid=GA1.2.266115569.1605605987; _fbp=fb.1.1605605989339.1901530086; acceleratorSecureGUID=a21d40c7cdb55b323a686b37facfded200814ecf; customerFavoriteStore=SOME%2B-%2BPREMILHAT%7C%5B%7B%22closingTime2%22%3A%2219%3A00%22%2C%22weekDay%22%3A%22lundi%22%2C%22closed%22%3Afalse%2C%22closingTime1%22%3A%2212%3A00%22%2C%22openingTime2%22%3A%2214%3A00%22%2C%22openingTime1%22%3A%2209%3A30%22%7D%2C%7B%22closingTime2%22%3A%2219%3A00%22%2C%22weekDay%22%3A%22mardi%22%2C%22closed%22%3Afalse%2C%22closingTime1%22%3A%2212%3A00%22%2C%22openingTime2%22%3A%2214%3A00%22%2C%22openingTime1%22%3A%2209%3A30%22%7D%2C%7B%22closingTime2%22%3A%2219%3A00%22%2C%22weekDay%22%3A%22mercredi%22%2C%22closed%22%3Afalse%2C%22closingTime1%22%3A%2212%3A00%22%2C%22openingTime2%22%3A%2214%3A00%22%2C%22openingTime1%22%3A%2209%3A30%22%7D%2C%7B%22closingTime2%22%3A%2219%3A00%22%2C%22weekDay%22%3A%22jeudi%22%2C%22closed%22%3Afalse%2C%22closingTime1%22%3A%2212%3A00%22%2C%22openingTime2%22%3A%2214%3A00%22%2C%22openingTime1%22%3A%2209%3A30%22%7D%2C%7B%22closingTime2%22%3A%2219%3A00%22%2C%22weekDay%22%3A%22vendredi%22%2C%22closed%22%3Afalse%2C%22closingTime1%22%3A%2212%3A00%22%2C%22openingTime2%22%3A%2214%3A00%22%2C%22openingTime1%22%3A%2209%3A30%22%7D%2C%7B%22weekDay%22%3A%22samedi%22%2C%22closed%22%3Afalse%2C%22closingTime1%22%3A%2219%3A00%22%2C%22openingTime1%22%3A%2209%3A30%22%7D%2C%7B%22closingTime2%22%3A%22%22%2C%22weekDay%22%3A%22dimanche%22%2C%22closed%22%3Atrue%2C%22closingTime1%22%3A%22%22%2C%22openingTime2%22%3A%22%22%2C%22openingTime1%22%3A%22%22%7D%5D%7C%2FAllier-03%2FAAAAAA%C3%87ON-Pr%C3%A9milhat-03410%2FSOME-PREMILHAT%2F00574_000%2F; isFidelity=false; CLICKANDCOLLECT-customerInformations=c29vb29vb29vb0BhYWFhYWEuY29t|Test+Test%2CTest|MTExMTExMTExMTExMQ==|; isNewCustomer=true; t2s-rank=rank1; _dc_gtm_UA-52322712-6=1; _uetsid=d060e34028b811eb8d3ef174562c91c3; _uetvid=d060d20028b811eb98dc9b58b7dbeb20\r
\r
title=mr&firstName=Test+Test&lastName=Test&phoneNumber=1111111111&phoneCountry.isocode=FR&email=sooooooooo%40aaaaaa.com&addresses%5B0%5D.id=9189547245591&addresses%5B0%5D.defaultAddress=true&addresses%5B0%5D.lastName=Test&addresses%5B0%5D.firstName=Test+Test&addresses%5B0%5D.postalCode=75013&addresses%5B0%5D.town=PARIS&addresses%5B0%5D.line1=6+ALLEE+PARIS+IVRY&addresses%5B0%5D.country.isocode=FR&addresses%5B0%5D.addressPhoneCountry.isocode=FR&addresses%5B0%5D.phone=0755911324&addresses%5B0%5D.billingAddress=true&child-count=0&sportActivities%5B0%5D.name=Course+%C3%A0+pied&sportActivities%5B0%5D.code=4&sportActivities%5B0%5D.id=&sportActivities%5B0%5D.me=&sportActivities%5B0%5D.myChildren=&sportActivities%5B1%5D.name=Cycles+(V%C3%A9lo%2C+VTT%2C+%E2%80%A6)&sportActivities%5B1%5D.code=1&sportActivities%5B1%5D.id=&sportActivities%5B1%5D.me=&sportActivities%5B1%5D.myChildren=&sportActivities%5B2%5D.name=Danse%2C+gymnastique%2C+fitness&sportActivities%5B2%5D.code=3&sportActivities%5B2%5D.id=&sportActivities%5B2%5D.me=&sportActivities%5B2%5D.myChildren=&sportActivities%5B3%5D.name=Musculation&sportActivities%5B3%5D.code=5&sportActivities%5B3%5D.id=&sportActivities%5B3%5D.me=&sportActivities%5B3%5D.myChildren=&sportActivities%5B4%5D.name=Randonn%C3%A9es&sportActivities%5B4%5D.code=10&sportActivities%5B4%5D.id=&sportActivities%5B4%5D.me=&sportActivities%5B4%5D.myChildren=&sportActivities%5B5%5D.name=Roller&sportActivities%5B5%5D.code=2&sportActivities%5B5%5D.id=&sportActivities%5B5%5D.me=&sportActivities%5B5%5D.myChildren=&sportActivities%5B6%5D.name=Ski&sportActivities%5B6%5D.code=14&sportActivities%5B6%5D.id=&sportActivities%5B6%5D.me=&sportActivities%5B6%5D.myChildren=&sportActivities%5B7%5D.name=Sport+d'eau+(Natation%2C+surf%2C+voile%2C+%E2%80%A6)&sportActivities%5B7%5D.code=12&sportActivities%5B7%5D.id=&sportActivities%5B7%5D.me=&sportActivities%5B7%5D.myChildren=&sportActivities%5B8%5D.name=Sports+collectifs+(Foot%2C+rugby%2C+basket%2C+%E2%80%A6)&sportActivities%5B8%5D.code=7&sportActivities%5B8%5D.id=&sportActivities%5B8%5D.me=&sportActivities%5B8%5D.myChildren=&sportActivities%5B9%5D.name=Sports+de+combat+(Judo%2C+karat%C3%A9%2C+aikido%2C+%E2%80%A6)&sportActivities%5B9%5D.code=13&sportActivities%5B9%5D.id=&sportActivities%5B9%5D.me=&sportActivities%5B9%5D.myChildren=&sportActivities%5B10%5D.name=Sports+de+raquette&sportActivities%5B10%5D.code=8&sportActivities%5B10%5D.id=&sportActivities%5B10%5D.me=&sportActivities%5B10%5D.myChildren=&sportActivities%5B11%5D.name=Autres&sportActivities%5B11%5D.code=6&sportActivities%5B11%5D.id=&sportActivities%5B11%5D.me=&sportActivities%5B11%5D.myChildren=&birthdate=12%2F11%2F1999&isWebNewsletterSubscribed=false&isSmsNewsletterSubscribed=false&CSRFToken=e87a083d-9743-4d47-8d60-d25e5f00e15e\r
"
--- error_code: 200

