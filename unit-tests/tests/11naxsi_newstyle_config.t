#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();


__DATA__
=== TEST 1: Basic GET request
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
location / {
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
	# return 412;
}
--- request
GET /?a=buibui
--- error_code: 200
=== TEST 2: DENY : Obvious GET XSS
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
check_rule "$SQL >= 8" BLOCK;
check_rule "$RFI >= 8" BLOCK;
check_rule "$TRAVERSAL >= 4" BLOCK;
check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a="><ScRiPt>alert(1)</scRiPt>
--- error_code: 412
=== TEST 2.1: DENY : Obvious RFI
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
check_rule "$SQL >= 8" BLOCK;
check_rule "$RFI >= 2" BLOCK;
check_rule "$TRAVERSAL >= 4" BLOCK;
check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=http://evil.com/eva.txt
--- error_code: 412
=== TEST 2.3: DENY : Obvious LFI
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
check_rule "$SQL >= 8" BLOCK;
check_rule "$RFI >= 2" BLOCK;
check_rule "$TRAVERSAL >= 4" BLOCK;
check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=../../../../../bar.txt
--- error_code: 412
=== TEST 3: OBVIOUS GET SQL INJECTION
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=1'+Or+'1'='1
--- error_code: 412
=== TEST 3bis: OBVIOUS (quoteless) GET SQL INJECTION
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=1+UnIoN+SeLeCt+1
--- error_code: 412
=== TEST 4: VERY STRANGE GET REQUEST
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=[]();--
--- error_code: 412
=== TEST 5: SIMPLE POST (www-form style)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=bar1&foo2=bar2"
--- error_code: 200
=== TEST 7 : SQLi POST (www-form style)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=' OR '1'='1"
--- error_code: 412
=== TEST 8 : XSS POST (www-form style)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1='><script>alert(1)</script>"
--- error_code: 412
=== TEST 9: Adding a test rule in http_config (ARGS zone).
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:foobar" "msg:foobar test pattern" "mz:ARGS" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=foobar
--- error_code: 412
=== TEST 10: Adding a test rule in http_config (URL zone).
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:foobar" "msg:foobar test pattern" "mz:URL" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /foobar?aa
--- error_code: 412
=== TEST 11: Adding a test rule in http_config (BODY zone).
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:foobar" "msg:foobar test pattern" "mz:BODY" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=foobar"
--- error_code: 412
=== TEST 17: Negative RX rule on header:content-type.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 basic_rule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 200
=== TEST 17: Negative RX rule on header:content-type.
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 basic_rule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 200
=== TEST 18: Negative RX rule on header:content-type (again).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 basic_rule wl:1999 "mz:$URL:/foobar|$ARGS_VAR:barone";
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/OBSCURE_EVIL_CONTENT_TYPE
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 412
=== TEST 19: Negative RX rule on header:content-type (again & last, I promise !).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=buibui
--- error_code: 200
=== TEST 19.2: Negative RX rule on header:content-type (I LIED !).
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule negative "rx:application/x-www-form-urlencoded|multipart/form-data" "msg:foobar test pattern" "mz:$HEADERS_VAR:Content-type" "s:$SQL:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: ApPlIcaTiOn/x-wWw-fORm-urlEnCoDed
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 200
=== TEST 22: CUSTOM SCORE RULES !
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:1999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:1998;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=yesone&b=yestwo
--- error_code: 412
=== TEST 23: CUSTOM SCORE RULES, bis
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:2999;
MainRule "str:yestwo" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:21" id:2998;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a=yesone&b=yestwo
--- error_code: 412
=== TEST 24: Testing MULTIPART POSTs -- INVALID FORMAT
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data
--- request eval
use URI::Escape;
"POST /
a1=trolol"
--- error_code: 412
=== TEST 24: Testing MULTIPART POSTs
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 355
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 200
=== TEST 25: Testing MULTIPART POSTs (NO CONTENT LEN)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 200
=== TEST 26: Testing MULTIPART POSTs (BAD CONTENT LEN)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 42
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMyName\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412
=== TEST 26.1: Testing MULTIPART POSTs (BAD CONTENT LEN)
#nginx changed his way, no data is cut to content lenght header, so this test is obsolete
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
Content-Length: 42
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nMy<aaaaa>Name\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\ny<alert>es\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412
=== TEST 27: Obvious POST XSS (multipart)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\naz\"><script>alert(1)</script>\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412
=== TEST 28: Obvious POST SQLi (multipart)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\naz\" OR \"1\"=\"1\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412
=== TEST 29: Malformed POST / BoF try #1 (missing some boundaries)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nNaaaaaa\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nyes\r\n-----------------------------103832778631715--\r\n"
--- error_code: 412
=== TEST 30 : Malformed POST / BoF try #3 (random overflow trigger n1)
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE > 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: multipart/form-data; boundary=---------------------------103832778631715
--- request eval
use URI::Escape;
"POST /\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nazzzo\r\n\r\n\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"married\"\r\n\r\nnot single\r\n-----------------------------103832778631715\r\nContent-Disposition: form-data; name=\"male\"\r\n\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n-----------------------------103832778631715--\r\n"
--- error_code: 200
=== TEST 31: enc0ding phun ?
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
	 error_page 405 = $uri;
}
location /RequestDenied {
	 return 412;
}
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /
foo1=ba%%2f%3c%3D%3%D%33%DD%FF%2F%3cr1&foo2=bar2"
--- error_code: 412
=== TEST 32: fucked up URLs #1
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?a&&z=yesone&&
--- error_code: 412
=== TEST 33: fucked up URLs #2
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?z=&yesone
--- error_code: 412
=== TEST 33: fucked up URLs #2bis
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?z=&==yesone&&&
--- error_code: 412
=== TEST 33: fucked up URLs #2ter
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?==yesone&&&
--- error_code: 412
=== TEST 33: fucked up URLs #3
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?z=&AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbuiyesone&&
--- error_code: 412
=== TEST 33: fucked up URLs #4
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?z=&%00yesone
--- error_code: 412
=== TEST 33: fucked up URLs #4
--- user_files
>>> foobar
eh yo
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
main_rule "rx:select|union|update|delete|insert|table|from|ascii|hex|unhex|drop" "msg:sql keywords" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1000;
main_rule "str:\"" "msg:double quote" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8,$XSS:8" id:1001;
main_rule "str:0x" "msg:0x, possible hex encoding" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:2" id:1002;
main_rule "str:/*" "msg:mysql comment (/*)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1003;
main_rule "str:*/" "msg:mysql comment (*/)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1004;
main_rule "str:|" "msg:mysql keyword (|)"  "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1005;
main_rule "rx:&&" "msg:mysql keyword (&&)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:8" id:1006;
main_rule "str:--" "msg:mysql comment (--)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1007;
main_rule "str:;" "msg:; in stuff" "mz:BODY|URL|ARGS" "s:$SQL:4,$XSS:8" id:1008;
main_rule "str:=" "msg:equal in var, probable sql/xss" "mz:ARGS|BODY" "s:$SQL:2" id:1009;
main_rule "str:(" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1010;
main_rule "str:)" "msg:parenthesis, probable sql/xss" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1011;
main_rule "str:'" "msg:simple quote" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$SQL:4,$XSS:8" id:1013;
main_rule "str:," "msg:, in stuff" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1015;
main_rule "str:#" "msg:mysql comment (#)" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$SQL:4" id:1016;
main_rule "str:http://" "msg:http:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1100;
main_rule "str:https://" "msg:https:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1101;
main_rule "str:ftp://" "msg:ftp:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1102;
main_rule "str:php://" "msg:php:// scheme" "mz:ARGS|BODY|$HEADERS_VAR:Cookie" "s:$RFI:8" id:1103;
main_rule "str:.." "msg:double dot" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1200;
main_rule "str:/etc/passwd" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1202;
main_rule "str:c:\\" "msg:obvious windows path" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1203;
main_rule "str:cmd.exe" "msg:obvious probe" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1204;
main_rule "str:\\" "msg:backslash" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$TRAVERSAL:4" id:1205;
main_rule "str:<" "msg:html open tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1302;
main_rule "str:>" "msg:html close tag" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1303;
main_rule "str:[" "msg:[, possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1310;
main_rule "str:]" "msg:], possible js" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1311;
main_rule "str:~" "msg:~ character" "mz:BODY|URL|ARGS|$HEADERS_VAR:Cookie" "s:$XSS:4" id:1312;
main_rule "str:`"  "msg:grave accent !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1314;
main_rule "rx:%[23]."  "msg:double encoding !" "mz:ARGS|URL|BODY|$HEADERS_VAR:Cookie" "s:$XSS:8" id:1315;
main_rule "str:&#" "msg: utf7/8 encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1400;
main_rule "str:%U" "msg: M$ encoding" "mz:ARGS|BODY|URL|$HEADERS_VAR:Cookie" "s:$EVADE:4" id:1401;
main_rule negative "rx:multipart/form-data|application/x-www-form-urlencoded" "msg:Content is neither mulipart/x-www-form.." "mz:$HEADERS_VAR:Content-type" "s:$EVADE:4" id:1402;
main_rule "rx:.ph|.asp" "msg:asp/php file upload!" "mz:FILE_EXT" "s:$UPLOAD:8" id:1501;
main_rule "str:phpmyadmin" "msg:phpmyadmin bot ?" "mz:URL" "s:LOG" id:1502;

#MainRule "str:yesone" "msg:foobar test pattern" "mz:ARGS" "s:$TESTSCORE:42" id:1999;
--- config
location / {
	 #LearningMode;
	 rules_enabled;
	 denied_url "/RequestDenied";
	 check_rule "$SQL >= 8" BLOCK;
	 check_rule "$RFI >= 8" BLOCK;
	 check_rule "$TRAVERSAL >= 4" BLOCK;
	 check_rule "$XSS >= 8" BLOCK;
	 check_rule "$TESTSCORE >= 42" BLOCK;
  	 root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
}
location /RequestDenied {
	 return 412;
}
--- request
GET /?z=&y%00esone
--- error_code: 412



