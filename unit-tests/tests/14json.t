#vi:filetype=perl

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each(1) * blocks();
no_root_location();
no_long_string();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();
__DATA__
=== JSON0 : Valid JSON
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 200
=== JSON1 : invalid JSON (double closing ']')
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412



=== JSON2 : invalid JSON (missing closing ']')
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412
=== JSON3 : invalid JSON (closing array with '}' instead of ']')
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"}
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412
=== JSON4 : invalid JSON (Missing final closing '}')
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

"
--- error_code: 412

=== JSON5 : invalid JSON (Extra closing '}')
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}}"
--- error_code: 412
=== JSON6 : invalid JSON (Missing ',' in array)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\" \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 412
=== JSON7 : Valid JSON with empty array item (Extra ',' in array)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\",\"XML\",]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 200
=== JSON8 : valid JSON - too deep !
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{{{{{{{{{{{{[\"lol\"]}}}}}}}}}}}}"
--- error_code: 412
=== JSON9 : Valid JSON with ev0l stuff (array => var content)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"G<ML\",\"XML\",]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 412
=== JSON10 : Valid JSON with ev0l stuff (array => var name)
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAl<so\": [\"GML\",\"XML\",]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }

}"
--- error_code: 412
=== JSON11 : Empty JSON object
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{

}"
--- error_code: 200
=== JSON12 : malformed (closing object before array) Json 
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : [\"laul\", {\"die\" : \"nope\" ]}
}"
--- error_code: 412
=== JSON12 : malformed (unescaped quotes) 
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : [\"laul\", {\"die\" : \"n\"ope\" }]
}"
--- error_code: 412

=== JSON12 : escaped quotes 
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
	 BasicRule wl:1001,1205;
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : [\"laul\", {\"die\" : \"n\\\"ope\" }]
}"
--- error_code: 200
=== JSON13 : concatenation attempt (ie "foo":"bar"+eval(evil)+"foo")
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"fuu\" : \"oh \"+eval(evil)+\" my\"]
}"
--- error_code: 412
=== JSON13 : concatenation attempt (ie "foo":"bar"+eval(evil)+"foo")
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"obvious\" : \"a<a\"]
}"
--- error_code: 412
=== JSON14 : unfinished sub object
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
\"obvious\" : \"a<a\",
\"fu\" : { \"aa\" : \"bb\" 
}"
--- error_code: 412

=== JSON14 : bug_418
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
         DeniedUrl "/RequestDenied";
         CheckRule "$SQL >= 8" BLOCK;
         CheckRule "$RFI >= 8" BLOCK;
         CheckRule "$TRAVERSAL >= 4" BLOCK;
         CheckRule "$XSS >= 8" BLOCK;
         root $TEST_NGINX_SERVROOT/html/;
         index index.html index.htm;
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"error\": 
  \"ERROR_REPORT:{\\\"request\\\":{\\\"bar\\\":\\\"\\\"},\\\"response\\\":{\\\"bar\\\":[{\\\"schema_id\\\":\\\"foo\\\"}]}}\"
}"
--- error_code: 412

=== JSON14 : bug_437
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
         SecRulesEnabled;
     DeniedUrl "/RequestDenied";
     CheckRule "$SQL >= 8" BLOCK;
     CheckRule "$RFI >= 8" BLOCK;
     CheckRule "$TRAVERSAL >= 4" BLOCK;
     CheckRule "$XSS >= 8" BLOCK;
     root $TEST_NGINX_SERVROOT/html/;
     index index.html index.htm;
     error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
 \"number\": -2.806683719414e-14
}"
--- error_code: 200


=== JSON15 : JSON with XSS.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$RFI >= 8" BLOCK;
    CheckRule "$TRAVERSAL >= 4" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
    error_page 405 = $uri;
}
location /RequestDenied {
    return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"MyKey\": \"MyValue <script>alert('1')</script>\"
}"
--- error_code: 412


=== JSON16 : Null char in JSON with XSS.
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
--- config
set $naxsi_extensive_log 1;
location / {
    SecRulesEnabled;
    DeniedUrl "/RequestDenied";
    CheckRule "$SQL >= 8" BLOCK;
    CheckRule "$RFI >= 8" BLOCK;
    CheckRule "$TRAVERSAL >= 4" BLOCK;
    CheckRule "$XSS >= 8" BLOCK;
    root $TEST_NGINX_SERVROOT/html/;
    index index.html index.htm;
    error_page 405 = $uri;
}
location /RequestDenied {
    return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"POST /
{
    \"MyKey\": \"MyValue \0 <script>alert('1')</script>\"
}"
--- error_code: 412

=== JSON17 : Valid JSON With HTTP Patch Method
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"PATCH /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 200

=== JSON1 : invalid JSON With HTTP Patch Method (double closing ']')
--- main_config
load_module $TEST_NGINX_NAXSI_MODULE_SO;
--- http_config
include $TEST_NGINX_NAXSI_RULES;
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
         error_page 405 = $uri;
}
location /RequestDenied {
         return 412;
}
--- more_headers
Content-Type: application/json
--- request eval
use URI::Escape;
"PATCH /
{
    \"glossary\": {
        \"title\": \"example glossary\",
\"GlossDiv\": {
            \"title\": \"S\",
\"GlossList\": {
                \"GlossEntry\": {
                    \"ID\": \"SGML\",
\"SortAs\": \"SGML\",
\"GlossTerm\": \"Standard Generalized Markup Language\",
\"Acronym\": \"SGML\",
\"Abbrev\": \"ISO 8879:1986\",
\"GlossDef\": {
                        \"para\": \"A meta-markup language used to create markup languages such as DocBook.\",
\"GlossSeeAlso\": [\"GML\", \"XML\"]]
                    },
\"GlossSee\": \"markup\"
                }
            }
        }
    }
}
"
--- error_code: 412
