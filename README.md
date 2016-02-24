<img alt="naxsi logo" src="https://www.nbs-system.com/wp-content/uploads/nbs-logo-naxsi1.png" align="center"/>   


<a href="https://scan.coverity.com/projects/1883">
  <img alt="Coverity Scan Build Status"
      src="https://scan.coverity.com/projects/1883/badge.svg"/>
</a>

<a href="https://travis-ci.org/nbs-system/naxsi">
  <img alt="Travis Build Status"
      src="https://travis-ci.org/nbs-system/naxsi.svg"/>
</a>

<a href="http://codecov.io/github/nbs-system/naxsi?branch=master">
  <img alt="Coverage via codecov.io" 
      src="http://codecov.io/github/nbs-system/naxsi/coverage.svg?branch=master"/>
</a>


### We need your help

[Please fill this little feedback survey](https://docs.google.com/spreadsheet/viewform?formkey=dG9UWDFuTEhiWWt4UF9fZEtwWFVJUlE6MQ), 2 minutes of your time, great help for us !


## What is Naxsi?

NAXSI means [Nginx]( http://nginx.org/ ) Anti [XSS]( https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29 ) & [SQL Injection]( https://www.owasp.org/index.php/SQL_injection ). 

Technically, it is a third party nginx module, available as a package for
many UNIX-like platforms. This module, by default, reads a small subset of
[simple (and readable) rules]( https://github.com/nbs-system/naxsi/blob/master/naxsi_config/naxsi_core.rules )
containing 99% of known patterns involved in
websites vulnerabilities. For example, `<`, `|` or `drop` are not supposed
to be part of a URI.

Being very simple, those patterns may match legitimate queries, it is
Naxsi's administrator duty to add specific rules that will whitelist those
legitimate behaviours. The administrator can either add whitelists manually
by analyzing nginx's error log, or (recommended) start the project by an
intensive auto-learning phase that will automatically generate whitelisting
rules regarding website's behaviour.

In short, Naxsi behaves like a DROP-by-default firewall, the only job needed
is to add required ACCEPT rules for the target website to work properly.

## Why it is different?

On the contrary of most Web Application Firewall, Naxsi doesn't rely on a
signature base, like an antivirus, and thus cannot be circumvented by an
"unknown" attack pattern. Another main difference between Naxsi and other
WAF, Naxsi filters only GET and POST resquests,
is a [Free software]( https://www.gnu.org/licenses/gpl.html ) (as in freedom)
and free (as in free beer) to use.

### Getting started

- The [documentation](https://github.com/nbs-system/naxsi/wiki)
- Some [rules]( https://github.com/nbs-system/naxsi-rules ) for mainstream softwares
- The [nxapi/nxtool]( https://github.com/nbs-system/naxsi/tree/master/nxapi ) to generate rules
