<a href="https://scan.coverity.com/projects/1883">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/1883/badge.svg"/>
</a>


### We need your help

[Please fill this little feedback survey](https://docs.google.com/spreadsheet/viewform?formkey=dG9UWDFuTEhiWWt4UF9fZEtwWFVJUlE6MQ), 2 minutes of your time, great help for us !


## What is Naxsi?

NAXSI means Nginx Anti Xss & Sql Injection. 

Technically, it is a third party nginx module, available as a package for
many UNIX-like platforms. This module, by default, reads a small subset of
simple rules (naxsi_core.rules) containing 99% of known patterns involved in
websites vulnerabilities. For example, '<', '|' or 'drop' are not supposed
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
WAF, Naxsi filters Get & Posts resquests and is OpenSource and free to use
for your company or personal own use (ie: as long as you don't resell a
service or product based on Naxsi to customers).

### Getting started

#### Wiki

See the [wiki](https://github.com/nbs-system/naxsi/wiki)


#### Performance reviews

  * [See how Naxsi performs against a highly vulnerable web site](https://github.com/nbs-system/naxsi/wiki/NaxsiVsAppScan) 
  * [See how Naxsi performs vs Obfuscated|Complex SQLi patterns](https://github.com/nbs-system/naxsi/wiki/naxsivsobfuscated)

### We need you !

 * Performance, stability testing: we are looking for independent reviews, benchmarks, and related feedback
 * Security testing: we prepared a running [testing environment](http://github.com/nbs-system/naxsi/wiki/OnlyTrustWhatYouCanTest) for you to play with. Go, play, (try to) bypass!
 * Post feature requests, documentation improvements
 * Bug reports: [Naxsi is young, there are known bugs](https://github.com/nbs-system/naxsi/wiki/KnownBugs)

