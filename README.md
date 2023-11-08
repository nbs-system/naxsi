![naxsi](https://raw.githubusercontent.com/nbs-system/naxsi/master/logo.png)

# Project Status

This is a project status update regarding Naxsi.

**As you may have noticed, the development of Naxsi has been stopped and the repository will be archived for historical reasons. This means that no new updates or bug fixes will be released for this version.**

However, if you wish to update to newer versions of Naxsi, we recommend that you use the new repository at https://github.com/wargio/naxsi. This repository has been actively maintained and updated with new features and bug fixes.

We understand that this news may be disappointing for some of our users who have been relying on Naxsi for their web application security needs. We want to assure you that we are committed to providing the best possible solutions for your security needs and encourage you to explore our security products.

Thank you for your understanding and continued support.

## What is Naxsi?

NAXSI means [Nginx](http://nginx.org/) Anti [XSS](https://www.owasp.org/index.php/Cross-site_Scripting_%28XSS%29) & [SQL Injection](https://www.owasp.org/index.php/SQL_injection). 

Technically, it is a third party nginx module, available as a package for
many UNIX-like platforms. This module, by default, reads a small subset of
[simple (and readable) rules](https://github.com/nbs-system/naxsi/blob/master/naxsi_config/naxsi_core.rules)
containing 99% of known patterns involved in
website vulnerabilities. For example, `<`, `|` or `drop` are not supposed
to be part of a URI.

Being very simple, those patterns may match legitimate queries, it is
the Naxsi's administrator duty to add specific rules that will whitelist
legitimate behaviours. The administrator can either add whitelists manually
by analyzing nginx's error log, or (recommended) start the project with an
intensive auto-learning phase that will automatically generate whitelisting
rules regarding a website's behaviour.

In short, Naxsi behaves like a DROP-by-default firewall, the only task
is to add required ACCEPT rules for the target website to work properly.

## Why is it different?

Contrary to most Web Application Firewalls, Naxsi doesn't rely on a
signature base like an antivirus, and thus cannot be circumvented by an
"unknown" attack pattern.
Naxsi is [Free software](https://www.gnu.org/licenses/gpl.html) (as in freedom)
and free (as in free beer) to use.

## What does it run on?
Naxsi should be compatible with any nginx version.

It depends on `libpcre` for its regexp support, and is reported to work great on NetBSD, FreeBSD, OpenBSD, Debian, Ubuntu and CentOS.
