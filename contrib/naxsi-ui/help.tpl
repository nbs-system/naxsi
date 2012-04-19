<html>
  <head>
    <title>Naxsi Rules Extractor</title>
  </head>
  <body>
    <p style="text-align:center"><b>Naxsi Rules Extractor</b></p>
    <h3>How to extract generated rules from the database : </h3>
    <ul>
      <li>
	A GET request on /get_rules will display the generated rules. Non-optimised rules will be displayed in comment.
      </li>
    </ul>
    <h3>The available args on /get_rules are : </h3>
    <ul>
      <li>
	<p>
	<b>rules_file</b> : Path to the core rules file of naxsi (typically /etc/nginx/conf/naxsi_core.rules).<br />
	This arg is used to display the message associated with the rule (ie, will display "double quote" if the rule 1001 is whitelisted).<br />
	If this arg is not present, an error message will be displayed.	
	</p>
      </li>
      <li>
	<p>
	<b>page_hit</b> :  Minimum number of pages triggering the same event before proposing the optimisation (ie, if there is more than 10 urls that trigger a rule, the rule will be whitelisted on every url).<br />
	Default to 10.
	</p>
      </li>
      <li>
	<p>
	  <b>rules_hit</b> : Minimum number of rules hitting the same event on the same page before proposing optimisation (ie, if there is more than 10 differents rules triggered on the same url, all rules will be whitelisted on that url)<br />
	  Default to 10.
	</p>
      </li>
    </ul>
    <h3>Example : </h3>
<ul>
<li>
      Optimise the rules if more than 7 exceptions on the same arg are triggered on a page (whitelist all rules on the arg on this page) : 
    <a href="http://__HOSTNAME__/get_rules?rules_hit=7">http://__HOSTNAME__/get_rules?rules_hit=7</a><br />
</li>
<li>
      Optimise the rules if more than 7 exceptions on the same arg are triggered on a page (whitelist all rules on the arg on this page) or if more than 10 pages trigger the same rule (whitelist the rule on every page): 
    <a href="http://__HOSTNAME__/get_rules?rules_hit=7&page_hit=10">http://__HOSTNAME__/get_rules?rules_hit=7&page_hit=10</a><br />
</li>
</ul>
    <h3>Statistics : </h3>
    __STATS__
  </body>
</html>