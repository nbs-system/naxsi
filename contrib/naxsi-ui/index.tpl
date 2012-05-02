<html lang="en">
<head>
<title>Naxsi Graphs</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="bootstrap/css/bootstrap.css" rel="stylesheet">
<link href="bootstrap/css/bootstrap-responsive.css" rel="stylesheet">
<script type="text/javascript" src="bootstrap/js/bootstrap.js"></script>
<style>
      body {
        padding-top: 60px;
      }
    </style>
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript"></script>
<script type="text/javascript" src="js/highcharts.js"></script>

<script type="text/javascript">
function DisplayHome() {
document.getElementById('home').setAttribute("class", "active");
document.getElementById('help').setAttribute("class", "inactive")
document.getElementById('stats').setAttribute("class", "inactive");
document.getElementById('display').innerHTML = "Welcome to the NAXSI Web Interface !";
}

function DisplayHelp() {
document.getElementById('home').setAttribute("class", "inactive");
document.getElementById('help').setAttribute("class", "active");
document.getElementById('stats').setAttribute("class", "inactive");
document.getElementById('display').innerHTML = "<p style='text-align:center'><b>Naxsi Rules Extractor</b></p>\n    <h3>How to extract generated rules from the database : </h3>\n    <ul>\n      <li>\n	A GET request on /get_rules will display the generated rules. Non-optimised rules will be displayed in comment.\n      </li>\n    </ul>\n    <h3>The available args on /get_rules are : </h3>\n    <ul>\n      <li>\n	<p>\n	<b>rules_file</b> : Path to the core rules file of naxsi (typically /etc/nginx/conf/naxsi_core.rules).<br />\n	This arg is used to display the message associated with the rule (ie, will display \"double quote\" if the rule 1001 is whitelisted).<br />\n	If this arg is not present, an error message will be displayed.	\n	</p>\n      </li>\n      <li>\n	<p>\n	<b>page_hit</b> :  Minimum number of pages triggering the same event before proposing the optimisation (ie, if there is more than 10 urls that trigger a rule, the rule will be whitelisted on every url).<br />\n	Default to 10.\n	</p>\n      </li>\n      <li>\n	<p>\n	  <b>rules_hit</b> : Minimum number of rules hitting the same event on the same page before proposing optimisation (ie, if there is more than 10 differents rules triggered on the same url, all rules will be whitelisted on that url)<br />\n	  Default to 10.\n	</p>\n      </li>\n    </ul>\n    <h3>Example : </h3>\n<ul>\n<li>\n      Optimise the rules if more than 7 exceptions on the same arg are triggered on a page (whitelist all rules on the arg on this page) : \n    <a href='http://__HOSTNAME__/get_rules?rules_hit=7'>http://__HOSTNAME__/get_rules?rules_hit=7</a><br />\n</li>\n<li>\n      Optimise the rules if more than 7 exceptions on the same arg are triggered on a page (whitelist all rules on the arg on this page) or if more than 10 pages trigger the same rule (whitelist the rule on every page): \n    <a href='http://__HOSTNAME__/get_rules?rules_hit=7&page_hit=10'>http://__HOSTNAME__/get_rules?rules_hit=7&page_hit=10</a><br />\n</li>\n</ul>";
}

function DisplayStats()
{
document.getElementById('home').setAttribute("class", "inactive");
document.getElementById('help').setAttribute("class", "inactive");
document.getElementById('stats').setAttribute("class", "active");
document.getElementById('display').innerHTML = "__STATS__";
}

</script>

</head>
<body>

 <div class="navbar navbar-fixed-top">
      <div class="navbar-inner">
        <div class="container">
          <a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </a>
          <a class="brand" href="#">Naxsi Web Interface</a>
          <div class="nav-collapse">
            <ul class="nav">
              <li class="active" id="home"><a href="#" onclick="javascript:DisplayHome()">Home</a></li>
              <li class="inactive" id="Graphics"><a href="/graphs">Graphics</a></li>
              <li class="inactive" id="rules"><a href="/get_rules">Generate Whitelist</a></li>
              <li class="inactive" id="stats"><a href="#" onclick="javascript:DisplayStats()">Statitics</a></li>
              <li class="inactive" id="help"><a href="#" onclick="javascript:DisplayHelp()">Help</a></li>
            </ul>
          </div>
        </div>
      </div>
    </div>

<div class="container">
  <div id="display">
	Welcome to the NAXSI Web Interface !
  </div>
</div>
</body>
</html>
