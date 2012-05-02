<!DOCTYPE html>
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
function DisplayDays() {
document.getElementById('top10').setAttribute("class", "inactive");
document.getElementById('repartition').setAttribute("class", "inactive");
document.getElementById('home').setAttribute("class", "inactive");
document.getElementById('days').setAttribute("class", "active");

  var chart = null;
  var total_hits = __TOTALEXCEP__;
  var sqli_hits = __SQLIEXCEP__;
  var xss_hits = __XSSEXCEP__;
  var rfi_hits = __RFIEXCEP__;
  var upload_hits = __UPLOADEXCEP__;
  var dt_hits = __DTEXCEP__;
  var evading_hits = __EVADEEXCEP__;
  var intern_hits = __INTERNEXCEP__;

$(document).ready(function () {
chart = new Highcharts.Chart({
credits:{enabled:false},
chart: {
renderTo: 'display',
defaultSeriesType: 'spline' <!-- line, spline, area, areaspline, column, bar, pie and scatter-->
},
title: {
text: 'Rules hit per day'
},
xAxis: {
type : 'datetime'
},
yAxis: {
title: {
text: 'Number of hits',
},
min: 0
},
series: [
{name : 'SQLI', data: sqli_hits},
{name : 'XSS', data: xss_hits},
{name : 'Directory traversal', data: dt_hits},
{name : 'RFI', data: rfi_hits},
{name : 'Upload', data: upload_hits},
{name : 'Evading', data: evading_hits},
{name : 'Intern', data: intern_hits},
{name: 'Total Hits', data: total_hits}
],
});
$('tspan').last().remove();
});
}

function DisplayRepartition() {
document.getElementById('top10').setAttribute("class", "inactive");
document.getElementById('repartition').setAttribute("class", "active");
document.getElementById('home').setAttribute("class", "inactive");
document.getElementById('days').setAttribute("class", "inactive");
var chart;
$(document).ready(function() {
chart = new Highcharts.Chart({
chart: {
renderTo: 'display',
plotBackgroundColor: null,
plotBorderWidth: null,
plotShadow: false
},
credits:{enabled:false},
title: {
text: 'Hit Repartition'
},
tooltip: {
formatter: function() {
return '<b>'+ this.point.name +'</b>: '+ this.percentage.toFixed(2) +' %';
}
},
plotOptions: {
pie: {
allowPointSelect: true,
cursor: 'pointer',
dataLabels: {
enabled: true,
color: '#000000',
connectorColor: '#000000',
formatter: function() {
return '<b>'+ this.point.name +'</b>: '+ this.percentage.toFixed(2) +' %';
}
}
}
},
series: [{
type: 'pie',
name: 'hit',
data: [
['SQL Injection',   __SQLCOUNT__],
['XSS',       __XSSCOUNT__],
['Directory Traversal', __DTCOUNT__],
['RFI',    __RFICOUNT__],
['Evading',    __EVCOUNT__],
['Upload',   __UPCOUNT__],
['Intern',   __INTCOUNT__]
]
}]
});
});
}

function DisplayTop() {
document.getElementById('top10').setAttribute("class", "active");
document.getElementById('repartition').setAttribute("class", "inactive");
document.getElementById('home').setAttribute("class", "inactive");
document.getElementById('days').setAttribute("class", "inactive");
document.getElementById('display').innerHTML = '__TOPTEN__';
document.getElementById('display').innerHTML += '__TOPTENPAGE__';
}

function DisplayHome() {
document.getElementById('top10').setAttribute("class", "inactive");
document.getElementById('repartition').setAttribute("class", "inactive");
document.getElementById('home').setAttribute("class", "active");
document.getElementById('days').setAttribute("class", "inactive");
document.getElementById('display').innerHTML = "Welcome to the NAXSI Web Interface !";
}

</script>

<script type="text/javascript">

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
              <li class="active" id="home"><a href="/">Home</a></li>
              <li id="days" ><a href="#" onclick="javascript:DisplayDays()">Hit Per Days</a></li>
              <li id="repartition" ><a href="#"  onclick="javascript:DisplayRepartition()">Hits Repartition</a></li>
              <li id="top10" ><a href="#" onclick="javascript:DisplayTop()">Top 10</a></li>
            </ul>
          </div>
        </div>
      </div>
    </div>

<div class="container">
  <div id="display">
	<script>DisplayDays()</script>
  </div>
</div>
</body>
</html>
