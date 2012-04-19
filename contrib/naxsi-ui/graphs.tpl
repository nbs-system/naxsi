<html>
<head>
<title>Naxsi Graphs</title>
<script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript"></script>
<script type="text/javascript" src="js/highcharts.js"></script>
<script type="text/javascript">
  var chart = null;
  var a = __ARRAYEXCEP__;
$(document).ready(function () {
chart = new Highcharts.Chart({
credits:{enabled:false},
chart: {
renderTo: 'container',
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
series: [{
name: 'Number of hits',
data: a
}],
});
$('tspan').last().remove();
});

var chart;
$(document).ready(function() {
chart = new Highcharts.Chart({
chart: {
renderTo: 'container2',
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
</script>
</head>
<body>
<div style="float:left">TOP 10 ATTACKERS : __TOPTEN__</div>
<div id="container" style="width: 800px; height: 400px; float:left"></div>
<div style="float:left">TOP 10 PAGES : __TOPTENPAGE__</div>
<div id="container2" style="width: 600px; height: 400px; float:left"></div>
</body>
</html>