<!DOCTYPE html>
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
    <link href="bootstrap/css/bootstrap.css" rel="stylesheet">
    <link href="bootstrap/css/bootstrap-responsive.css" rel="stylesheet">
    <!-- fix img bug on bootstrap + gmap -->
    <style type="text/css">
      html { height: 100% }
      body { height: 100%; margin: 0; padding: 0 }
      #map_canvas { height: 100%; width: auto}
      #map_canvas img { 
      max-width: none;
      }
    </style>
    <script type="text/javascript">
      function DisplayMap() {
      document.getElementById('top10').setAttribute("class", "inactive");
      document.getElementById('repartition').setAttribute("class", "inactive");
      document.getElementById('home').setAttribute("class", "inactive");
      document.getElementById('days').setAttribute("class", "inactive");
      document.getElementById('map').setAttribute("class", "active");
      initialize();
      }

      function DisplayDays() {
      document.getElementById('top10').setAttribute("class", "inactive");
      document.getElementById('repartition').setAttribute("class", "inactive");
      document.getElementById('home').setAttribute("class", "inactive");
      document.getElementById('days').setAttribute("class", "active");
      document.getElementById('map').setAttribute("class", "inactive");
      
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
      renderTo: 'map_canvas',
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
      document.getElementById('map').setAttribute("class", "inactive");
      var chart;
      $(document).ready(function() {
      chart = new Highcharts.Chart({
      chart: {
      renderTo: 'map_canvas',
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
      document.getElementById('map').setAttribute("class", "inactive");
      document.getElementById('map_canvas').innerHTML = '__TOPTEN__';
      document.getElementById('map_canvas').innerHTML += '__TOPTENPAGE__';
      }
      
      function DisplayHome() {
      document.getElementById('top10').setAttribute("class", "inactive");
      document.getElementById('repartition').setAttribute("class", "inactive");
      document.getElementById('home').setAttribute("class", "active");
      document.getElementById('days').setAttribute("class", "inactive");
      document.getElementById('map').setAttribute("class", "inactive");
      document.getElementById('map_canvas').innerHTML = "Welcome to the NAXSI Web Interface !";
      }
      
    </script>
    <script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript"></script>
    <script type="text/javascript" src="bootstrap/js/bootstrap.js"></script>
    <script type="text/javascript" src="js/highcharts.js"></script>

    <script type="text/javascript"
	    src="http://maps.googleapis.com/maps/api/js?key=AIzaSyBbKJnS1H3sZ3EAAlNTtzZogOH43O2NcMo&sensor=false">
    </script><script>
      var citymap = {};
      __CITYMAP__
      var cityCircle;
      
      function initialize() {
      var mapOptions = {
      zoom: 2,
      center: new google.maps.LatLng(46.2276380,2.2137490),
      mapTypeId: google.maps.MapTypeId.TERRAIN};
      
      var map = new google.maps.Map(document.getElementById("map_canvas"), mapOptions);
      var infoWindow = new google.maps.InfoWindow;
      for (var city in citymap) {
      var populationOptions = {
      strokeColor: "#FF0000",
      strokeOpacity: 0.8,
      strokeWeight: 2,
      fillColor: "#FF0000",
      fillOpacity: 0.35,
      map: map,
      center: citymap[city].center,
      radius: citymap[city].population * __CIRCLE_RATIO__,
      clickable: true};
      cityCircle = new google.maps.Circle(populationOptions);
      var listener = google.maps.event.addListener(cityCircle, "mouseover", function () {
      infoWindow.setContent('<h3>Number of exceptions :</h3>' + this.radius / 100);
      infoWindow.setPosition(this.getCenter());
      infoWindow.open(map);
      });
      var listener2 = google.maps.event.addListener(cityCircle, "mouseout", function() {infoWindow.close();});
      }
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
              <li class="active" id="home"><a href="/">Home</a></li>
              <li id="days" ><a href="#" onclick="javascript:DisplayDays()">Hit Per Days</a></li>
              <li id="repartition" ><a href="#"  onclick="javascript:DisplayRepartition()">Hits Repartition</a></li>
              <li id="top10" ><a href="#" onclick="javascript:DisplayTop()">Top 10</a></li>
              <li id="map" ><a href="#" onclick="javascript:DisplayMap()">World Map</a></li>
            </ul>
          </div>
        </div>
      </div>
    </div>
    
    <div id="map_canvas"></div>
  </body>
</html>
