<!DOCTYPE html>
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
    <style type="text/css">
      html { height: 100% }
      body { height: 100%; margin: 0; padding: 0 }
      #map_canvas { height: 100% }
    </style>
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
                             radius: citymap[city].population * 100,
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
<body onload="initialize()">
<div id="map_canvas"></div>
</body>
</html>
