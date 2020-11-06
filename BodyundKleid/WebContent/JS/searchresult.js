$(document).ready(function(){ 	
	var usrinput = Cookies.get('searchcookie');
	$("#searched").text(usrinput);
	$.ajax({
		url : "Searchbar",
		type : "GET",
		data : {userinput : usrinput},
	}).done(function(response){
		var obj = JSON.parse(response);
		console.log(obj);
		
		console.log(obj[0].id);
		console.log(obj[0].titel);

		var length = obj.length;
		console.log(length);
		$('#searchresult-container').append("<p>Found result : "+length+"</p>");

		for(i=0 ; i<length ;  i++){
			$('#searchresult-container').append("<h3>"+obj[i].titel+"</h3>");
			$('#searchresult-container').append("<img src="+obj[i].bildpfad+".jpg>");
			$('#searchresult-container').append("<p>"+obj[i].beschreibung+"</p>");
			$('#searchresult-container').append("<p>Preis : "+obj[i].preis+"</p>");
		}
	})
	Cookies.remove('searchcookie');
})