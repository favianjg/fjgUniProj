$(document).ready(function(){
	var value = $.session.get("click");
	console.log(value);
	$.ajax({
		url : "./ClothesServlet",
		type: "POST",
		data : {click: value}
	}).done(function(response){
		var obj = JSON.parse(response);
		var length = obj.length;
		var text = $.session.get("click");
		console.log(obj);
		
		$("#clickuser").append("<h2 style=\"margin-left: 2%\">"+text+"</h2>");

		for(i=0 ; i<length ; i++){
			$("#clickresult").append("<figure class=\"gesamt\">");
			for(j=0 ; j<4 ; j++){
				$("#clickresult").append("<figure class=\"einzel\">");		
				$("#clickresult").append("<a href=\"article.html\" id=\"clothesbild\">");
				$("#clickresult").append("<img src=\""+obj[i].bildpfad+"\">");
				$("#clickresult").append("</a>");
				$("#clickresult").append("<a href=\"article.html\" id=\"clothescaption\">");
				$("#clickresult").append("<figcaption>"+obj[i].beschreibung+"<br> Rot, Blau, Grün <br>S, M, L</figcaption>");
				$("#clickresult").append("</a>");
				$("#clickresult").append("</figure>");
				i++;
			};
			$("#clickresult").append("</figure>");
			$("#clothesbild").click(function(){
				$.session.set("artikelid", obj[i].id);
			});
			$("#clothescaption").click(function(){
				$.session.set("artikelid", obj[i].id);
			});
		};
		
		$.session.remove("click");
	})
})