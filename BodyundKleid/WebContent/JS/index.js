$(document).ready(function (){
	if(Cookies.get("login") == null){
		$.ajax({
			url: "./Indexservlet",
			type: "POST",
		});
	};
})