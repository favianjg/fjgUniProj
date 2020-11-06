$(document).ready(function(){
	$("#searchform").submit(function(event){
		event.preventDefault();
		var input = $("#searchinput").val();
		alert(input);
		Cookies.set('searchcookie', input);
		window.location.href = "searchresult.html";
	})
})
