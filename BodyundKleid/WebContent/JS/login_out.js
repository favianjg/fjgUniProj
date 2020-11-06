$(document).ready(function(){
	if(Cookies.get("login") !=null){
		$("#logintext").text("User Profil");
		$("#logintext").attr("href","userprofile.html");
		$("#logoutbtn").click(function(){
			$.ajax({
				url : "./Benutzerservlet",
				type : "POST",
				data : {logout : "logout"},
				success : function(data){
					alert("Logout erfolgreich");
					window.location.href = data;
				}
			});
		});
	};
})