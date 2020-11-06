$(document).ready(function sendform(){
	$("#registerform").submit(function(event){
		event.preventDefault();
		var usrmail = $("#Emailreg").val();
		var pass = $.trim($("#Passwortreg").val());
		var repass = $.trim($("#Passwortbst").val());
		var flag = "reg";
				
		if(pass.length == 0){
			alert("Passwort ungültig");
		}
		else if(pass != repass){
			alert("Passwort ungültig");
		}
		else{
			$("#done").text("wird bearbeitet...");
			$.ajax({
				url : "Benutzerservlet",
				type:"POST",
				data : {email : usrmail, passwort : pass, reg : flag},
				success : function(data){
					if(data == "reg"){
						$("#done").text("Registrierung erfolgreich.");
						$("#registerform")[0].reset();
						location.reload();
					}else if(data == "exist"){
						$("#done").text("Registrierung fehler. Benutzer bereits existiert");
						$("#registerform")[0].reset();
					}else {
						$("#done").text("Registrierung fehler. Ueberpruefen Sie Ihre Eingabe");
						$("#registerform")[0].reset();
					}
				},
				error : function(textStatus){
					alert("Registrierung Fehler."+textStatus);
				}
			})
		}
	});
	
	$("#loginform").submit(function(event){
		event.preventDefault();
		var usrmail = $("#Emaillog").val();
		var pass = $.trim($("#Passwortlog").val());
		var flag = "log";
		var url = null;
		
		$("#done").text("wird bearbeitet...");
		
		$.ajax({
			url:"Benutzerservlet",
			type:"POST",
			data : {email : usrmail, passwort : pass, reg : flag},
			success : function(data, textStatus){
				alert("Anmeldung erfolgreich");
				$("#done").text("Redirecting..");
				window.location.href = data;
			},
			error:function(XMLHttpRequest, textStatus, errorThrown){
				alert(textStatus)
				$("#done").text("Fehler aufgetreten laden Sie die Seite neu und versuchen Sie nochmal");
			}
		})
	});	
});