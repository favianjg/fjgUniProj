 $(document).ready(function(){
	var value = "";
	$("#damen").click(function(){
		value = "damen";
		$.session.set("click",value);
	});
	
	$("#herren").click(function(){
		value = "herren";
		$.session.set("click",value);
	});
	
	$("#kinder").click(function(){
		value = "kinder";
		$.session.set("click",value);
	});
	
	$("#damenkl").click(function(){
		value = "damen kleider";
		$.session.set("click",value);
	});
	
	$("#damenrc").click(function(){
		value = "damen röcke";
		$.session.set("click",value);
	});
	
	$("#herrenan").click(function(){
		value = "herren anzug";
		$.session.set("click",value);
	});
	
	$("#herrenkr").click(function(){
		value = "herren krawatte";
		$.session.set("click",value);
	});
	
	$("#kindersc").click(function(){
		value = "kinder schuhe";
		$.session.set("click",value);
	});
	
	$("#kindersh").click(function(){
		value = "kinder shirt";
		$.session.set("click",value);
	});
})