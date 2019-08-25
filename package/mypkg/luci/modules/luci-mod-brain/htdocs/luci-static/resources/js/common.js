window.onload = function(){
	// 滑动开关跳转
    var div2 = document.getElementById("div2");
    var div1 = document.getElementById("div1");
    div2.onclick = function(){
       div1.className = (div1.className == "close1") ? "open1" : "close1";
       div2.className = (div2.className == "close2") ? "open2" : "close2";
	}

	var div02 = document.getElementById("div02");
    var div01 = document.getElementById("div01");
    div02.onclick = function(){
       div01.className = (div01.className == "close1") ? "open1" : "close1";
       div02.className = (div02.className == "close2") ? "open2" : "close2";
	}
    
}