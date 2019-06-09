$(document).ready(function() {

    var message = "null";
    var userName = "null";
    var time = "00:00:00";
    var d = new Date();

    function addMessage(type,name,time,message){
        document.getElementById("conversation").innerHTML += '<li id='+type+'><div id="message"><time id = "time">'+name+' - '+time+'</time> <br> <strong>'+message+'</strong></div></li><br>'
    }

   setInterval(ping_check, 5000)
    function ping_check(){
        $.post('/ping_check', function(data){
        });
    }
   setInterval(load_page, 1000)
    function load_page(){
        console.log(logged_in)
        if (logged_in == true) {
            $("#LoginScreen").hide();
            $("#MainWindow").show();
        }
        else {
            $("#LoginScreen").show();
            $("#MainWindow").hide();
        }
    }



    $("#sendMessage").click(function(e) {
        $.post("/sendMessage", {"data": $("input[name='MsgS']").val(), "name": $("input[name='NmeS']").val()}).done(function(string) {
            if(string == '0'){
                alert("Message Sent!" );

                $("#The-Msg").show();
                addMessage("user",userName,d.getHours()+":"+d.getMinutes()+":"+d.getSeconds(),document.getElementById("msg").value);
                $('#The-Msg').scrollTop($('#The-Msg')[0].scrollHeight);
            }else{
                alert("!*MESSAGE FAILED TO SEND*!" );
            }
        });
        e.preventDefault();
    });

    $("#broadcastMessage").click(function(e) {
        $.post("/broadcast", {"data": $("input[name='MsgB']").val()}).done(function(string) {
            if(string == '0'){
                alert("Broadcast Sent!" );

                $("#Broadcast").show();
                addMessage("user",userName,d.getHours()+":"+d.getMinutes()+":"+d.getSeconds(),document.getElementById("msg").value);
                $('#Broadcast').scrollTop($('#Broadcast')[0].scrollHeight);
            }else{
                alert("!*Broadcast FAILED TO SEND*!" );
            }
        });
        e.preventDefault();
    });

//    $("#logout").click(function(e) {
//        $.post('/signout', function(data){
////            $(".index").html(data)
//        });
//        $.post("/sendFile", {"fileName": $("input[name='file']").val(), "name": $("input[name='NmeS']").val()}).done(function(string) {
//            if(string == '0'){
//                alert("File Sent Successfully" );
//            }else{
//                alert("Failed to Send" );
//            }
//        });
//        e.preventDefault();
//    });

    $("#reset").click(function(e) {
        document.getElementById("p1").innerHTML = " "
        $.ajax({ type: "POST", url: "/reset",}).done(function() {
            alert("Reset!");
            $("#The-Msg").hide();
            $("#The-Msginput").val(string);
        });
        e.preventDefault();
    });

    $("#signin").click(function(e) {
        $.ajax({ url: "/signin", data: { username: $('#nameUser').val(), password: $('#password').val(), location: $('#location').val() } }).done(function(data) {
            if(data == '0'){
                userName = document.getElementById("nameUser").value;
                alert("Welcome : " + userName );
                $("#LoginScreen").hide();
                $("#MainWindow").show();
                logged_in = true
                usrUpdate()
            }else{
                logged_in = false

                alert("Invalid Username or Password");
                }
        });
        e.preventDefault();
    });

    $("#refresh").click(function(e) {
        $.post('/refreshBroadcast', function(data){
            $(".refreshBroadcast").html(data)
            usrUpdate()

        });
        e.preventDefault();
    });

   (function poll(){
       setTimeout(function(){
          $.ajax({  url: "/getMessage", success: function(data){
            //Update your dashboard gauge

            var temp = data.split("%");
            if (time != temp[temp.length - 2]){
                for(var i = 1; i < temp.length - 1;i+=3){
                    if(temp[i+2] > time){
                    time = temp[i+2];
                    addMessage("peer",temp[i],temp[i+2],temp[i+1]);
                    $('#The-Msg').scrollTop($('#The-Msg')[0].scrollHeight);
                    }
                }

            }
            //Setup the next poll recursively
            poll();
           }, dataType: "text"});
        }, 10000);
    })();

      function usrUpdate(){
      $.ajax({ url: "/getUsers" , success: function(data) {
            var obj = JSON.parse(data);
            document.getElementById("UserList").innerHTML = "<h2 onclick = 'JavaScript:reset();'>USERS</h2>";
            for(var key in obj){
                //document.getElementById("UserList").innerHTML += '<p>'+Object.keys(obj)[0]+'</p>'
                document.getElementById("UserList").innerHTML += "<p onclick = document.getElementById('sendName').value="+"'"+key+"'"+'>'+key+" : "+obj[key]+"</p>"
            }
        }, datatype: "text"})
      }

     (function updateUsers(){
       setTimeout(function(){
          $.ajax({ url: "/getUsers" , success: function(data) {
            var obj = JSON.parse(data);
            document.getElementById("UserList").innerHTML = "<h2 onclick = 'JavaScript:reset();'>USERS</h2>";
            for(var key in obj){
                //document.getElementById("UserList").innerHTML += '<p>'+Object.keys(obj)[0]+'</p>'
                document.getElementById("UserList").innerHTML += "<p onclick = document.getElementById('sendName').value="+"'"+key+"'"+'>'+key+" : "+obj[key]+"</p>"
            }
            updateUsers();
        }, datatype: "text"});
        },20000);})();

});



function reset(){
        document.getElementById("ChatLog").innerHTML = " ";
}

window.onbeforeunload = function(){
   alert("Bye : " + userName );
}
