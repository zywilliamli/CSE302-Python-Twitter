$(document).ready(function() {

    var message = "null";
    var userName = "null";
    var time = "00:00:00";
    var d = new Date();

   setInterval(ping_check, 60000)
    function ping_check(){
        if (logged_in == true){
            $.post('/ping_check', function(data){
            });
        }
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
            }else{
                alert("!*Broadcast FAILED TO SEND*!" );
            }
        });
        e.preventDefault();
    });

    $("#logout").click(function(e) {
        $.post('/signout', function(data){
            if (data == '0'){
                logged_in = false
            }
//            $(".index").html(data)
        });
        e.preventDefault();
    });

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
                broadcastUpdate()
                messageUpdate()
            }else{
                logged_in = false
                alert("Invalid Username or Password");
                }
        });
        e.preventDefault();
    });

      function usrUpdate(){
      $.ajax({ url: "/update_users" , success: function(data) {
            var obj = JSON.parse(data);
            document.getElementById("UserList").innerHTML = "<h2 onclick = 'JavaScript:reset();'>USERS</h2>";
            for(var key in obj){
                document.getElementById("UserList").innerHTML += "<p onclick = document.getElementById('sendName').value="+"'"+obj[key]+"'"+'>'+obj[key]+"</p>"
            }
        }, datatype: "text"})
      }

      function broadcastUpdate(){
      $.ajax({ url: "/update_broadcast" , success: function(data) {
            var obj = JSON.parse(data);
            for(var key in obj){
                document.getElementById("broadcast_message").innerHTML += "<p>"+obj[key]+"</p>"
            }
        }, datatype: "text"})
      }

      function messageUpdate(){
      $.ajax({ url: "/update_message" , success: function(data) {
            var obj = JSON.parse(data);
            for(var key in obj){
                document.getElementById("message").innerHTML += "<p>"+obj[key]+"</p>"
            }
        }, datatype: "text"})
      }

     (function updateUsers(){
       setTimeout(function(){
          $.ajax({ url: "/update_users" , success: function(data) {
            var obj = JSON.parse(data);
            document.getElementById("UserList").innerHTML = "<h2 onclick = 'JavaScript:reset();'>USERS</h2>";
            for(var key in obj){
                document.getElementById("UserList").innerHTML += "<p onclick = document.getElementById('sendName').value="+"'"+obj[key]+"'"+'>'+obj[key]+"</p>"
            }
            updateUsers();
        }, datatype: "text"});
        },20000);})();

      (function updateBroadcast(){
       setTimeout(function(){
          $.ajax({ url: "/update_broadcast" , success: function(data) {
            var obj = JSON.parse(data);
            document.getElementById("broadcast_message").innerHTML = "<h2 onclick = 'JavaScript:reset();'></h2>";
            for(var key in obj){
                document.getElementById("broadcast_message").innerHTML += "<p>"+obj[key]+"</p>"
            }
            updateBroadcast();
        }, datatype: "text"});
        },20000);})();

     (function updateMessages(){
       setTimeout(function(){
          $.ajax({ url: "/update_message" , success: function(data) {
            var obj = JSON.parse(data);
            document.getElementById("message").innerHTML = "<h2 onclick = 'JavaScript:reset();'></h2>";
            for(var key in obj){
                document.getElementById("message").innerHTML += "<p>"+obj[key]+"</p>"
            }
            updateMessages();
        }, datatype: "text"});
        },5000);})();

});



function reset(){
        document.getElementById("ChatLog").innerHTML = " ";
}

window.onbeforeunload = function(){
   alert("Bye : " + userName );
}