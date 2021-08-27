function myFunction() {
  
  var threads = GmailApp.getInboxThreads();
  for (var i = 0; i < threads.length; i++) {
    var subject = threads[i].getFirstMessageSubject();
    var messages = threads[i].getMessages();
    for (var y=0;y<messages.length;y++){
      var message = messages[y];   
      var msg_date = message.getDate();
      var my_date = new Date();
      var diff = Math.abs(my_date - msg_date);
      var minutes = Math.floor((diff/1000)/1200);
      //Logger.log("Time diff: "+minutes);  
      if (minutes < 6000) {
        Logger.log(threads[i].getFirstMessageSubject());
        var body = message.getBody();
        var plain_body = message.getPlainBody();
        //Logger.log(message.getBody());
        var from = message.getFrom();
        var message_id =message.getHeader("Message-ID");
        var message_type = message.getHeader("Content-Type");
        var attachments = message.getAttachments();
        //Logger.log("Subject: "+subject+" Allegati:"+attachments.length);
        var raw_content = message.getRawContent();
        
        //if (attachments.length > 0){
        // for (z=0;z<attachments.length;z++){
        //   Logger.log("Allegato type:"+attachments[z].getContentType()+" Allegato name "+attachments[z].getName());
        //   var data = attachments[z].getDataAsString;
        // 
        // }        
        //}
        //var USERNAME = PropertiesService.getScriptProperties().getProperty('admin');
        //var PASSWORD = PropertiesService.getScriptProperties().getProperty('mypassword');

         var headers = {
          //"Authorization" : "Basic " + Utilities.base64Encode(USERNAME + ':' + PASSWORD)
          "Authorization": "Basic " + Utilities.base64Encode("admin:mypassword")
         };

        var references = message.getHeader("References");
        var data = {
          'subject': subject,
          'body': body,
          'plain_body': plain_body,
          'raw_content': raw_content,
          'from': from,
          //'header': header,
          'message_id': message_id,
          'message_type': message_type,
          'references': references,
        };

        var options = {
          'method' : 'POST',
          'headers':headers,
          'payload' : data
        };

        var response = UrlFetchApp.fetch("https://thehive.mydomain/api/",options);
        Logger.log(response.getContentText());
        Utilities.sleep(500);
      }
    }
  }
}
