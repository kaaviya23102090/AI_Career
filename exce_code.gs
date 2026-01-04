// This handles Login Checks via GET
function doGet(e) {
  var action = e.parameter.action;
  var email = e.parameter.email;
  var pass = e.parameter.password;
  
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName("Users");
  var rows = sheet.getDataRange().getValues();

  if (action === "login") {
    for (var i = 1; i < rows.length; i++) {
      if (rows[i][0] === email && rows[i][1] === pass) {
        return ContentService.createTextOutput("Success").setMimeType(ContentService.MimeType.TEXT);
      }
    }
    return ContentService.createTextOutput("Invalid").setMimeType(ContentService.MimeType.TEXT);
  }
}

// This handles Signups via POST
function doPost(e) {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = ss.getSheetByName("Users") || ss.insertSheet("Users");
  
  var data = JSON.parse(e.postData.contents);
  sheet.appendRow([data.email, data.password]);
  }
  return ContentService.createTextOutput("Success").setMimeType(ContentService.MimeType.TEXT);
}
