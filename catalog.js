import express from 'express';
import cors from 'cors';

let servicePORT = 5027; //Default Service PORT
const app = express();

app.use(cors());

const corsOptions = {
  //origin: ['https://' + DOMAIN_2, 'https://' + DOMAIN_3, 'https://' + DOMAIN_1, 'https://' + DOMAIN_0]
  origin: "https://epay-store-2-2.myshopify.com"
//  origin: ['https://localhost']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // enable pre-flight request for all routes

function getTimeStamp() {

  var date = new Date().getDate(); 
  console.log(date);
  date = (date < 10 ? '0' : '') + date;
  var month = new Date().getMonth() + 1; 
  month = (month < 10 ? '0' : '') + month;
  var year = new Date().getFullYear();   
  var hours = new Date().getHours(); 
  hours = (hours < 10 ? '0' : '') + hours;
  var min = new Date().getMinutes(); 
  min = (min < 10 ? '0' : '') + min;
  var sec = new Date().getSeconds(); 
  sec = (sec < 10 ? '0' : '') + sec;

  console.log(sec);
  var timeStamp = year + month + date
    + hours + min + sec;

  return timeStamp;

}


function getFormattedTime() {

  var date = new Date().getDate(); 
  console.log(date);
  date = (date < 10 ? '0' : '') + date;
  var month = new Date().getMonth() + 1;
  month = (month < 10 ? '0' : '') + month;
  var year = new Date().getFullYear(); 
  var hours = new Date().getHours(); 
  hours = (hours < 10 ? '0' : '') + hours;
  var min = new Date().getMinutes(); 
  min = (min < 10 ? '0' : '') + min;
  var sec = new Date().getSeconds(); 
  sec = (sec < 10 ? '0' : '') + sec;

  console.log(sec);


  var currentDate = year + '-' + month + '-' + date
    + ' ' + hours + ':' + min + ':' + sec;
  console.log(currentDate);


  return currentDate;

}


app.get('/', cors(corsOptions), async (req, res) => {
  res.send('Hello World!')
})


app.get('/getData', cors(corsOptions), async (req, res) => {

 var txid = getTimeStamp();
      var x = Math.random() * 1000000;      
      var y = x.toString().split('.');      
      txid = txid + y[0];

 let currentDate = getFormattedTime();         

 let UPInterfaceURL = 'https://precision.epayworldwide.com/up-interface/'
      let userIdHost = 'UPTest_93889311'
      let userPaswdHost = '028eb6be0b280853';
      console.log('user cred..' + userIdHost + userPaswdHost);
      let tidhead = '<TERMINALID>93889311</TERMINALID>';

      const fetchOptions = {
        method: 'POST',

        body: '<REQUEST type="CATALOG">' +
          '<CATALOGPAGE>1</CATALOGPAGE>' +
          '<CATALOGVERSION>3</CATALOGVERSION>' +
          '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
          '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
          tidhead +
          '<TXID>' + txid + '</TXID>' +
          '<USERNAME>' + userIdHost + '</USERNAME>' +
          '</REQUEST>',

        headers: {
          'Content-Type': 'text/xml',
         // 'Content-Type': 'application/xml',
        },
   

      }
    
      console.log('CATLOG Request: ' + UPInterfaceURL);

      
      try {
        const response = await fetch(UPInterfaceURL, fetchOptions);

        let jsonResponse = await response.text();
      //  console.log('CATALOG Response: ' + jsonResponse );
        res.send(jsonResponse);
          console.log('CATALOG Response sent : ' + jsonResponse.length );

      } catch (error) {
        
        console.log('CATALOG Fetch Error: ' + error );
       
      }
    });

  app.listen(Number(servicePORT), () => { 
    console.log(`Server started ...... ${servicePORT}`);  
  
  });