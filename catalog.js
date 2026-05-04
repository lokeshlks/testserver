import express from 'express';
import cors from 'cors';
import { parseString } from 'xml2js';

let servicePORT = 5027; //Default Service PORT
const app = express();

app.use(cors());

const corsOptions = {
  //origin: ['https://' + DOMAIN_2, 'https://' + DOMAIN_3, 'https://' + DOMAIN_1, 'https://' + DOMAIN_0]
  //origin: "https://c"
  //origin: {["https://epay-store-2-2.myshopify.com","https://epay-store-2-2.myshopify.com"]: true}
  origin: '*'
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




app.get('/getDataV2', cors(corsOptions), async (req, res) => {

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
      try{

        const response = await fetch(UPInterfaceURL, fetchOptions);
        let jsonResponse = await response.text();

        console.log('CATALOG Response received : ' + jsonResponse.length );

      if((jsonResponse.includes('<RESULT>0</RESULT>'))&&(!jsonResponse.includes('<CATALOG />'))&&(jsonResponse.includes('<CATALOG>')))
            {
                        
              jsonResponse = await getUpdateJSONInfoData(jsonResponse,req);        
            }
            res.send(jsonResponse);  

          }catch(err){
            console.log('Retry catalog with default TID failed.......');
            console.log(err);
           
            let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT> Error processing request</RESULTTEXT></RESPONSE>';
                    
            res.send(str);
          }
        });
        
      
     /* try {
        const response = await fetch(UPInterfaceURL, fetchOptions);

        let jsonResponse = await response.text();
      //  console.log('CATALOG Response: ' + jsonResponse );
        res.send(jsonResponse);
          console.log('CATALOG Response sent : ' + jsonResponse.length );

      } catch (error) {
        
        console.log('CATALOG Fetch Error: ' + error );
       
      }
    });*/

  app.listen(Number(servicePORT), () => { 
    console.log(`Server started ...... ${servicePORT}`);  
  
  });


  
async function getUpdateJSONInfoData(catalogData,req) {
 // if((arr[3])&&(arr[3] == 'v2')) {
    catalogData = await getJSONInfoCatalog(catalogData,req,false); 
   // let bannerJsonData = await getBannersDataJson(req);
   // console.log(bannerJsonData);
   // catalogData = catalogData.replace('</RESPONSE>', bannerJsonData + '</RESPONSE>');
   //  let demoJsonData = await getDemoDataJson(req);
   //  console.log(demoJsonData);
   //  catalogData = catalogData.replace('</RESPONSE>', demoJsonData + '</RESPONSE>');         

 //}
 let categoryDisplay = 'yes'; //await getIsCategoryWiseDisplayEnabled(req);
 catalogData = catalogData.replace('</RESPONSE>', '<CATEGORY_WISE_PROVIDERS>' + categoryDisplay + '</CATEGORY_WISE_PROVIDERS></RESPONSE>')
 return catalogData;
}



async function getJSONInfoCatalog(response,req,bInfo) {


  let jsonResponse = response; 

try {
  if(!jsonResponse.includes('<INFOS>')) {
    return response;
  }
console.log('step:: 1');
  let languages = 'en'// await getSupportedLanguages(req);

  if(languages.includes(',')) {
    languages = languages.split(',');
  }else{
    let lang = [];
    lang.push(languages);
    languages = lang;
  }

  console.log('step:: 2 ' + languages);

  let arr_info = jsonResponse.split('<INFOS>'); 
  let final = arr_info[0]; 
  for(let y=1; y<arr_info.length;y++ ) {
    let bFoundDefaultLanguage =  false;
    let br = arr_info[y].split('</INFOS>');
    if(br[0].includes('<INFO>')){
      let x = br[0].split('<INFO>');
      for(let k=1; k<x.length;k++ ) {
          let bkr = x[k].split('</INFO>');
          let info_bloc = bkr[0];
          let defaultLangC = '<LANGUAGE>' + languages[0] + '</LANGUAGE>';
          let defaultLang = '<language>' + languages[0] + '</language>';
          if(info_bloc.includes(defaultLang) || info_bloc.includes(defaultLangC)){
            bFoundDefaultLanguage = true;
            break;
          }
      }
console.log('step:: 3');
      if((!bFoundDefaultLanguage)&&((br[0].includes('<language />'))||br[0].includes('<LANGUAGE />'))) {
        if(br[0].includes('<language />'))
          br[0] = br[0].replace('<language />','<language>' + languages[0] + '</language>');
        else if (br[0].includes('<LANGUAGE />')) {
          br[0] = br[0].replace('<LANGUAGE />','<language>' + languages[0] + '</language>');
        }
      }
      
    }
    
    final = final + '<INFOS>' + br[0] + '</INFOS>' + br[1];    
  }
  jsonResponse = final;

console.log('step:: 4');
  ////////////////////////////////////////////////////////////////////////////
  //let bannerJsonData = await getBannersDataJson(req);
  //jsonResponse.replace('</RESPONSE>', bannerJsonData + '</RESPONSE>');

  
  let iArray = jsonResponse.split('<INFOS>'); 
  let finalResponse = iArray[0];
  for(let x=1; x<iArray.length; x++){

      let defaultProductDisplayName = '';
      if(iArray[x-1].includes('<NAME>')) {
        
          let az = iArray[x-1].split('<NAME>');
          let bz = az[az.length - 1].split('</NAME>');
          defaultProductDisplayName = bz[0] ?  bz[0]:'';
      }

      let bx = iArray[x].split('</INFOS>') ;
      let infoBlock = '<INFOS>' + bx[0] + '</INFOS>';
      let InfoArray = {};

        
       // console.log('infoBlock:: '+ infoBlock);
        console.log('step:: 5');
       // let parseString = require('xml2js').parseString;
        console.log('step:: 6');

        parseString(infoBlock, function (err, result) {
          
        console.log('infoBlock parsed:: ');
        console.log(JSON.stringify(result));
            
            let defaultLang = '';
            for(let k=0; k<languages.length;k++)
            {
             console.log('language loop:: ' + k);
            let lang = languages[k];
            console.log('step:: 2');
            let found = false;
            for(let i=0; i<result.INFOS.INFO.length;i++)
            {
                console.log('info loop:: ' + i);
                let info = result.INFOS.INFO[i];
                let cmp_lang = '';
                if(info.language) {
                  cmp_lang = info.language[0];
                } else if(info.LANGUAGE) {
                  cmp_lang = info.LANGUAGE[0];
                }
             
                let brand = info.BRAND ? info.BRAND[0]:'';
                let desc_short = info.DESCRIPTION_SHORT ? info.DESCRIPTION_SHORT[0]:'';
                let desc_long = info.DESCRIPTION_LONG ? info.DESCRIPTION_LONG[0]:'';

                console.log('step:: 0_3');
                console.log('cmp_lang:: ' + cmp_lang);
                console.log('info.BRAND[0]:: ' + brand);
                console.log('info.DESCRIPTION_SHORT[0]:: ' + desc_short);
                console.log('info.DESCRIPTION_LONG[0]:: ' + desc_long);
                if((cmp_lang == lang)&&(brand.length)&&((desc_short.length)||(desc_long.length))){               
                  console.log('step:: 3');
                  if(info.DESCRIPTION_SHORT[0].length == 0){                    
                     info.DESCRIPTION_SHORT[0] = info.DESCRIPTION_LONG[0];                
                  }
                  console.log('step:: 4');
                  if(info.DESCRIPTION_LONG[0].length == 0){
                    
                     info.DESCRIPTION_LONG[0] = info.DESCRIPTION_SHORT[0];                
                  }

                  if(info.DISPLAY_NAME[0].length == 0){
                    info.DISPLAY_NAME[0] = defaultProductDisplayName;
                  }

                  InfoArray[lang] = JSON.parse(JSON.stringify(info));
                  found = true;

                  if(defaultLang.length == 0)
                    defaultLang = lang;

                  break;
                }
                  
              
            }      

            }
            if(InfoArray) {
                for(let j=0;j<languages.length;j++) {
          
                  if((!InfoArray[languages[j]])&&(defaultLang.length)) {
                    InfoArray[languages[j]] = JSON.parse(JSON.stringify(InfoArray[defaultLang]));
                  }
                }
            }
       
        });

console.log('step:: 7');

       let iresp = '<INFOSJSON>' + JSON.stringify(InfoArray) + '</INFOSJSON>' +  bx[1];
       //bInfo = true;
       if(bInfo) {
          iresp =  infoBlock + bx[1];
          iresp = iresp.replace('</INFOS>', '</INFOS>\n<INFOSJSON>' + JSON.stringify(InfoArray) + '</INFOSJSON>')
       }

      finalResponse = finalResponse + iresp;
     
    }

    return finalResponse;

  } catch (err) {
    console.log('Exception in getJSONInfoCatalog()');
    console.log(JSON.stringify(err));
    return response;
  }
      
}