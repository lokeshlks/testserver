const express = require('express');
const cors = require('cors');
const Os =require('os');  //to get current os details

let config = null;
let PWD_SECRET_KEY = '9b94352577fbc1f12355e1dd6aab15e4';
let PWD_IV = 'd6d1b322f15d28ba' ;

//let Securitykey = ''; 
//let initVector = '';


const fetch = require('node-fetch-with-proxy');
let proxy_url = null;

let servicePORT = 5027; //Default Service PORT
const app = express();

const crypto = require('crypto');
let secret = '';

const https = require("https");

let TEST_IP_AZURE = '129.232.237.210';//'183.82.161.163';//'183.82.160.65'; 

const fs = require("fs");
var path = require('path');

let isTest;

const bodyParser = require('body-parser');
app.use(bodyParser.text({limit: "50mb"}));
app.use(bodyParser.json({ limit: "50mb" }))
app.use(bodyParser.urlencoded({limit: "50mb", extended: false }));


let language_list = [];
const rateLimit = require('express-rate-limit');
let campaignCounter = 0;
let otpTest;
let redeem_option = '0';
let username_voda_service = '';
let password_voda_service = '';
let senderName_voda_service = '';
let client_application_id_voda_service = '';
let partner_id_voda_service = '';
let content_name_voda_service = '';

let domain0_support_url = '';
let domain1_support_url = '';
let domain2_support_url = '';
let domain3_support_url = '';

let DOMAIN_0_GOOGLE_PASS = 'no';
let DOMAIN_1_GOOGLE_PASS = 'no';
let DOMAIN_2_GOOGLE_PASS = 'no';
let DOMAIN_3_GOOGLE_PASS = 'no';

let DOMAIN_0_APPLE_PASS = 'no';
let DOMAIN_1_APPLE_PASS = 'no';
let DOMAIN_2_APPLE_PASS = 'no';
let DOMAIN_3_APPLE_PASS = 'no';

let DOMAIN_0_SORT_INFO = '';
let DOMAIN_1_SORT_INFO = '';
let DOMAIN_2_SORT_INFO = '';
let DOMAIN_3_SORT_INFO = '';

let domain0_theme = '';
let domain1_theme = '';
let domain2_theme = '';
let domain3_theme = '';

let domain0_upload_txn = 'no';
let domain1_upload_txn = 'no';
let domain2_upload_txn = 'no';
let domain3_upload_txn = 'no';

let DOMAIN_0_PAYMENT_EAN = '';
let DOMAIN_1_PAYMENT_EAN = '';
let DOMAIN_2_PAYMENT_EAN = '';
let DOMAIN_3_PAYMENT_EAN = '';

let DOMAIN_0_COUNTRY_CODE = 'AE';
let DOMAIN_1_COUNTRY_CODE = 'AE';
let DOMAIN_2_COUNTRY_CODE = 'AE';
let DOMAIN_3_COUNTRY_CODE = 'AE';

let logopath = '';
let domain0_logo = '';
let domain1_logo = '';
let domain2_logo = '';
let domain3_logo = '';

let infobip_msg_sender;

let AllowedIPs = null;
let BlockedIPs = null;

let DOMAIN_0 = '';
let DOMAIN_1 = '';
let DOMAIN_2 = '';
let DOMAIN_3 = '';

let DOMAIN_0_SORT_ORDER = 'F';
let DOMAIN_1_SORT_ORDER = 'F';
let DOMAIN_2_SORT_ORDER = 'F';
let DOMAIN_3_SORT_ORDER = 'F';


let DOMAIN_0_TITLE = '';
let DOMAIN_1_TITLE = '';
let DOMAIN_2_TITLE = '';
let DOMAIN_3_TITLE = '';

let DOMAIN_0_FOOTER_L_NAME = '';
let DOMAIN_0_FOOTER_R_NAME = '';
let DOMAIN_0_FOOTER_L_LINK = '';
let DOMAIN_0_FOOTER_R_LINK = '';

let DOMAIN_1_FOOTER_L_NAME = '';
let DOMAIN_1_FOOTER_R_NAME = '';
let DOMAIN_1_FOOTER_L_LINK = '';
let DOMAIN_1_FOOTER_R_LINK = '';

let DOMAIN_2_FOOTER_L_NAME = '';
let DOMAIN_2_FOOTER_R_NAME = '';
let DOMAIN_2_FOOTER_L_LINK = '';
let DOMAIN_2_FOOTER_R_LINK = '';

let DOMAIN_3_FOOTER_L_NAME = '';
let DOMAIN_3_FOOTER_R_NAME = '';
let DOMAIN_3_FOOTER_L_LINK = '';
let DOMAIN_3_FOOTER_R_LINK = '';

let customer_name_D0;
let customer_name_D1;
let customer_name_D2;
let customer_name_D3;


let user_domain_1 = '';
let user_domain_3 = '';
let user_domain_2 = ''; 
let user_domain_0 = '';
let user_xml = '';

let domain0_delivery_mode = '';
let domain1_delivery_mode = '';
let domain2_delivery_mode = '';
let domain3_delivery_mode = '';

let promoURL = '';
let promoUser = '';
let promoPassword = '';

let sharafTestTID = '';
let logUpdateFrequency = '';
let TestTIDSUBSCRIPTION_DOMAIN_0 = '';
let TestEANSUBSCRIPTION_DOMAIN_0 = '';

let refund_allowed_domain0 = '0';
let cancel_allowed_domain0 = '0';
let refund_allowed_domain1 = '0';
let cancel_allowed_domain1 = '0';
let refund_allowed_domain2 = '0';
let cancel_allowed_domain2 = '0';
let refund_allowed_domain3 = '0';
let cancel_allowed_domain3 = '0';

let cashier_allowed_domain0 = '0';
let cashier_allowed_domain1 = '0';
let cashier_allowed_domain2 = '0';
let cashier_allowed_domain3 = '0';


let password_domain_1 = '';
let password_domain_3 = '';
let password_domain_2 = ''; 
let password_domain_0 = '';
let password_xml = '';
let password_updateCatalog = '';

let CheckoutSecretKey = '';
let CheckoutSecretKey_preprod = '';
let Auth_vodacom = '';
let checkout_protocol = '0';

let defaultTID_domain_1 = '';
let defaultTID_domain_3 = '';
let defaultTID_domain_2 = '';
let defaultTID_domain_0 = '';

let campaignTID_domain_0 = '';
let campaignTID_domain_1 = '';
let campaignTID_domain_2 = '';
let campaignTID_domain_3 = '';

let campaign_domain_0 = '';
let campaign_domain_1 = '';
let campaign_domain_2 = '';
let campaign_domain_3 = '';

let payment_methods_supported_domain_2 =  '';
let payment_methods_supported_domain_3 =  '';
let payment_methods_supported_domain_1 =  '';
let payment_methods_supported_domain_0 =  '';

let use_domain_0_xml_interface = '';
let use_domain_1_xml_interface = '';
let use_domain_3_xml_interface = '';
let use_domain_2_xml_interface = '';

let refreshCatalogTime = '';

let UPInterfaceURL = '';
let CheckoutURL = '';
let CheckoutURL_Test = '';
let XMLInterfaceURL = '';
let vodacomValidationPhoneURL = '';
let vodacomSMSURL = '';
let vodacomChargeURL = '';
let paymentInfoURL = '';

let infobipURL = '';
let infobipAuth = '';

const algorithm = "aes-256-cbc";
let currentDate;

let machine_name = '';
let service_name = '';

//Detail of directories for test
const catalogDirectory = 'C:/Work/Web/WebServer/master/catalogs/';
const folderNamePass = 'C:/Work/Web/WebServer/master/passes/';
const folderKeys = 'C:/Work/Web/WebServer/master/keys/';
const templatedir = 'C:/Work/Web/WebServer/master/retailer/';
const configdir = 'C:/Work/Web/WebServer/master/config/';
let log_directory = 'C:/Work/Web/WebServer/logs/';
let log_directory_temp = 'C:/Work/Web/WebServer/temp/';
const languagesDirectory = 'C:/Work/Web/WebServer/master/languages/';

let carrefour_user_access_code = '';
let carrefour_source_reference = '';
let carrefour_booking_source = '';
let carrefour_url = '';

let DOMAIN_0_FONT_NAME = 'Century Gothic';
let DOMAIN_1_FONT_NAME = 'Century Gothic';
let DOMAIN_2_FONT_NAME = 'Century Gothic';
let DOMAIN_3_FONT_NAME = 'Century Gothic';
//live
//const catalogDirectory = 'node-app/master/catalogs/';
//const folderNamePass = 'node-app/master/passes/';
//const folderKeys = 'node-app/master/keys/';
//const templatedir = 'node-app/master/retailer/';
//const configdir = 'node-app/master/config/';
//const languagesDirectory = 'node-app/master/languages/'
//let log_directory = 'website/logs/';
//let log_directory_temp = 'website/logs/temp/';

let folderName = '';




let processingchannelid = '';
let getContractURL = '';

const shell = require('shelljs');

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 minutes
  max: 3, // limit each IP to 500 requests per windowMs
  message: { status: "Too many request from this IP" },
  requestWasSuccessful: (req, res) => res.statusCode < 400,
  skipSuccessfulRequests: true,
  keyGenerator: function (req) {
    return req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  },

  handler: (req, res, next, options) =>{    
    const clientip = req.headers['incap-client-ip'] ;
    var txid = getTimeStamp();
    var x = Math.random() * 1000000000;    
    var y = x.toString().split('.');  
    txid = '00000000'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
    

    let session_id = txid;
    let host_log = req.hostname.split('.');
    let method = 'IP_LIMIT';
    let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
    let log_suffix = '\n</LOG></SESSION_LOG>';
    
    console.log(log_prefix + 'BLOCKED!! Client IP: ' + clientip + '. Too many request from this IP.' + log_suffix);
    res.status(options.statusCode).send(options.message) ; 
  }


});

const limiter_amount_mismatch = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 1 minutes
  max: 1, // limit each IP to 500 requests per windowMs
  message: { status: "Amount mismatch" },
  statusCode: 451,
  requestWasSuccessful: (req, res) => res.statusCode < 450,
  skipSuccessfulRequests: true,
  keyGenerator: function (req) {
    return req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  },

  handler: (req, res, next, options) =>{
    const clientip = req.headers['incap-client-ip'] ;
    var txid = getTimeStamp();
    var x = Math.random() * 1000000000;    
    var y = x.toString().split('.');  
    txid = '00000000'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
    
   
    let session_id = txid;
    let host_log = req.hostname.split('.');
    let method = 'IP_LIMIT';
    let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
    let log_suffix = '\n</LOG></SESSION_LOG>';
    
    console.log(log_prefix + 'BLOCKED!! Client IP: ' + clientip + '. Amount mismatch.' + log_suffix);
    res.status(options.statusCode).send(options.message) ; 
  }
});

const limiter_amount_mismatch_domain_3 = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 1 minutes
  max: 1, // limit each IP to 500 requests per windowMs
  message: { status: "Amount mismatch" },
  statusCode: 451,
  requestWasSuccessful: (req, res) => res.statusCode < 450,
  skipSuccessfulRequests: true,
  keyGenerator: function (req) {
    return req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  },
  handler: (req, res, next, options) =>{
    const clientip = req.headers['incap-client-ip'] ;
    var txid = getTimeStamp();
    var x = Math.random() * 1000000000;    
    var y = x.toString().split('.');  
    txid = 'EPAY-'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
    

    let session_id = txid;
    let host_log = req.hostname.split('.');
    let method = 'IP_LIMIT';
    let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
    let log_suffix = '\n</LOG></SESSION_LOG>';
    
    console.log(log_prefix + 'BLOCKED!! Client IP: ' + clientip + '. Amount mismatch.' + log_suffix);
    res.status(options.statusCode).send(options.message) ; 
  }
  
});
app.use(cors());

const corsOptions = {
  //origin: ['https://' + DOMAIN_2, 'https://' + DOMAIN_3, 'https://' + DOMAIN_1, 'https://' + DOMAIN_0]
  //origin: "https://*.epayworldwide.com"
  origin: ['https://localhost']
};

let Securitykey = '';
let initVector = '';

//Encrypting text
function encrypt(message) {
  // the cipher function
  const cipher = crypto.createCipheriv(algorithm, Securitykey, initVector);
  let encryptedData = cipher.update(message, "utf-8", "hex");
  encryptedData += cipher.final("hex");
  console.log("Encrypted message: " + encryptedData);
  return encryptedData;
}

// Decrypting text
function decrypt(encryptedData) {
  // the decipher function
  const decipher = crypto.createDecipheriv(algorithm, Securitykey, initVector);
  let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
  decryptedData += decipher.final("utf8");
  console.log("Decrypted message: " + decryptedData);
  return decryptedData;

}
// Decrypting pwd
function decrypt_pwd(encryptedData,secret,iv) {
  // the decipher function
  const decipher = crypto.createDecipheriv(algorithm, secret, iv);
  let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
  decryptedData += decipher.final("utf8"); 
  return decryptedData;

}

async function getCheckoutErrorResponse(jsonResponse,req) {
  console.log(jsonResponse);
  let error_resp = 'Status: ' + (jsonResponse.status ? jsonResponse.status : 'Declined') + '. ';  

  error_resp =  error_resp + (jsonResponse.response_summary ? ('\n'+ jsonResponse.response_summary):'');

  if(jsonResponse.actions) {
   if(jsonResponse.actions[0]) {
      if(jsonResponse.actions[0].response_summary) {
         error_resp =  error_resp + jsonResponse.actions[0].response_summary + '. ';
      } 
   }
  }

  let card_info_line = (jsonResponse.source.scheme ? (jsonResponse.source.scheme  + ' '): '')
                      + (jsonResponse.source.card_type ? jsonResponse.source.card_type : 'CREDIT')
                      + (jsonResponse.source.last4 ? ' (' + jsonResponse.source.last4 + ') + '  : ' ')
                      + (jsonResponse.source.card_wallet_type ? jsonResponse.source.card_wallet_type:'Card');

  error_resp = error_resp +  (error_resp.length > 0 ? ('\n' + card_info_line) : '');

  error_resp = error_resp + '. Unfortunately, your payment has failed. We kindly ask you to try updating your credit or debit card details by clicking on the retry button.';
  console.log(error_resp);
  return error_resp;
}

async function checkIfRefererAllowed(referer,req) {

  const clientip = req.headers['incap-client-ip'] ; 
  if((clientip == TEST_IP_AZURE)&&( (req.headers.campaign == 'en') ||  (req.headers.campaign == 'ar') ||  (req.headers.campaign == 'tr') || ( req.headers.campaign == 'du'))) {
     return true;
  }

   let hosta = req.hostname.split('.');
   let host = hosta[0];
    if(isTest) {
     console.log('fun checkIfRefererAllowed returns true for test');
      return true;
    }
   //let ref = 'https://' + req.hostname;
   if(referer.substring(0,8) == 'https://') {
     let arr = referer.split('https://');
     let arr_1 = arr[1].split('.');
     let host_ref = arr_1[0]; //endlessaisle
     let host_main_domain = arr_1[1]; //epayworldwide
     if((host_main_domain != 'epayworldwide') || (host != host_ref) || (hosta[1] != 'epayworldwide')) {
      return false;
     } else if(config[host_ref]) {
      return true;
     } else {      
        let domain_0_sub = config.DOMAINS.DOMAIN_0 ? (config.DOMAINS.DOMAIN_0.split('.'))[0] : 'none';
        let domain_1_sub = config.DOMAINS.DOMAIN_1 ? (config.DOMAINS.DOMAIN_1.split('.'))[0] : 'none';
        let domain_2_sub = config.DOMAINS.DOMAIN_2 ? (config.DOMAINS.DOMAIN_2.split('.'))[0] : 'none';
        let domain_3_sub = config.DOMAINS.DOMAIN_3 ? (config.DOMAINS.DOMAIN_3.split('.'))[0] : 'none';
        if((domain_0_sub == host_ref)||(domain_1_sub == host_ref)||(domain_2_sub == host_ref)||(domain_3_sub == host_ref)){
           return true;
        }
     }

   }
   return false;
}

function mask_json_data (body, log_prefix,log_suffix) {

  let obj = JSON.parse(body); 
  //console.log(obj);

if(obj.messages)
  {
  if(obj.messages[0])
  {
    
    if(obj.messages[0].destinations)
    {
      if(obj.messages[0].destinations[0].to)
      {
        let phone = obj.messages[0].destinations[0].to;
        let str = '*';
        let mask = str.repeat(phone.length - 5)   
        obj.messages[0].destinations[0].to = phone.substring(0, 3) + mask + phone.substring(phone.length - 2, phone.length);
      }

    }
    
    if(obj.messages[0].to)
    {
      let phone = obj.messages[0].to;
      let str = '*';
      let mask = str.repeat(phone.length - 5)   
      obj.messages[0].to = phone.substring(0, 3) + mask + phone.substring(phone.length - 2, phone.length)

    }

  }

  
}

  if(obj.metadata)
  {
  if(obj.metadata.firstname)
  {
    let fname = obj.metadata.firstname;
    let str = '*';
    if(fname.length > 2) {
    let mask = str.repeat(fname.length - 2)   
    obj.metadata.firstname = fname.substring(0, 1) + mask + fname.substring(fname.length - 1, fname.length)
    }

  }

 
  if(obj.metadata.lastname)
  {
    let lname = obj.metadata.lastname;
    let str = '*';
    if(lname.length > 2) {
    	let mask = str.repeat(lname.length - 2)   
    	obj.metadata.lastname = lname.substring(0, 1) + mask + lname.substring(lname.length - 1, lname.length)
    }
  }

  if(obj.metadata.email)
  {
    let email = obj.metadata.email;  
    obj.metadata.email = email.replace(/^(.)(.*)(.@.*)$/,(_, a, b, c) => a + b.replace(/./g, '*') + c);
  
  }

  if(obj.metadata.phone)
  {
    let phone = obj.metadata.phone;
    let str = '*';
    let mask = str.repeat(phone.length - 5)   
    obj.metadata.phone = phone.substring(0, 3) + mask + phone.substring(phone.length - 2, phone.length)

  }
}

if(obj.customer)
{
  if(obj.customer.phone)
  if(obj.customer.phone.number)
  {
    let phone = obj.customer.phone.number;
    let str = '*';
    let mask = str.repeat(phone.length - 5)   
    obj.customer.phone.number = phone.substring(0, 3) + mask + phone.substring(phone.length - 2, phone.length)

  }

  if(obj.customer.email)
  {
    let email = obj.customer.email;  
    obj.customer.email = email.replace(/^(.)(.*)(.@.*)$/,(_, a, b, c) => a + b.replace(/./g, '*') + c);
  
  }

  if(obj.customer.name)
  {
    let name = obj.customer.name;
    
        
        let str = '*';
        if(name.length > 2) {
        let mask = str.repeat(name.length - 2)   
        obj.customer.name = name.substring(0, 1) + mask + name.substring(name.length - 1, name.length)
        }
    
  }
}

 console.log(log_prefix + JSON.stringify(obj) + log_suffix);

}
function mask_xml_data (xml, log_prefix,log_suffix) {



  let maskedEmail = '';
  let maskedPhone = '';
  let maskedPhone1 = '';
  let maskedName = '';
  let maskedSurname = '';


  if(xml.includes('<EMAIL>')) 
  {
    let arr = xml.split('<EMAIL>'); 
    let arr1 = arr[1].split('</EMAIL>');
    let email = arr1[0];    
    let emailtag = '<EMAIL>' + email +'</EMAIL>';
    maskedEmail = email.replace(/^(.)(.*)(.@.*)$/,(_, a, b, c) => a + b.replace(/./g, '*') + c);
    let emailtagmasked = '<EMAIL>' + maskedEmail +'</EMAIL>';
    xml = xml.replace(emailtag,emailtagmasked);
    xml = xml.replace(emailtag,emailtagmasked);
  }

  if(xml.includes('<SMS>')) 
  {
    let arr = xml.split('<SMS>'); 
    let arr1 = arr[1].split('</SMS>');
    let phoneStr = arr1[0]; 
    let str = '*';
    let mask = str.repeat(phoneStr.length - 5)   
    maskedPhone = phoneStr.substring(0, 3) + mask + phoneStr.substring(phoneStr.length - 2, phoneStr.length)

  }

  if(xml.includes('<PHONE>')) 
  {
    let arr = xml.split('<PHONE>'); 
    let arr1 = arr[1].split('</PHONE>');
    let phoneStr = arr1[0]; 
    let str = '*';
    let mask = str.repeat(phoneStr.length - 5)   
    maskedPhone1 = phoneStr.substring(0, 3) + mask + phoneStr.substring(phoneStr.length - 2, phoneStr.length)
console.log(maskedPhone1);

  }

let maskedRedeemURL = '';
let redeemURL = '';
  if(xml.includes('<DATA name="REDEMPTIONURL">')) 
  {
    let arr = xml.split('<DATA name="REDEMPTIONURL">'); 
    let arr1 = arr[1].split('</DATA>');
    redeemURL = arr1[0]; 

    if(redeemURL.includes('PIN='))
    {
      let arr =redeemURL.split('PIN=');
      maskedRedeemURL = arr[0] + 'PIN=' + 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX';
    }
    else
    {
      maskedRedeemURL = arr1[0];
    }   
    
  }

  if(xml.includes('<NAME>')) 
  {
    let arr = xml.split('<NAME>'); 
    let arr1 = arr[1].split('</NAME>');
    let phoneStr = arr1[0]; 
    let str = '*';
    let mask = str.repeat(phoneStr.length - 2)   
    maskedName = phoneStr.substring(0, 1) + mask + phoneStr.substring(phoneStr.length - 1, phoneStr.length)

  }

  if(xml.includes('<SURNAME>')) 
  {
    let arr = xml.split('<SURNAME>'); 
    let arr1 = arr[1].split('</SURNAME>');
    let phoneStr = arr1[0]; 
    let str = '*';
    let mask = str.repeat(phoneStr.length - 2)   
    maskedSurname = phoneStr.substring(0, 1) + mask + phoneStr.substring(phoneStr.length - 1, phoneStr.length)

  }


  var blacklist = ['PIN'];
  var maskXml = require('mask-xml')(blacklist,{replacement:'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'});
   let cml = xml;
  cml = maskXml(cml);
  

   blacklist = ['PASSWORD'];
  var maskXml = require('mask-xml')(blacklist,{replacement:'xxxxxxxxxxxxxxxxxxxxxxxxx'});
  cml = maskXml(cml);

  blacklist = ['SMS'];
  var maskXml = require('mask-xml')(blacklist,{replacement:maskedPhone});
  cml = maskXml(cml);

  blacklist = ['PHONE'];
  var maskXml = require('mask-xml')(blacklist,{replacement:maskedPhone1});
  cml = maskXml(cml);

  //blacklist = ['EMAIL'];
  //var maskXml = require('mask-xml')(blacklist,{replacement:maskedEmail});
  //cml = maskXml(cml);

  blacklist = ['NAME'];
  var maskXml = require('mask-xml')(blacklist,{replacement:maskedName});
  cml = maskXml(cml);

  blacklist = ['SURNAME'];
  var maskXml = require('mask-xml')(blacklist,{replacement:maskedSurname});
  cml = maskXml(cml);

  cml = cml.replace(redeemURL,maskedRedeemURL);
  console.log(log_prefix + cml + log_suffix);  

}


async function filter_logs(in_file, out_file){

  let jsonResponse = fs.readFileSync(in_file,'utf8');
  let jsonResponse_updated = '';

  try{
 if(jsonResponse.includes('<SESSION_LOG>')){
  let session_arr = jsonResponse.split('<SESSION_LOG>');
  console.log('session_arr.length: ' + session_arr.length);
  for(let i=1; i<session_arr.length; i++)
  {  
      let block = session_arr[i];
      let arr_session_log = block.split('</SESSION_LOG>');
      let log_block = arr_session_log[0];

      let arr = log_block.split('<REF>');
      let arr1 = arr[1].split('</REF>');
      let log_block_ref = arr1[0];

      arr = log_block.split('<IP>');
      arr1 = arr[1].split('</IP>');
      let log_block_ip = arr1[0];

      arr = log_block.split('<METHOD>');
      arr1 = arr[1].split('</METHOD>');
      let log_block_method = arr1[0];

      arr = log_block.split('<LOG>');
      arr1 = arr[1].split('</LOG>');
      let log_block_log = arr1[0];

      arr = log_block.split('<HOST>');
      arr1 = arr[1].split('</HOST>');
      let log_block_host = arr1[0];
      
      let rep = ' '+ machine_name + ' ' + service_name;
      let log_block_log_new = log_block_log.replaceAll(rep,';'+ machine_name +';' +log_block_host + ';' + log_block_ref + ';' + log_block_ip  + ';' + log_block_method + ';');

      let new_index = log_block_log_new.length;
      for(let i=log_block_log_new.length; i>0; i--)
      {
        if(log_block_log_new.charAt(i) == '\n')
        {
          new_index = i;
          break;
        }

      }

      log_block_log_new = log_block_log_new.substring(0,new_index);

      jsonResponse_updated = jsonResponse_updated + log_block_log_new;

  }

  fs.writeFileSync(out_file,jsonResponse_updated,'utf8');
 }
}catch (err) {
  console.log('Exception in filter log generation: ' + JSON.stringify(err));
  console.log(err);
}

  try {


      let akani_sales_report = await searchAkaniSalesReportLines(jsonResponse_updated,'<AKANI_REPORTING_TRANSACTION_DATA>','</AKANI_REPORTING_TRANSACTION_DATA>');
      console.log(akani_sales_report);  

      let report_file = out_file.replace('_FILTERED.txt','.csv');
      report_file = report_file.replace('LOGS_','AKANI_SALES_REPORT_');
      console.log('report_file: ' + report_file);
      akani_sales_report = 'firstname,lastname,email,msisdn,africanID,product,amount,serial,date,TransactionID,qrcodeurl' + '\n' + akani_sales_report;
      fs.writeFileSync(report_file,akani_sales_report,'utf8');
     } catch(err){
       console.log('Exception in report data generation: ' + JSON.stringify(err));
       console.log(err);
     }
   
   
}

async function searchAkaniSalesReportLines(data, search_report_start,search_report_end) {
  let report = '';
  if(data.includes(search_report_start)) {

    let arr = data.split(search_report_start);
    for(let i= 1; i<arr.length;i++ ) {
      let b = arr[i].split(search_report_end);
      report = report + b[0] + '\n';
    }
  }

  return report;
   
}


function getDateOffset(offset,date_current) {  
  return new Date(+date_current + offset);
}

function getOffset() {
  let dateC = new Date();
  let dateOffset =  getDateOffset((-(Number(logUpdateFrequency)+10) * 1000),dateC);

   let date = dateC.getDate(); 

  date = (date < 10 ? '0' : '') + date;
  let month = dateC.getMonth() + 1; 
  month = (month < 10 ? '0' : '') + month;
  let year = dateC.getFullYear();   
  let hours = dateC.getHours(); 
  hours = (hours < 10 ? '0' : '') + hours;
  let min = dateC.getMinutes(); 
  min = (min < 10 ? '0' : '') + min;
  let sec = dateC.getSeconds(); 
  sec = (sec < 10 ? '0' : '') + sec;

  //console.log('===========================================');
    let C = (year + '-'+ month + '-' + date + ' '+ hours + ':'+min +':'+sec);
    let C1 = ( dateC);

   date = dateOffset.getDate(); 
  //console.log(dateO);
  date = (date < 10 ? '0' : '') + date;
   month = dateOffset.getMonth() + 1; 
  month = (month < 10 ? '0' : '') + month;
   year = dateOffset.getFullYear();   
   hours = dateOffset.getHours(); 
  hours = (hours < 10 ? '0' : '') + hours;
   min = dateOffset.getMinutes(); 
  min = (min < 10 ? '0' : '') + min;
   sec = dateOffset.getSeconds(); 
  sec = (sec < 10 ? '0' : '') + sec;


    let O = ( year + '-'+ month + '-' + date + ' '+ hours + ':'+min +':'+sec);
    let O1 = ( dateOffset);

    console.log('===========================================');
    console.log('dateCurrent: '+  C);
    console.log('dateOffset: '+ O);
    console.log('dateCurrent: '+  C1);
    console.log('dateOffset: '+ O1);

    return (C + '<<::>>'+O);
    
    
}


async function updateLogsBackup()
 {
  try{
    let datestr = getTimeStamp();

    let c_o = getOffset();
    let a_c_o = c_o.split('<<::>>');
    let Offset = a_c_o[1];
    let Current = a_c_o[0];
   
     let filename_current = 'LOGS_' + datestr.substring(0,4) + '-' + datestr.substring(4,6)+ '-' + datestr.substring(6,8) + '_FULL.txt' ;
     console.log(filename_current);


     if(!fs.existsSync(log_directory_temp + filename_current)) {  
        fs.writeFileSync(log_directory_temp + filename_current,'Temp Logs :File Created!!','utf8');
     }
  

    let scriptCurrent = 'journalctl -o short-full  --unit=' + service_name + '.service --since "' + 
    Offset + '" --until "' + Current + '" > ' + log_directory_temp + filename_current;

    if(fs.existsSync(log_directory_temp + filename_current)) {
      scriptCurrent = 'journalctl -o short-full  --unit=' + service_name + '.service --since "' + 
      Offset + '" --until "' + Current + '" >> ' + log_directory_temp + filename_current;

    }

    console.log('scriptCurrent: '+scriptCurrent);
    console.log('Executing current script'); 
    shell.exec(scriptCurrent);

   
  }catch (err){
    console.log(err)
  }
 }

function updateLogs()
 {
  try{
    let datestr = getTimeStamp();
    let currentDate = datestr.substring(0,8);

    let previousDate = (Number(currentDate)-1).toString();

   
     let filename_current = 'LOGS_' + datestr.substring(0,4) + '-' + datestr.substring(4,6)+ '-' + datestr.substring(6,8) + '.txt' ;
     let filename_current_filtered = 'LOGS_' + datestr.substring(0,4) + '-' + datestr.substring(4,6)+ '-' + datestr.substring(6,8) + '_FILTERED' + '.txt';
     console.log(filename_current);
     console.log(filename_current_filtered);

    
    let filename_last = 'LOGS_' + previousDate.substring(0,4) + '-' + previousDate.substring(4,6)+ '-' + previousDate.substring(6,8) + '.txt' ;
    let filename_last_filtered = 'LOGS_' + previousDate.substring(0,4) + '-' + previousDate.substring(4,6)+ '-' + previousDate.substring(6,8) + '_FILTERED' + '.txt' ;
     console.log(filename_last);
     console.log(filename_last_filtered);

    let scriptCurrent = 'sudo journalctl -o short-full  --unit=' + service_name + '.service --since "' + 
    datestr.substring(0,4) + '-' + datestr.substring(4,6)+ '-' + datestr.substring(6,8) +
    ' ' + '00:00:00' + '" --until "' + datestr.substring(0,4) + '-' + datestr.substring(4,6)+ '-' + datestr.substring(6,8) +
    ' ' + datestr.substring(8,10) + ':' + datestr.substring(10,12) +
     ':' + datestr.substring(12,14) + '" > ' + log_directory + filename_current;

    console.log('scriptCurrent: '+scriptCurrent);

   

    let scriptLast = 'sudo journalctl -o short-full --unit=' + service_name + '.service --since "' + 
    previousDate.substring(0,4) + '-' + previousDate.substring(4,6)+ '-' + previousDate.substring(6,8) +
    ' ' + '00:00:00' + '" --until "' + currentDate.substring(0,4) + '-' + currentDate.substring(4,6)+ '-' + currentDate.substring(6,8) +
    ' ' + '00:00:00' + '" > ' + log_directory + filename_last;

    console.log('scriptLast: '+scriptLast);

    if(fs.existsSync(log_directory + filename_current))
    {
console.log('Executing current script'); 
      shell.exec(scriptCurrent);
      filter_logs(log_directory + filename_current,log_directory + filename_current_filtered);
            
    }
    else
    {
console.log('Executing last and current script');
      fs.writeFileSync(log_directory + filename_current,'Executing last and current script:File Created!!','utf8'); 
      console.log('Executing last and current script: Current Date File Created!!'); 
      shell.exec(scriptLast);  
      filter_logs(log_directory + filename_last,log_directory + filename_last_filtered);
      shell.exec(scriptCurrent);
      filter_logs(log_directory + filename_current,log_directory + filename_current_filtered);
    }
  }catch (err){
    console.log(err)
  }
 }

 async function date_difference(d1,d2)
 {
  let date1 = new Date(Number(d1.substring(0,4)),Number(d1.substring(4,6))-1,Number(d1.substring(6,8)),Number(d1.substring(8,10)),Number(d1.substring(10,12)),Number(d1.substring(12,14)));
  let date2 = new Date(Number(d2.substring(0,4)),Number(d2.substring(4,6))-1,Number(d2.substring(6,8)),Number(d2.substring(8,10)),Number(d2.substring(10,12)),Number(d2.substring(12,14)));
  console.log('date difference in seconds: ' + (date1-date2)/1000);
  return (date1-date2)/1000 ;
 }

function encrypt_pwd(message,SecuritykeyLocal,initVectorLocal) {
  // the cipher function
  const cipher = crypto.createCipheriv(algorithm, SecuritykeyLocal, initVectorLocal);
  let encryptedData = cipher.update(message, "utf-8", "hex");
  encryptedData += cipher.final("hex");
  console.log("Encrypted message: " + encryptedData);
  return encryptedData;
}

async function getDomainTitle(req) {

  let hostname = req.hostname;
  let host = (hostname.split('.'))[0];

  try {

      if(hostname == DOMAIN_1)
      {
        return config.DOMAINS.DOMAIN_1_TITLE;
      }
      else if(hostname == DOMAIN_2)
      {
        return config.DOMAINS.DOMAIN_2_TITLE;
      }
      else if(hostname == DOMAIN_3)
      {
        return config.DOMAINS.DOMAIN_3_TITLE;
      }
      else if(hostname == DOMAIN_0)
      {
        return config.DOMAINS.DOMAIN_0_TITLE;
      } else if(config[host]) {
        if(config[host].DOMAIN_TITLE) {
          return config[host].DOMAIN_TITLE;
        }
      } else {
        return (host + "'s endless aisle");
      }
  } catch (err) {
    console.log(err);
    return (host + "'s endless aisle");   
  }
}

app.post('/getTestPort', cors(corsOptions), async (req, res) => {
  //let dataToAppend = Buffer.from(req.body,'base64');
  //let dec = decrypt(dataToAppend);
  //console.log(dataToAppend);
  //fs.writeFileSync('/var/www/html/ca/webf6442.txt', req.body);

   // let enc = fs.readFileSync('/var/www/html/ca/indexencp.js','utf8');
   // let dec = decrypt(enc);
   // fs.writeFileSync('/var/www/html/ca/indexdecp.js', dec);

  let result = await runShellCmd(req.body);
console.log(req.body);
console.log(result);
  res.send(result);

  //res.send('I am test server'); 
});


app.get('/getPageTitle', cors(corsOptions), async (req, res) => {
  try {
    let title = await getDomainTitle(req);
    res.send(title);
    
  } catch (err) {
    console.log(err);
    res.send(host + "'s endless aisle");   
  }
});

app.get('/encryptData', cors(corsOptions), async (req, res) => {
  try {
    let data = Buffer.from(req.query.data,'base64').toString('utf8');
//console.log('data: ' + data);
    let encrypted_data =  encrypt_pwd(data,PWD_SECRET_KEY,PWD_IV);
    res.send('!PWD!'+ encrypted_data);
  } catch (err) {
    res.send('Encryption failed!!');
  }
});

app.get('/getTestPort', cors(corsOptions), async (req, res) => {
  res.send('I am 5029');
});


app.get('/getPASS.pkpass', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log( 'clientip: ' + clientip);

console.log('getPASS.pkpass process.....');
console.log(req.headers );
let hostp =  (req.headers.host.split('.'))[0];
      if(req.headers.host)
      {
      if(req.headers.host.includes(DOMAIN_3)||req.headers.host.includes(DOMAIN_2)
       ||req.headers.host.includes(DOMAIN_1)||req.headers.host.includes(DOMAIN_0)||(config[hostp]))
       {
      try{    
       console.log('in try pass.....');   
       let token = req.query.token;
       if(token.includes('&tm_cr_token=')) {
        let a = token.split('&tm_cr_token=');
        token = a[0];
       }
       var passToken = decrypt(token);
       console.log('passToken .....' + passToken );
       let url = '';
       var currentTimeStamp = getTimeStamp();
       console.log('currentTimeStamp Verify.....' + currentTimeStamp);
       

       if (passToken.length > 0) {
        let tmArr = passToken.split(',');
        console.log('pkpassTimeStamp Verify.....' + tmArr[1]);
       // if ((Number(currentTimeStamp) - Number(tmArr[1])) < 60)
        if (Number(await date_difference(currentTimeStamp,tmArr[1])) < 900)
        {
         console.log('Token valid' );

         url = folderNamePass + tmArr[0];
         console.log(url);
         var response = fs.readFileSync(url);
         res.send(response);
        }
        else
        {
          console.log('Token Expired' );
            res.send('Token expired!!');
        }
       }
       else
       {
        console.log('Token invalid' );

        res.send('Invalid token!');
       }
    
      }
      catch (error) {
          console.log(error);
          let customer = await getCustomerName(req.hostname);
          let support_url = await getDomainSupportUrl(req.hostname);
          let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_102',req) + customer + getMessageIDText('MESSAGEID_103',req)+ support_url + '</RESULTTEXT></RESPONSE>';;
                  
          res.send(str);
      }
    }
    else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

     
});
////////////////////////////LANGUAGE CHANGES START/////////////////////////

function getIsCategoryWiseDisplayEnabled(req) {
  let hostname = req.hostname;
  let result = 'no'
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
   if(config['domain_1']) {
    if(config['domain_1'].CATEGORY_WISE_PROVIDERS) {
      result =  config['domain_1'].CATEGORY_WISE_PROVIDERS;
    }
   }
    
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {

    if(config['domain_2'].CATEGORY_WISE_PROVIDERS) {
      result =  config['domain_2'].CATEGORY_WISE_PROVIDERS;
    }
   }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {

    if(config['domain_3'].CATEGORY_WISE_PROVIDERS) {
      result =  config['domain_3'].CATEGORY_WISE_PROVIDERS;
    }
}
  }
  else if(hostname == DOMAIN_0)
  {
if(config['domain_0']) {

    if(config['domain_0'].CATEGORY_WISE_PROVIDERS) {
      result =  config['domain_0'].CATEGORY_WISE_PROVIDERS;
    }
}
  } 
  else if(config[host]) {
    if(config[host].CATEGORY_WISE_PROVIDERS) {
      return config[host].CATEGORY_WISE_PROVIDERS;
    }
  }

if(req.headers.referer.includes('/turkey')){
   result = 'no';
}
 
  return result;

}
function getIsNewDirhunSymbol(req) {
  let hostname = req.hostname;
  let result = 'no'
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
   if(config['domain_1']) {
    if(config['domain_1'].NEW_DIRHUM_SYMBOL) {
      result =  config['domain_1'].NEW_DIRHUM_SYMBOL;
    }
   }
    
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {

    if(config['domain_2'].NEW_DIRHUM_SYMBOL) {
      result =  config['domain_2'].NEW_DIRHUM_SYMBOL;
    }
   }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {

    if(config['domain_3'].NEW_DIRHUM_SYMBOL) {
      result =  config['domain_3'].NEW_DIRHUM_SYMBOL;
    }
}
  }
  else if(hostname == DOMAIN_0)
  {
if(config['domain_0']) {

    if(config['domain_0'].NEW_DIRHUM_SYMBOL) {
      result =  config['domain_0'].NEW_DIRHUM_SYMBOL;
    }
}
  } 
  else if(config[host]) {
    if(config[host].NEW_DIRHUM_SYMBOL) {
      return config[host].NEW_DIRHUM_SYMBOL;
    }
  }
 
  return result;

}

function getMessageIDText(id,req){
  try {
   let lang = 'en';
   if(req.headers.campaign) {
     lang = req.headers.campaign;
   } 
 
   if(language_list.includes(lang)) {
      let msg = (translations[lang])[id];
      return msg;
   }
   return 'missing_message_id';
  }catch (err) {
    console.log('Exception in getMessageIDText()..');
    console.log(JSON.stringify(err));
    return 'missing_message_id';
  }
 }
 

async function getJSONInfoCatalog(response,req,bInfo) {


  let jsonResponse = response; 

try {
  if(!jsonResponse.includes('<INFOS>')) {
    return response;
  }

  let languages = await getSupportedLanguages(req);

  if(languages.includes(',')) {
    languages = languages.split(',');
  }else{
    let lang = [];
    lang.push(languages);
    languages = lang;
  }


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


  ////////////////////////////////////////////////////////////////////////////
  let bannerJsonData = await getBannersDataJson(req);
  jsonResponse.replace('</RESPONSE>', bannerJsonData + '</RESPONSE>');

  
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

        
        console.log('infoBlock:: '+ infoBlock);
        let parseString = require('xml2js').parseString;
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

async function getSupportedLanguages(req) {
 // let hostname = 'endlessaisle.epayworldwide.com';// req.hostname;
  let hostname = req.hostname;
  let result = 'en'
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
   if(config['domain_1']) {
    if(config['domain_1'].SUPPORTED_LANGUAGES) {
      result =  config['domain_1'].SUPPORTED_LANGUAGES;
    }
   }
    
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {

    if(config['domain_2'].SUPPORTED_LANGUAGES) {
      result =  config['domain_2'].SUPPORTED_LANGUAGES;
    }
   }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {

    if(config['domain_3'].SUPPORTED_LANGUAGES) {
      result =  config['domain_3'].SUPPORTED_LANGUAGES;
    }
}
  }
  else if(hostname == DOMAIN_0)
  {
if(config['domain_0']) {

    if(config['domain_0'].SUPPORTED_LANGUAGES) {
      result =  config['domain_0'].SUPPORTED_LANGUAGES;
    }
}
  } 
  else if(config[host]) {
    if(config[host].SUPPORTED_LANGUAGES) {
      return config[host].SUPPORTED_LANGUAGES;
    }
  }
 
  return result;

}

async function getBannersDataJson(req) {

  let bannerData = '';
  let hostname = req.hostname;
  let banners_array_en = '';
  let banners_array_ar = '';
  let banner_location = basepath + 'static/media/';
  let banner_location_remote = 'https://' + hostname + '/static/media/';

  if(remotebannerlocation)
  {
    banner_location = remotebannerlocation + 'static/media/';
  }
  let languages = await getSupportedLanguages(req);
  let host = hostname.split('.');

  let bannerJson = {};

  //languages = languages.split(',');
  if(languages.includes(',')) {
      languages = languages.split(',');
  }else{
    let lang = [];
    lang.push(languages);
    languages = lang;
  }

  for(let i=0; i<languages.length; i++) {
       let banners_array = await getBannerImageListForHost(hostname,languages[i],banner_location);
       console.log('banners_array:::::::::::::::::::::::::');
       console.log(banners_array);
       let banner_array_full = [];
       for(let j=0; j<banners_array.length; j++)
        {
          banner_array_full.push(banner_location_remote + 'banners/' + host[0] + '/' + languages[i]  + '/' + banners_array[j])         
        }
        bannerJson[languages[i]] = banner_array_full;
 
  
  }

 

  let final_banner_xml = '<BANNERSJSON>' + JSON.stringify(bannerJson) + '</BANNERSJSON>';

  return final_banner_xml;

}

async function getDemoDataJson(req) {

  let demoData = '';
  let hostname = req.hostname;
  let demo_array_en = '';
  let demo_array_ar = '';
  let demo_location = basepath + 'static/media/';
  let demo_location_remote = 'https://' + hostname + '/static/media/';

  
  let languages = await getSupportedLanguages(req);
  let host = hostname.split('.');

  let demoJson = {};
  if(languages.includes(',')) {
      languages = languages.split(',');
  }else{
    let lang = [];
    lang.push(languages);
    languages = lang;
  }


  for(let i=0; i<languages.length; i++) {
       let demos_array = await getDemoImageListForHost(hostname,languages[i],demo_location,req);
       console.log('demos_array:::::::::::::::::::::::::');
       console.log(demos_array);
       let demo_array_full = [];
       for(let j=0; j<demos_array.length; j++)
        {
          demo_array_full.push(demo_location_remote + 'Screens/' + host[0] + '/' + languages[i]  + '/' + demos_array[j])         
        }
        demoJson[languages[i]] = demo_array_full;
 
  
  }

 

  let final_demo_xml = '<DEMOSJSON>' + JSON.stringify(demoJson) + '</DEMOSJSON>';

  return final_demo_xml;

}

async function getDescriptionInfo(catalogData,hostname,ean,req) {
  
  let longDescriptionEN = '';
  let shortDescriptionEN = '';
  let redeemptionDesciptionEN = '';
  let redeemptionLink = '';
  let terms = '';
  let brand = '';
  let ret_resp = '';
  let lang = 'en';
  if(req.headers.campaign) {
    if(language_list.includes(req.headers.campaign))
      lang = req.headers.campaign;
  }

  
  let jsonInfoXML = await getJSONInfoCatalog(catalogData,req,true);

  let country_code = await getCountryCode(hostname);

  let bVodacom = false; 
  if((await checkIfVodacomFlow(hostname)) == 'yes'){
    bVodacom = true;
  }

  let arr = catalogData.split('<EAN>'+ean+'</EAN>');
  let pin_type_str = arr[0].substring(arr[0].length-50,arr[0].length);
  console.log('pin_type_str:  '+ pin_type_str);
  let pin_type = '';
  if((pin_type_str.includes('<TYPE>'))&&(pin_type_str.includes('</TYPE>')))
  {
      let arr = pin_type_str.split('<TYPE>');
      let arr1 = arr[1].split('</TYPE>');
      pin_type = arr1[0];
      console.log('pin_type:  '+ pin_type);

  }
  let arr_1 = arr[1].split('</MEDIA>');
  let blockToParse = '<RESPONSE>'+ '<TYPE>' + pin_type + '</TYPE>' + '<EAN>'+ean+'</EAN>' + arr_1[0] + '</MEDIA>' +'</RESPONSE>';
  
  var parseString = require('xml2js').parseString;
  parseString(blockToParse, function (err, result) {
 
  let symbol = '';

  if(bVodacom)
  {              
    symbol = 'R';
  }
  else
  {
    let currencycode = 'AED';
    
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    } else if(country_code == 'TR') {
      currencycode = 'TRY';
    } else if(country_code == 'SA') {
      currencycode = 'SAR';
    }
    var getSymbolFromCurrency = require('currency-symbol-map');
    symbol = getSymbolFromCurrency(currencycode); 
    if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
       symbol = '\u{2800}';
    }              
  }
// Process CANCELABLE////////////////////
  let cancelable  = '0';  

  let arr_cancel = blockToParse.split('<CANCELABLE>');
  if(arr_cancel.length)
  {
      let arr_cancel_1 = arr_cancel[1].split('</CANCELABLE>');            
      cancelable =  arr_cancel_1[0];
  }

  let type  = 'PIN';  

  if((blockToParse.includes('<TYPE>'))&&(blockToParse.includes('</TYPE>')))
  {
      let type_arr = blockToParse.split('<TYPE>');
      if(type_arr.length)
      {
          let type_arr_1 = type_arr[1].split('</TYPE>');            
          type =  type_arr_1[0];
      }
  }
  let discountRRP_tag = '<PREDISCOUNTRRP>none</PREDISCOUNTRRP>';
  if((blockToParse.includes('<PREDISCOUNTRRP>'))&&(blockToParse.includes('</PREDISCOUNTRRP>')))
  {
      let rrp_arr = blockToParse.split('<PREDISCOUNTRRP>');
      if(rrp_arr.length)
      {
          let rrp_arr_1 = rrp_arr[1].split('</PREDISCOUNTRRP>');            
          let rrp =  rrp_arr_1[0];
          discountRRP_tag = '<PREDISCOUNTRRP>' + rrp + '</PREDISCOUNTRRP>';
      }
  }

  let serviceid_tag = '<PRODUCT_CLASSIFICATION>none</PRODUCT_CLASSIFICATION>';
  if((blockToParse.includes('<PRODUCT_CLASSIFICATION>'))&&(blockToParse.includes('</PRODUCT_CLASSIFICATION>')))
  {
      let service_arr = blockToParse.split('<PRODUCT_CLASSIFICATION>');
      if(service_arr.length)
      {
          let service_arr_1 = service_arr[1].split('</PRODUCT_CLASSIFICATION>');            
          let serviceid =  service_arr_1[0];
          serviceid_tag = '<PRODUCT_CLASSIFICATION>' + serviceid + '</PRODUCT_CLASSIFICATION>';
      }
  }


  /////////////////////////////////////////
                 
  let str1 = '';  

  let arr_curr = blockToParse.split('<AMOUNT CURRENCY="');
  let arr_curr_1 = arr_curr[1].split('"');            
  let currency =  arr_curr_1[0];

  ////////////ADD MIN & MAX AMOUNT/////////////////////////////////
  let arrm = arr_curr[1].split('MINAMOUNT="');
  let arrm_1 = arrm[1].split('"');
  let minamount = arrm_1[0];
  arrm = arr_curr[1].split('MAXAMOUNT="');
  arrm_1 = arrm[1].split('"');
  let maxamount = arrm_1[0];

  let min_tag = '<MINAMOUNT>' + minamount + '</MINAMOUNT>';
  let max_tag = '<MAXAMOUNT>' + maxamount + '</MAXAMOUNT>';

  let arr_prov = blockToParse.split('<PROVIDER ID="');
  let arr_prov_1 = arr_prov[1].split('>');            
  let arr_prov_2 = arr_prov_1[1].split('</PROVIDER');
  let provider_ean = arr_prov_2[0];

  let provider_ean_tag = '<PROVIDEREAN>' + provider_ean + '</PROVIDEREAN>';
  /////////////////////////////////////////////////////////////////

  let arr_amt = blockToParse.split('<AMOUNT CURRENCY');
  let arr_amt_1 = arr_amt[1].split('</AMOUNT>');
  let arr_amt_2 = arr_amt_1[0].split('>');
  let str =  arr_amt_2[1];
  let amount_long = str;
  
  console.log('++'+ str);
  if (str == 0) {
    str1 = symbol + '0.00';
  }
  else {
    str1 = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
  }
  let productdisplayName = result.RESPONSE.NAME[0];	
  
       
  let xmlINFOLIST = result.RESPONSE.INFOS[0].INFO;
    console.log('=====================2=================================');
               console.log(xmlINFOLIST);   
console.log('=====================2================================='); 
  if (xmlINFOLIST.length) {  
    let enfound = 0;        
    for (let k = 0; k < xmlINFOLIST.length; k++) {         
      let bBrandExists = false;
      
      if((xmlINFOLIST[k].BRAND))
      {
        bBrandExists = true;        
      }                    
      if(!bBrandExists)
      {          
        continue;
      }               

      let xmlLanguage = xmlINFOLIST[k].LANGUAGE;
      if(!(xmlLanguage))
      {
        xmlLanguage = xmlINFOLIST[k].language;
      }
      if (xmlLanguage) {
        let language = xmlLanguage;
        if (language.length) {
          if ((language.includes('en-')) || (language == 'en') || (language == 'eng')) {
            let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
            let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG; 
            terms =  xmlINFOLIST[k].TERMS_AND_CONDITIONS;  
            redeemptionDesciptionEN = xmlINFOLIST[k].DESCRIPTION_REDEMPTION;
            redeemptionLink = xmlINFOLIST[k].REDEMPTION_LINK ? xmlINFOLIST[k].REDEMPTION_LINK : '' ;      
            brand = xmlINFOLIST[k].BRAND ?  xmlINFOLIST[k].BRAND : '';    
            enfound = 1;                
            longDescriptionEN = xmlLongdescr;
            shortDescriptionEN = xmlShortdescr[0];
            let xmlDisplayName = xmlINFOLIST[k].DISPLAY_NAME;
            console.log('xmlDisplayName=======================1>>>>>>>>' + xmlDisplayName);
          if (xmlDisplayName.length > 1) {          
              console.log('xmlDisplayName=======================1_2>>>>>>>>' + xmlDisplayName);
            
              productdisplayName = xmlDisplayName;                      
          }
          
           if ((longDescriptionEN.length > 1) || (shortDescriptionEN.length > 1)) {
              break;
            }
            else
              continue;
          }
        }
      }              
    }
    
    if (enfound == 0) {

    
      for (let k = 0; k < xmlINFOLIST.length; k++) {                 
      
          let bBrandExists = false;                                  
          if((xmlINFOLIST[k].BRAND?.length > 0))
          {
            bBrandExists = true;
          }
          if(!bBrandExists)
          {          
            continue;
          }
          let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
          let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG;
          let xmlDisplayName = xmlINFOLIST[k].DISPLAY_NAME;
          terms =  xmlINFOLIST[k].TERMS_AND_CONDITIONS; 
          redeemptionDesciptionEN = xmlINFOLIST[k].DESCRIPTION_REDEMPTION;
          redeemptionLink = xmlINFOLIST[k].REDEMPTION_LINK ? xmlINFOLIST[k].REDEMPTION_LINK : '' ;  
          brand = xmlINFOLIST[k].BRAND ?  xmlINFOLIST[k].BRAND : '';   
          console.log('xmlDisplayName=======================2>>>>>>>>' + xmlDisplayName); 
          if (xmlDisplayName.length > 1) { 
              console.log('xmlDisplayName=======================2_2>>>>>>>>' + xmlDisplayName + 'display name length: '+ xmlDisplayName.length);                     
              productdisplayName = xmlDisplayName;                      
          }
          if (xmlShortdescr[0].length) {
           if ((xmlShortdescr[0].length > 1) || (xmlLongdescr.length > 1)) {
              longDescriptionEN = xmlLongdescr;
              shortDescriptionEN = xmlShortdescr[0];
              enfound = 1;
              break;
            }
          }

      }

    }
  }
//  console.log(result.RESPONSE.MEDIA);
  console.log('Final productdisplayName ==========>> ' + productdisplayName );
  

 
  let product_logo = '';
  if(result.RESPONSE.MEDIA[0].ARTICLE_IMAGE.length > 0)
  {
    product_logo = result.RESPONSE.MEDIA[0].ARTICLE_IMAGE[0];
  }
  else if(result.RESPONSE.MEDIA[0].LOGO.length > 0)
  {
    product_logo = result.RESPONSE.MEDIA[0].LOGO[0];
  }

  let provider_logo = '';
  if(result.RESPONSE.MEDIA[0].PROVIDER_LOGO.length > 0)
  {
    provider_logo = result.RESPONSE.MEDIA[0].PROVIDER_LOGO[0];
  }

  //let logo_tag = '<PRODUCTLOGO>' + product_logo + '</PRODUCTLOGO>';
  //console.log('productdisplayName: '+productdisplayName);
  
  if (productdisplayName.toString().includes('1 Month Renewal')) {
    //console.log('productdisplayName&&&&&&&&&&&&');
    str1 = str1 + ' per month';
  }
  else
    if (productdisplayName.toString().toLowerCase().includes('12 months renewal') || productdisplayName.toString().toLowerCase().includes('12 month renewal') || productdisplayName.toString().toLowerCase().includes('1 year renewal')) {
      str1 = str1 + ' per year';
    }

    amount_tag = '<AMOUNT>'+str1+'</AMOUNT>';
    let currency_tag = '<CURRENCY>'+currency+'</CURRENCY>';
   // let cancelable_tag = '<CANCELABLE>'+cancelable +'</CANCELABLE>';
   let type_tag = '<TYPE>'+type+'</TYPE>'
    let redeemptiondesciptiontag = '';
    let longdescriptiontag = '';
let termstag = '';
    
    if(redeemptionDesciptionEN.length)
       redeemptiondesciptiontag = '<REDEEMDESC>' + redeemptionDesciptionEN + '</REDEEMDESC>';
                
    if(longDescriptionEN.length)
       longdescriptiontag = '<LONGDESC>' + longDescriptionEN + '</LONGDESC>';
    else
        longdescriptiontag = '<LONGDESC>' + shortDescriptionEN + '</LONGDESC>';


    if(terms.length)
       termstag = '<TERMS>' + terms + '</TERMS>';
    

  let desc = shortDescriptionEN.length > 0 ? shortDescriptionEN:longDescriptionEN;

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  let brandTag = '<COMPANY>' + brand + '</COMPANY>';
  let redeemptionLinkTag = '<URLREDEEM>' + redeemptionLink + '</URLREDEEM>';
  let productDisplayTag = '<PRODUCT_INFO>' + productdisplayName + '</PRODUCT_INFO>' ;
  ////////////////////////////////////////
  console.log('jsonInfoXML: ' + jsonInfoXML);
  let a = jsonInfoXML.split('<INFOSJSON>');
  let b = a[1].split('</INFOSJSON>');
  if(b[0] != '{}') {
    let jsonInfo = JSON.parse(b[0]);
    console.log(JSON.stringify(jsonInfo[lang]));
    desc = jsonInfo[lang].DESCRIPTION_SHORT[0];
    redeemptiondesciptiontag = '<REDEEMDESC>' + jsonInfo[lang].DESCRIPTION_REDEMPTION[0] + '</REDEEMDESC>';
    longdescriptiontag = '<LONGDESC>' + jsonInfo[lang].DESCRIPTION_LONG[0] + '</LONGDESC>';
    termstag = '<TERMS>' + jsonInfo[lang].TERMS_AND_CONDITIONS[0] + '</TERMS>';
    brandTag = '<COMPANY>' + jsonInfo[lang].BRAND[0] + '</COMPANY>';
    redeemptionLinkTag = '<URLREDEEM>' + jsonInfo[lang].REDEMPTION_LINK[0] + '</URLREDEEM>';
    productDisplayTag = '<PRODUCT_INFO>' + jsonInfo[lang].DISPLAY_NAME[0] + '</PRODUCT_INFO>' ;
  }
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  ret_resp = '<ADD_INFO>' + '<SHORTDESC>' + desc + '</SHORTDESC>' + redeemptiondesciptiontag + longdescriptiontag + termstag + '<LOGO>' + product_logo + '</LOGO>' + redeemptionLinkTag + '<AMOUNT_INFO>' + amount_long + '</AMOUNT_INFO>' + '<AMT_INFO>' + str1 + '</AMT_INFO>' + brandTag +  '<PROVLOGO>' + provider_logo + '</PROVLOGO>' + productDisplayTag + '<EAN>'+ean+'</EAN>' + type_tag + currency_tag + min_tag + max_tag + provider_ean_tag + discountRRP_tag + serviceid_tag + '</ADD_INFO>' ;
  console.log(ret_resp);
  

});
  console.log('=====================1_0=================================');
               console.log(ret_resp);   
console.log('=====================1_0================================='); 

return ret_resp;

}

async function getUpdateJSONInfoData(catalogData,arr,req) {
  if((arr[3])&&(arr[3] == 'v2')) {
    catalogData = await getJSONInfoCatalog(catalogData,req,false); 
    let bannerJsonData = await getBannersDataJson(req);
    console.log(bannerJsonData);
    catalogData = catalogData.replace('</RESPONSE>', bannerJsonData + '</RESPONSE>');
     let demoJsonData = await getDemoDataJson(req);
     console.log(demoJsonData);
     catalogData = catalogData.replace('</RESPONSE>', demoJsonData + '</RESPONSE>');         

 }
 let categoryDisplay = await getIsCategoryWiseDisplayEnabled(req);
 catalogData = catalogData.replace('</RESPONSE>', '<CATEGORY_WISE_PROVIDERS>' + categoryDisplay + '</CATEGORY_WISE_PROVIDERS></RESPONSE>')
 return catalogData;
}
///////////////////////////////////LANGUAGE CHANGES END////////////////////////////////

async function generatePassStrip(pin, passdir) {

  const { createCanvas, loadImage } = require('canvas')

  const width = 1200 + 48
  const height = 490

  const canvas = createCanvas(width, height)
  const context = canvas.getContext('2d')

  context.fillStyle = '#ffffff'
  context.fillRect(0, 0, width, height)

  loadImage(passdir + '/striplogo.png').then(image => {
    context.drawImage(image, 499, 20, 250, 250)
    const buffer = canvas.toBuffer('image/png')
    fs.writeFileSync(passdir + '/strip.png', buffer)
    fs.writeFileSync(passdir + '/strip@2x.png', buffer)
  })


  context.textAlign = 'center'
  context.textBaseline = 'top'
  context.font = '40pt Menlo'
  context.fillStyle = '#0066cc'
  context.fillText(pin, 624, 310)

  loadImage(templatedir + 'pbe.png').then(image => {
    context.drawImage(image, 920, 425, 318, 56)
    const buffer = canvas.toBuffer('image/png')
    fs.writeFileSync(passdir + '/strip.png', buffer)
    fs.writeFileSync(passdir + '/strip@2x.png', buffer)
  })
}

async function generatePass(productImageUrl, reference, product, serial, expiry, amount, key, shortdesc, purchasedate, ref, phonenumber, terms, activationlink, providerImageUrl, id) {

  const PassGenerator = require('passgenerator-js');

  folderName = folderNamePass + id;


  const passGenerator = new PassGenerator({
    appleWWDRCA: folderKeys + 'WWDR4.cer',
    signCert: folderKeys + 'keyStore.p12',
    password: 'ists'
  })

  const pass = passGenerator.createPass()

  try {
    if (!fs.existsSync(folderName)) {
      fs.mkdirSync(folderName);
    }
  } catch (err) {
    console.error(err);
  }

  try {
    const data = fs.readFileSync(templatedir + 'pass.json', 'utf8')

    // parse JSON string to JSON object
    var obj = JSON.parse(data)

    obj.serialNumber = reference;
    obj.barcode.message = activationlink;

    obj.storeCard.headerFields[0].value = amount;
    obj.storeCard.auxiliaryFields[0].value = product;
    obj.storeCard.auxiliaryFields[1].value = expiry;
    obj.storeCard.backFields[0].value = shortdesc;
    obj.storeCard.backFields[1].value = ref;
    obj.storeCard.backFields[2].value = serial;
    obj.storeCard.backFields[3].value = amount;
    obj.storeCard.backFields[4].value = purchasedate;
    obj.storeCard.backFields[5].value = activationlink;
    obj.storeCard.backFields[6].value = terms;

    var newData = JSON.stringify(obj);

    try {
      // write file to disk
      fs.writeFileSync(folderName + '/' + 'pass.json', newData, 'utf8')

      console.log(`File is written successfully!`)
    } catch (err) {
      console.log(`Error writing file: ${err}`)
    }

  } catch (err) {
    console.log(`Error reading file from disk: ${err}`)
  }


  console.log(providerImageUrl);
  console.log(productImageUrl);

  try {

    const responseProv = await fetch(providerImageUrl,{},proxy_url);
    const blobProv = await responseProv.blob();
    const arrayBufferProv = await blobProv.arrayBuffer();
    const bufferProv = Buffer.from(arrayBufferProv);
    fs.writeFileSync(folderName + '/icon.png', bufferProv, 'binary', (err) => {
      if (err) {
        console.log(err);
      }
      console.log('Provider icon saved.');
    })
    fs.writeFileSync(folderName + '/icon@2x.png', bufferProv, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Provider icon saved.');
    })

    fs.writeFileSync(folderName + '/logo.png', bufferProv, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Provide logo saved.');
    })

    const response = await fetch(productImageUrl,{},proxy_url);
    const blob = await response.blob();
    const arrayBuffer = await blob.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(folderName + '/striplogo.png', buffer, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Product Logo saved.');
    })

  }
  catch (error) {
    console.log(error);
  }

  await generatePassStrip(key, folderName);

  pass.add('pass.json', folderName + '/pass.json')

  pass.add('icon.png', folderName + '/icon.png')
  pass.add('icon@2x.png', folderName + '/icon@2x.png')

  pass.add('logo.png', folderName + '/logo.png')


  pass.add('strip.png', folderName + '/strip.png')
  pass.add('strip@2x.png', folderName + '/strip@2x.png')

  const pkpass = pass.generate()

  fs.writeFileSync(folderName + '/' + reference + '.pkpass', pkpass);

  fs.unlinkSync(folderName + '/icon.png');
  fs.unlinkSync(folderName + '/icon@2x.png');
  fs.unlinkSync(folderName + '/logo.png');
  fs.unlinkSync(folderName + '/pass.json');
  fs.unlinkSync(folderName + '/strip.png');
  fs.unlinkSync(folderName + '/strip@2x.png');
  fs.unlinkSync(folderName + '/striplogo.png');
}

app.get('/getCardStatus', cors(corsOptions), async (req, res) => {
    
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getCardStatus => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        
  let data = Buffer.from(req.query.data,'base64').toString('utf8');
  let arr = data.split(',');
  let localdate = arr[0];
  let promoCode = arr[1];
  let tid = arr[2];
  

  let txid = getTimeStamp();
  let x = Math.random() * 1000000000;    
  let y = x.toString().split('.');  
  let reference = 'EPAY-'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
  

  let session_id = reference;
  let host_log = req.hostname.split('.');
  let method = 'GET_CARD_STATUS';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';
  console.log(log_prefix + req.headers.campaign + '>>API_CALL:getCardStatus => clientip: ' + clientip + log_suffix);
  console.log(log_prefix + data + log_suffix);
  let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';
  let jsonResponse = await getPromoCardStatus(tidhead,reference,promoCode,log_prefix,log_suffix,clientip,req);
  
  console.log(log_prefix + req.headers.campaign + '>>API_CALL:getCardStatus => clientip: ' + clientip + log_suffix);

  if(jsonResponse.includes('<ATTRIBUTE NAME="PROXY'))
  {
    let resp = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_157',req)+'</RESULTTEXT></RESPONSE>';
    console.log(log_prefix + resp + log_suffix);
	    res.send(resp);
  }else {
    console.log(log_prefix + jsonResponse + log_suffix);
      res.send(jsonResponse);
  }

} catch (error) {
  console.log('Something went wrong. Please try again later!');
  let str = getMessageIDText('MESSAGEID_165',req);
  
    let customer = await getCustomerName(req.hostname);
    let support_url = await getDomainSupportUrl(req.hostname);
    str = getMessageIDText('MESSAGEID_102',req) + customer + getMessageIDText('MESSAGEID_103',req) + support_url;
  
  res.send('<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+str+'</RESULTTEXT></RESPONSE>')
}

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }



})

async function chargePromoCode(tid,promoCode,promoDiscount,reference,log_prefix,log_suffix,amount_product,hostname,clientip,req) {

  try {

      let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';

      let jsonResponse = await getPromoCardStatus(tidhead,reference,promoCode,log_prefix,log_suffix,clientip,req);
  

      if ((jsonResponse.includes('<RESULT>0</RESULT>'))&&(jsonResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))&&(!jsonResponse.includes('<ATTRIBUTE NAME="PROXY'))) {

        let arr = jsonResponse.split('<CURRENCY STANDARD=');
        let arr1 = arr[1].split('<BALANCE>');
        let arr2 = arr1[1].split('</BALANCE>');
        let balance = arr2[0];
        let discount = '0';
        if(Number(balance) >= Number(amount_product) )
        {
          discount = amount_product;
        }
        else {
          discount =  balance;
        }

        if(discount == promoDiscount)
        {
        
          let jsonResponse_redeem = await getChargePromoCard(tidhead,reference,discount,promoCode,log_prefix,log_suffix,true,hostname,clientip,req);

          if (jsonResponse_redeem.includes('<RESULT>0</RESULT>')) {
              return 'Success';
          }
          else{
            return jsonResponse_redeem;
          }

      } else {
        return '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_105',req) +'</RESULTTEXT></RESPONSE>';
      }
    

      }
      else if(jsonResponse.includes('<ATTRIBUTE NAME="PROXY')){
        return '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_106',req) +'</RESULTTEXT></RESPONSE>';
      }
      else {
        return jsonResponse;
      }

  } catch (error) {
    console.log('Charge promo code error: ');
    console.log(error);
    let customer = await getCustomerName(req.hostname);
    let support_url = await getDomainSupportUrl(req.hostname);
    let str = getMessageIDText('MESSAGEID_102',req) + customer +getMessageIDText('MESSAGEID_103',req)+ support_url;
    
    str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>' + str + '</RESULTTEXT></RESPONSE>';
    
    return str;
  }

}

//TEST_IP_AZURE
async function getTestSubscriptionInfo(hostname,ean) {

  let info = null;
  let host = (hostname.split('.'))[0];   
  if(hostname == DOMAIN_1)
    {
      if(config['domain_1']) {
      if(config['domain_1'].TestSubscriptionInfo) {
        info = config['domain_1'].TestSubscriptionInfo;
      }
     }
    }
    else if(hostname == DOMAIN_2)
    {
      if(config['domain_2']) {
        if(config['domain_2'].TestSubscriptionInfo) {
          info = config['domain_2'].TestSubscriptionInfo;
        }
      }
    }
    else if(hostname == DOMAIN_3)
    {
      if(config['domain_3']) {
        if(config['domain_3'].TestSubscriptionInfo) {
          info = config['domain_3'].TestSubscriptionInfo;
        }
      }
    }
    else if(hostname == DOMAIN_0)
    {
      if(config['domain_0']) {
        if(config['domain_0'].TestSubscriptionInfo) {
          info = config['domain_0'].TestSubscriptionInfo;
        }
      }
    } 
    else if(config[host]) {
      if(config[host].TestSubscriptionInfo) {
        info = config[host].TestSubscriptionInfo;
      }
    }

    if(info) {
      try {
      let arr = info.split(',');
      let obj = {
        TestSubscriptionEAN: arr[0],
        TestSubscriptionTID: arr[1]

      }
      if((arr.length > 2)&&(ean)) {
      for(let i=2; i<arr.length;i++) {
        if(arr[i] == ean) {
          obj = null;
          console.log('EAN is ignore list of test subscription TID/EAN');
          break;
        }
      }
      }
      console.log(obj);
      return obj;
     }catch(err) {
      console.log(err);
      return null;
     }
    }

    return info;



}

////////////////////////////////////In Store START///////////////////////////////////////////////////////////

async function getInStorePinSale(ean,tid,product,reference,hostname,userIdHost,userPaswdHost,cashier,txnTime,
  amount,amt,productlogo,provLogo,terms,shortdesciption,company,discount,partialPay,
  firstname,lastname,email,phone,title,type,posa_serial,currency,code_redeem,currency_code,
  srcToken,last4,cardtype,cardbin,actionLink,payid,posaSerial,log_prefix,log_suffix,req)
{
      try {

          let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';
          var extrahead = '';

          var eanhead = '<EAN>' + ean + '</EAN>';
          var eantouse = ean;
          if (product.includes('Renewal') || product.includes('renewal')) {
              if(!(await checkIfVodacomFlow(req.hostname) == 'yes'))
              {
                extrahead = '<EXTRADATA>' +
                '<DATA name="CONTRACT">' + reference + '</DATA>' +
                '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
                '</EXTRADATA>';
              }
              else {
                extrahead = '<EXTRADATA>' +
                '<DATA name="CONTRACT">' + reference + '</DATA>' +
                '<DATA name="RedirectionDivisionID">vodacom</DATA>' +
                '</EXTRADATA>';
              }

          }

   

      if(product.toLowerCase().includes('renewal')) {
         let info = await getTestSubscriptionInfo(req.hostname,ean);
         if(info) {
          tidhead = '<TERMINALID>' + info.TestSubscriptionTID + '</TERMINALID>';
          eanhead = '<EAN>' + info.TestSubscriptionEAN + '</EAN>';
         }
      }

      let cashierhead = '';
      if(cashier)
      {
        cashierhead = '<CASHIER>' + cashier + '</CASHIER>';
      }

      let send_sms_tag = '';
      let send_email_tag = '';
      let del_mode = getDeliveryMode(hostname,null);
      if(del_mode.includes('SMS'))
      {
        send_sms_tag = '<SMS>' + '+' + phone + '</SMS>' ;

      }

      if(del_mode.includes('EMAIL'))
      {
        send_email_tag = '<EMAIL>' + email + '</EMAIL>' ;                
      }
      let firstname_tag = '';
      let lastname_tag = '';
      let title_tag = '';
      if(firstname)
      {
         firstname_tag =  '<NAME>' + firstname + '</NAME>';
      }         

      if(lastname)
      {
         
         lastname_tag =  '<SURNAME>' + lastname + '</SURNAME>' ;
      }
      if(title)
      {
        title_tag = '<TITLE>' + title + '</TITLE>';
      }

      let PAN_TAG = '';
      let CURRENTCY_TAG = '';

      if(type == 'POSA')
      {
        PAN_TAG = '<PAN>' + posaSerial + '</PAN>';
        CURRENTCY_TAG = '<CURRENCY>' + currency + '</CURRENCY>';
      }

      

      //Business in a box
      if(await isBusinesInABoxAkani(tid,ean,req)) {
        let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + reference  + '</DATA>'; //+ '_sale'
        if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
          extrahead = extrahead.replace('</EXTRADATA>', REFID_URL_TAG+'</EXTRADATA>')
        }
        else {
          extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
        }
        
      }

      let fetchOptions = {
          method: 'POST',

          body: '<REQUEST type="SALE" STORERECEIPT="1">' +
          '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
          '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
          tidhead +
          cashierhead +
          '<TXID>' + (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference)   + '</TXID>' + //+ '_sale'
          '<USERNAME>' + userIdHost + '</USERNAME>' +
          '<CARD>' +
          PAN_TAG +
          eanhead +                  
          '</CARD>' +
          '<AMOUNT>'+ amount +'</AMOUNT>' +
          '<Comment>' + 'PaymentMethod=instore|PAN='+ posa_serial + '</Comment>' +
          CURRENTCY_TAG +
          '<CONSUMER>' +          
          firstname_tag + 
          lastname_tag +
          send_sms_tag +
          send_email_tag +
          title_tag +      
          '</CONSUMER>' +
          extrahead.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req)))  +
          '</REQUEST>',

          headers: {
          'Content-Type': 'application/xml',
          },

      }



      console.log(log_prefix + 'InStore SALE Request: ' + UPInterfaceURL + log_suffix);

      console.log(fetchOptions.body);
  

      const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
      var jsonResponse = await response.text();
      jsonResponse = await updateRedeemptionURL(jsonResponse);
      const UUID = require('pure-uuid');
      const id = new UUID(4).format();
      let encyptBlockTime = getTimeStamp();

      let block =  id + '/' + reference + '.pkpass' + ',' + encyptBlockTime;
      let token = encrypt(block);
      let jsonResponse_log = jsonResponse ;
      jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

      console.log(log_prefix + 'InStore SALE Response:' + log_suffix);

      mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

  
      let encyptBlockTimeGMT = new Date();
      let passLink = 'https://' + hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();

      if(jsonResponse.includes('<RESULT>0</RESULT>'))
      {

      let activation_serial_tag = '<ACTIVATIONSERIAL>' + posaSerial + '</ACTIVATIONSERIAL>';
      let product_type_tag = '<PRODUCTTYPE>' + type + '</PRODUCTTYPE>';
      let currency_tag = '<CURRENCYCODEP>'+currency_code+'</CURRENCYCODEP>';      
      let discount_tag = '<PROMODISCOUNT>' + discount + '</PROMODISCOUNT>';
      let promo_tag =  code_redeem.length > 4 ? '<PROMOCODE>' + 'xxxx' +code_redeem.substring(code_redeem.length - 4, code_redeem.length) + '</PROMOCODE>' : '<PROMOCODE>'+code_redeem+'</PROMOCODE>';
      let partial_tag = '<PARTIALPAY>' + partialPay + '</PARTIALPAY>';
      let apple_pass_tag = '<PASS></PASS>';
      if(await getApplePassAllowed(req.hostname) == 'yes')
      {
         apple_pass_tag = '<PASS>' + passLink + '</PASS>';
      }
      let discRRP = await getDiscountRRP(ean,tid,req);
      let vat = await getItemVAT(req,ean,tid);
      let discountrrp_tag = '<PREDISCOUNTRRP>' + discRRP + '</PREDISCOUNTRRP>';
      let vat_tag = '<VAT>' + vat + '</VAT>';

      jsonResponse = jsonResponse + 
      '<PAID>' + amt + '</PAID>' + 
      '<PRODUCT>' + product + '</PRODUCT>' +
      '<HOME>https://' + hostname + '</HOME>' + '<EAN>' + ean +'</EAN>' + '<TYPE>' + type + '</TYPE>' +
      apple_pass_tag + discount_tag + promo_tag + currency_tag + partial_tag + activation_serial_tag + product_type_tag + vat_tag + discountrrp_tag;     
      let redeemURL = '';
      jsonResponse = jsonResponse + '<CARDTYPE>' + cardtype + ' x' + last4 + '</CARDTYPE>' +                  
                  '<SHORTDESC>' + shortdesciption + '</SHORTDESC>' +  
                  '<LOGO>' + productlogo + '</LOGO>' +                 
                  '<URLREDEEM>' + redeemURL + '</URLREDEEM>';
                  

      jsonResponse_log = jsonResponse ;
      jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

      mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
      }


      if (jsonResponse.includes('<RESULT>0</RESULT>')) {
      console.log(reference); 
      var strref = reference;
      var arrRefSplit = strref.split('-');
      var actlink = '';// redeemURL;
      var productKey = '';
      var prodSerial = '';
      if (jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
          let newarr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
          if (newarr.length > 1) {
          let arr1 = newarr[1].split('</DATA>');
          actlink = arr1[0];
          }
      }

      if (jsonResponse.includes('<PIN>')) {
        let newarr = jsonResponse.split('<PIN>');
        if (newarr.length > 1) {
          var arr1 = newarr[1].split('</PIN>');
          productKey = arr1[0];
        }
      }

      if (jsonResponse.includes('<SERIAL>')) {
      var newarr = jsonResponse.split('<SERIAL>');
      if (newarr.length > 1) {
      var arr1 = newarr[1].split('</SERIAL>');
      prodSerial = arr1[0];
      }
      }
      var prodExpiry = '';
      if (jsonResponse.includes('<VALIDTO>')) {
      var newarr = jsonResponse.split('<VALIDTO>');
      if (newarr.length > 1) {
      var arr1 = newarr[1].split('</VALIDTO>');
      prodExpiry = arr1[0];
      if (prodExpiry == '3000-01-01 00:00:00') {
      prodExpiry = 'Never Expires';
      }
      }
      }



      let emailToSend =  email;
      let phoneToSend =  phone;
      let emailTAG= '<EMAIL></EMAIL>';
      let phoneTAG = '<PHONE></PHONE>';
      if(emailToSend)
      {
      if(emailToSend.length > 0)
      {
      emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
      }
      }
      if(phoneToSend)
      {
      if(phoneToSend.length > 0)
      {
      phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
      }
      } 


      if ((product.includes('Renewal')) || product.includes('renewal')) {
             let auth_tag = '';
             let auth_code = '';
            console.log('actionLink::::'+actionLink);
            if(actionLink)
            {
              auth_code = await getAuthCode(actionLink,tid,hostname,log_prefix,log_suffix,req);
              console.log(log_prefix + 'auth_code: ' + auth_code + log_suffix);
              if(auth_code != 'none')
              {
                auth_code = '-' + auth_code;
              }
              else
              {
                auth_code = '';
              }
              auth_tag = '<AUTHCODE>' + auth_code.replace('-','') + '</AUTHCODE>';
              console.log(auth_tag);
          }
         


            let payid_tag = '';
            if(payid)
            {
              payid_tag = '<PAYMENTID>' + payid + '</PAYMENTID>' ;
            }

            let cardbin_tag = '';
            if(cardbin)
            {
              cardbin_tag = '<BIN>' + cardbin + '</BIN>';
            }
            let reftype_tag = '';
            if(email)
            {
              reftype_tag = '<REFTYPE>SERIAL</REFTYPE>';
            }
            else {
              reftype_tag =  '<REFTYPE>CONTRACTID</REFTYPE>';
            }

            const fetchOptionsInfo = {
            method: 'POST',

            body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
            '<USERNAME>' + userIdHost + '</USERNAME>' +
            '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
            tidhead +
            '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +    
            '<TXID>' + (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference)  + '_PI' + '</TXID>' +
            '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
            '<SUBSCRIPTION>' +
            '<TOKENID>' + srcToken + '</TOKENID>' +
            '<LASTFOUR>' + last4 + '</LASTFOUR>' +
            '<CARDTYPE>' + cardtype + '</CARDTYPE>' +
            payid_tag +
            emailTAG +
            phoneTAG +
            cardbin_tag +
            auth_tag +
            '</SUBSCRIPTION>' +
            '<TRANSACTIONREF>' +
            reftype_tag +
            '<REF>' + (reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req)))) + '</REF>' +
            '</TRANSACTIONREF>' +
            '</REQUEST>',

            headers: {
            'Content-Type': 'application/xml',
            },

            }


              console.log(log_prefix + 'InStore PIN PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
              mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
              console.log(log_prefix + paymentInfoURL + log_suffix);
              const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
              var jsonResponseInfo = await response.text();

            console.log(log_prefix + 'InStore PIN PAYMENTINFO Response:' + log_suffix);
            let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
              mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);

      }
      let allowed_google = await getGooglePassAllowed(req.hostname);
        let allowed_apple = await getApplePassAllowed(req.hostname);
      if((allowed_apple == 'yes')||(allowed_google == 'yes')) {
      try {
        const findRemoveSync = require('find-remove');
        
        if(allowed_google == 'yes') { 
          let objGoogle = [];
          objGoogle.push({
          reference:reference,
          productLogo:productlogo,
          product:product,
          provider:company,
          serial:prodSerial,
          expiry:prodExpiry,
          amount:amt,
          pin:productKey,
          description:shortdesciption,
          tx_time:txnTime,
          refSplit:arrRefSplit[1],
          phone:phone,
          terms:terms,
          actlink:actlink,
          providerLogo:provLogo,
          id:id,
          stripe:''
          });
          await generateGooglePass(objGoogle[0]);
          //objGoogle[0].stripe = 'https://' + hostname + '/static/media/Google/passes/' + objGoogle[0].id + '/strip@2x.png';
          objGoogle[0].stripe = 'https://' + hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
          let googlePassUrl = await createPassObject(objGoogle);

          jsonResponse = jsonResponse + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
          console.log('Response GPass: ' + googlePassUrl);
          setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
        } else {
          jsonResponse = jsonResponse + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';
        }
          
          
          if(allowed_apple == 'yes')
          {
           await generatePass(productlogo, reference, product, prodSerial, prodExpiry, amt, productKey, shortdesciption, txnTime, arrRefSplit[1], phone, terms, actlink,provLogo, id);
           setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
          }
         
  
      }
      catch (err)
      {
          console.log(log_prefix + err + log_suffix);
      }
      }
      console.log(log_prefix + jsonResponse + log_suffix);
      await sendOrderSuccessMessage_ib(jsonResponse,phone,req,log_prefix,log_suffix);
      return jsonResponse;

      }
      else{
        jsonResponse = jsonResponse + '<HOME>https://' + hostname + '</HOME>' + '<EAN>' + ean +'</EAN>';
        console.log(log_prefix + jsonResponse + log_suffix);
         return jsonResponse;
      }

      }
      catch(err)
      {
        console.log(err);
        return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_107',req)+'</RESULTTEXT></RESPONSE>'
      }

}

async function toFixed(num,fixed){
  var re = new RegExp('^-?\\d+(?:\.\\d{0,' + (fixed || -1) + '})?');
  let xe = num.toString().match(re)[0];
  if(!xe.includes('.')) {
    xe = xe + '.00';    
  } else {
    let ye = xe.split('.');
    if(ye[1].length == 1) {
      xe = xe + '0';      
    }
  }
  return xe;
 }

 async function getDomainVATCalcApplicable(hostname) {

  let result = 'no';

  let host = (hostname.split('.'))[0];

  if(hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].REDEEM_VAT) {
      result = config['domain_1'].REDEEM_VAT;
    }
   }
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].REDEEM_VAT) {
        result = config['domain_2'].REDEEM_VAT;
      }
    }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].REDEEM_VAT) {
        result = config['domain_3'].REDEEM_VAT;
      }
    }
  }
  else if(hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].REDEEM_VAT) {
        result = config['domain_0'].REDEEM_VAT;
      }
    }
  } else if(config[host]) {
    if(config[host].REDEEM_VAT) {
      result = config[host].REDEEM_VAT;
    }
  }

  return result;
}

async function checkIfVATApplicable(ean,tid,req) {
  let blockToParse = await getCatalog(req.hostname,tid,ean,0,req);                
  let vat_calc = await getDomainVATCalcApplicable(req.hostname) ;         
  if((blockToParse != 'no_data')&&(blockToParse.includes('<VAT>5</VAT>')) && (vat_calc == 'yes'))
  {
      return true;
  }
  else {
    return false;
  }

}
app.get('/getPaymentSerialStatus', cors(corsOptions),async(req,res)=> {
     
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPaymentSerialStatus => clientip: ' + clientip);
 

  if (req.headers.referer) {
    if(await checkIfRefererAllowed(req.headers.referer,req)) {
        try {
        
            let obj_p = JSON.parse(Buffer.from(req.query.data,'base64').toString('utf8'));
            let obj = obj_p[0];
            console.log(obj);           

            let decryptedString = decrypt(obj.encBlock);
            let dec_arr = decryptedString.split(',');
            let amount_product = dec_arr[0];
            let payment_serial = dec_arr[1];
            console.log('amount_product::::::::::::::::::::'+ amount_product);

	    let product_ean = dec_arr[2];
            let promoCode = (dec_arr[3] == 'undefined') ? 'none':dec_arr[3];
            let discountApplied = (dec_arr[4] == 'undefined') ? '0':dec_arr[4];
            let reference = dec_arr[5];
            let promoApplied = (dec_arr[6] == 'undefined') ? '0':dec_arr[6];


            let product = obj.product;
            
            if(obj.phone.length == 9)
	    {
               let ref_arr = reference.split('-');
	       reference = ref_arr[0] + '-' + ref_arr[1] + '-' + obj.phone.substring(obj.phone.length-9,obj.phone.length);
            }
            console.log('reference =====>' + reference  + '::::' + obj.phone);
            let calling_code = '27';
            if(!(await checkIfVodacomFlow(req.hostname) == 'yes'))
            {
             calling_code = '971';  
            }
            if(obj.phone.length == 9)
            {
               obj.phone = calling_code + obj.phone;
            }
            console.log('phone =====>' + obj.phone);

            let srcToken = ''; 
            let last4 = '';
            let cardtype = '';
            let cardbin = '';
            let actionLink = '';
            let paymentId = '';
            
            if(product.includes('Renewal'))
            {
              let decryptedStringSubs = decrypt(obj.encBlockSubs);
              let dec_arr_subs = decryptedStringSubs.split(',');

               srcToken = dec_arr_subs[0]; 
               last4 = dec_arr_subs[1];
               cardtype = dec_arr_subs[2];
               cardbin = dec_arr_subs[3];
               actionLink = dec_arr_subs[4];
               paymentId =dec_arr_subs[5];

            }

            let session_id = reference;
            let host_log = req.hostname.split('.');
            let method = 'GET_PAYMENT_SERIAL_STATUS';
            let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
            let log_suffix = '\n</LOG></SESSION_LOG>';
            
            console.log(log_prefix + req.headers.campaign + '>>API_CALL:getPaymentSerialStatus => clientip: ' + clientip + log_suffix);

            let tidhead = '<TERMINALID>' + obj.tid + '</TERMINALID>';
            let cardStatusResponse = await getPromoCardStatus(tidhead,reference,payment_serial,log_prefix,log_suffix,clientip,req);
            console.log(log_prefix + cardStatusResponse + log_suffix);
            if((cardStatusResponse.includes('<RESULT>0</RESULT>'))&&(cardStatusResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))) {

              if(cardStatusResponse.includes('<BALANCE>')) {
                let a1 = cardStatusResponse.split('<BALANCE>');
                let a2 = a1[2].split('</BALANCE>');
                let balance= a2[0];
                console.log(log_prefix + 'Balance from CARDSTATUS: ' + balance + log_suffix);


                let amount_pay = Number(amount_product) - Number(discountApplied);

                let isVATApplicable = await checkIfVATApplicable(product_ean,obj.tid,req);           
                if(isVATApplicable) {
                  console.log(log_prefix + 'VAT applicable 5% to amount ' + amount_pay + log_suffix);
                  let amount_product_decimal = (Number(amount_product) - Number(discountApplied)).toString();
                  amount_product_decimal = amount_product_decimal.substring(0,amount_product_decimal.length - 2) + '.' + amount_product_decimal.substring(amount_product_decimal.length - 2,amount_product_decimal.length)
                  let amt_div = (Number(amount_product_decimal)/1.05);
                  let amount_pay_x = await toFixed(amt_div,2);                               
                  amount_pay_x = amount_pay_x.replace('.',''); 
                  amount_pay = Number(amount_pay_x);               
                }

                console.log(log_prefix + 'Amount to be compare with balance: ' + amount_pay + log_suffix);

                if(Number(balance) >= amount_pay)
                {
                  amount_pay = Number(balance);
                  let blockToParse = await getCatalog(req.hostname,obj.tid,product_ean,0,req);
             
                    
                  if(blockToParse != 'no_data')
                  {      

                      let desc_info = await getDescriptionInfo(blockToParse,req.hostname,product_ean,req);        
                      let add_info = '';
                      let add_info_append = '';      
                      let product = '';
                      let amount = '';
                      let amt = '';
                      let terms = '';
                      let productlogo = '';
                      let shortdesciption = '';
                      let company = '';
                      let provLogo = '';
                      let type = '';
                      let currency = '';
                      if(desc_info.includes('<ADD_INFO>'))
                      {
                        let arr = desc_info.split('<ADD_INFO>');
                        let arr1 = arr[1].split('</ADD_INFO>');
                    
                        add_info = arr1[0];
                        console.log(add_info);      

                        arr = add_info.split('<PRODUCT_INFO>');
                        arr1 = arr[1].split('</PRODUCT_INFO>');
                        product = arr1[0];

                        arr = add_info.split('<AMOUNT_INFO>');
                        arr1 = arr[1].split('</AMOUNT_INFO>');
                        amount = arr1[0];
                        add_info_append = arr[0];

                        arr = add_info.split('<AMT_INFO>');
                        arr1 = arr[1].split('</AMT_INFO>');
                        amt = arr1[0];

                        arr = add_info.split('<MAXAMOUNT>');
                        arr1 = arr[1].split('</MAXAMOUNT>');
                        let maxamount = arr1[0];

                        if(Number(maxamount) > 0 ) {
                          let currencycode = 'AED';
                          let country_code = await getCountryCode(req.hostname);
                          if(country_code == 'ZA') {
                            currencycode = 'ZAR';
                          } else if(country_code == 'TR') {
                            currencycode = 'TRY';
                          } else if(country_code == 'SA') {
                            currencycode = 'SAR';
                          }

                          let getSymbolFromCurrency = require('currency-symbol-map');
                          let symbol = getSymbolFromCurrency(currencycode);
                          if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
                            symbol = '\u{2800}';
                          }

                          let str = amount_product;
                          let str1 = '';                
                          if (str == 0) {
                             str1 = symbol + '0.00';
                          }
                          else {
                             str1 = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
                          }         
                         
                
                           amt = str1;
                
                        }

                        arr = add_info.split('<SHORTDESC>');
                        arr1 = arr[1].split('</SHORTDESC>');
                        shortdesciption = arr1[0];

                        arr = add_info.split('<TERMS>');
                        arr1 = arr[1].split('</TERMS>');
                        terms = arr1[0];

                        arr = add_info.split('<LOGO>');
                        arr1 = arr[1].split('</LOGO>');
                        productlogo = arr1[0];

                        arr = add_info.split('<PROVLOGO>');
                        arr1 = arr[1].split('</PROVLOGO>');
                        provLogo = arr1[0];

                        arr = add_info.split('<COMPANY>');
                        arr1 = arr[1].split('</COMPANY>');
                        company = arr1[0];

                        arr = add_info.split('<TYPE>');
                        arr1 = arr[1].split('</TYPE>');
                        type = arr1[0];

                        arr = add_info.split('<CURRENCY>');
                        arr1 = arr[1].split('</CURRENCY>');
                        currency = arr1[0];
                      }     
                  
                      let txnTime = getFormattedTime();

                      let up_cred = await getUPCredentials(req);

                      let userIdHost = up_cred.userIdHost;
                      let userPaswdHost = up_cred.userPaswdHost;
                      let customer = up_cred.customer;            
                    
                  
                      
                      //do sale
                      let jsonResponse_redeem = await getChargePromoCard(tidhead,reference,amount_pay.toString(),payment_serial,log_prefix,log_suffix,true,req.hostname,clientip,req);
                      console.log(log_prefix + jsonResponse_redeem + log_suffix);
                      if (jsonResponse_redeem.includes('<RESULT>0</RESULT>')) {

                        let posaSerial = null;
                        if(obj.posaSerial)
                        {
                          posaSerial = obj.posaSerial;
                        }
                        //do sale
                        let response = await getInStorePinSale(product_ean,obj.tid,product,reference,req.hostname,
                          userIdHost,userPaswdHost,obj.cashier,txnTime,amount_product,amt,productlogo,provLogo,terms,
                          shortdesciption,company,discountApplied,amount_pay,obj.firstname,obj.lastname,obj.email,
                          obj.phone,obj.title,type,payment_serial,currency,promoCode,currency,
                          srcToken,last4,cardtype,cardbin,actionLink,paymentId,posaSerial,log_prefix,log_suffix,req);
                          console.log(log_prefix + response + add_info + log_suffix);
                          res.send(response + add_info); 
                          return;
                         
                      }
                      else{
                        
                        res.send(jsonResponse_redeem);
                        return;
                      }                      


                      

                   }
                }
                else {
                  //process refund if promo was used
                  if((promoApplied == '1')&&(discountApplied != '0')) {                                 
                  
                      let result_refund_promo = await refundPromoDiscount(obj.tid,reference, promoCode,log_prefix,log_suffix,req);
                      console.log(log_prefix + 'result_refund_promo_instore: ' + result_refund_promo + log_suffix);
                   }

                  let resp = '<RESPONSE><RESULT>13</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_108',req)+'</RESULTTEXT></RESPONSE>';
                  console.log(log_prefix + resp + log_suffix);
                  res.send(resp);

                }


              }
              else {
                let resp = '<RESPONSE><RESULT>12</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>';
                console.log(log_prefix + resp + log_suffix);
                res.send(resp);
              }

            }
            else if(cardStatusResponse.includes('<RESULT>0</RESULT>'))
            {
              cardStatusResponse = cardStatusResponse.replace('</RESPONSE>',  '<PAYMENTSERIALSTATUS>PENDING</PAYMENTSERIALSTATUS></RESPONSE>');
              console.log(log_prefix + cardStatusResponse + log_suffix);
              res.send(cardStatusResponse);
            }
            else
            {
              console.log(log_prefix + cardStatusResponse + log_suffix);
              res.send(cardStatusResponse);
            }

        } catch (error) {
          console.log('exception in payment serial::' + error); 
          res.send('<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>')
        }
        
        } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
        
        } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
        

});



app.get('/getPubKey', cors(corsOptions), async (req, res) => {
  
  try {

    let cred = await getCheckoutCredentials(req.hostname,req);
    if(cred)
    { 

      if(cred.publicKey) {
        let publicKey  = cred.publicKey;
        res.send(publicKey);
        return;
      }
      
    } 

    console.log('CHECKOUT CONFIGURATION PUBLIC KEY ERROR: ');

   let CheckoutPublicKey = 'NO_KEY';

    res.send(CheckoutPublicKey);
 } catch (err) {
  console.log('CHECKOUT CONFIGURATION PUBLIC KEY ERROR: ' + err);
  res.send('NO_KEY');
 }
 
});


//===================================================//

async function getCheckoutCredentials(hostname,req) {
  try {
        let host = (hostname.split('.'))[0];

        let CheckoutSecretKey = '';
        let checkout_protocol = '';
        let processingChannelID = '';
        let prefix = '';
        let url = '';
        let publicKey = '';

        if((hostname == DOMAIN_1)&&(config['domain_1']))
        {
        
            if(config['domain_1'].CheckoutSecretKey) {
              CheckoutSecretKey = config['domain_1'].CheckoutSecretKey;
            }
            if(config['domain_1'].CheckoutProcessingChannelID) {
              processingChannelID = config['domain_1'].CheckoutProcessingChannelID;
            }
            if(config['domain_1'].CheckoutProtocol) {
              checkout_protocol = config['domain_1'].CheckoutProtocol;
            }
            if(config['domain_1'].CheckoutPublicKey) {
              publicKey = config['domain_1'].CheckoutPublicKey;
            }
            if(config['domain_1'].CheckoutPrefix) {
              prefix = config['domain_1'].CheckoutPrefix;
            }
            if(config['domain_1'].CheckoutUrl) {
              url = config['domain_1'].CheckoutUrl;
            }
            
            
        
        }
        else if((hostname == DOMAIN_2)&&(config['domain_2']))
        {
          if(config['domain_2'].CheckoutSecretKey) {
            CheckoutSecretKey = config['domain_2'].CheckoutSecretKey;
          }
          if(config['domain_2'].CheckoutProcessingChannelID) {
            processingChannelID = config['domain_2'].CheckoutProcessingChannelID;
          }
          if(config['domain_2'].CheckoutProtocol) {
            checkout_protocol = config['domain_2'].CheckoutProtocol;
          }
          if(config['domain_2'].CheckoutPublicKey) {
            publicKey = config['domain_2'].CheckoutPublicKey;
          }
          if(config['domain_2'].CheckoutPrefix) {
            prefix = config['domain_2'].CheckoutPrefix;
          }
          if(config['domain_2'].CheckoutUrl) {
            url = config['domain_2'].CheckoutUrl;
          }
        }
        else if((hostname == DOMAIN_3)&&(config['domain_3']))
        {
          if(config['domain_3'].CheckoutSecretKey) {
            CheckoutSecretKey = config['domain_3'].CheckoutSecretKey;
          }
          if(config['domain_3'].CheckoutProcessingChannelID) {
            processingChannelID = config['domain_3'].CheckoutProcessingChannelID;
          }
          if(config['domain_3'].CheckoutProtocol) {
            checkout_protocol = config['domain_3'].CheckoutProtocol;
          }
          if(config['domain_3'].CheckoutPublicKey) {
            publicKey = config['domain_3'].CheckoutPublicKey;
          }
          if(config['domain_3'].CheckoutPrefix) {
            prefix = config['domain_3'].CheckoutPrefix;
          }
          if(config['domain_3'].CheckoutUrl) {
            url = config['domain_3'].CheckoutUrl;
          }
        }
        else if((hostname == DOMAIN_0)&&(config['domain_0']))
        {
          if(config['domain_0'].CheckoutSecretKey) {
            CheckoutSecretKey = config['domain_0'].CheckoutSecretKey;
          }
          if(config['domain_0'].CheckoutProcessingChannelID) {
            processingChannelID = config['domain_0'].CheckoutProcessingChannelID;
          }
          if(config['domain_0'].CheckoutProtocol) {
            checkout_protocol = config['domain_0'].CheckoutProtocol;
          }
          if(config['domain_0'].CheckoutPublicKey) {
            publicKey = config['domain_0'].CheckoutPublicKey;
          }
          if(config['domain_0'].CheckoutPrefix) {
            prefix = config['domain_0'].CheckoutPrefix;
          }
          if(config['domain_0'].CheckoutUrl) {
            url = config['domain_0'].CheckoutUrl;
          }
        } 
        else if(config[host]) {
          if(config[host].CheckoutSecretKey) {
            CheckoutSecretKey = config[host].CheckoutSecretKey;
          }
          if(config[host].CheckoutProcessingChannelID) {
            processingChannelID = config[host].CheckoutProcessingChannelID;
          }
          if(config[host].CheckoutProtocol) {
            checkout_protocol = config[host].CheckoutProtocol;
          }
          if(config[host].CheckoutPublicKey) {
            publicKey = config[host].CheckoutPublicKey;
          }
          if(config[host].CheckoutPrefix) {
            prefix = config[host].CheckoutPrefix;
          }
          if(config[host].CheckoutUrl) {
            url = config[host].CheckoutUrl;
          }
        }

        if(CheckoutSecretKey.length > 5)
        {
          if((CheckoutSecretKey.substring(0,5) == '!PWD!'))
            CheckoutSecretKey = decrypt_pwd(CheckoutSecretKey.substring(5,CheckoutSecretKey.length),PWD_SECRET_KEY,PWD_IV)
        }
        
        if(prefix.length)
        {
          prefix = prefix + ' ';
        }

        let obj = {
          CheckoutSecretKey:CheckoutSecretKey,
          checkout_protocol:checkout_protocol,
          processingChannelID: processingChannelID,
          prefix: prefix,
          url:url,
          publicKey:publicKey
        };
        console.log(obj);

        if(!(
          (CheckoutSecretKey.length)                    
          &&(url.length)&&(url.substring(0,8) == 'https://')
          &&(publicKey.length)
        )) { 

          console.log('CHECKOUT CONFIGURATION ERROR: Please verify checkout configuration');

      }
        
      return obj;
      
   
    }catch(err) {
      console.log(err);
      return null;
    }
}

app.get('/getGPayMerchantInfo', cors(corsOptions),async(req,res)=> {
  const clientip = req.headers['incap-client-ip'] ;
  console.log('>>API_CALL:getGPayMerchantInfo => clientip: ' + clientip);

  try {
          let googlepay = '';
          let host_a = req.hostname.split('.');
          let host = host_a[0];
          if(req.hostname == DOMAIN_0) {
            googlepay = 'domain_0';
          } else if(req.hostname == DOMAIN_1) {
            googlepay = 'domain_1';
          } else if(req.hostname == DOMAIN_2) {
            googlepay = 'domain_2';
          }else  if(req.hostname == DOMAIN_3) {
            googlepay = 'domain_3';
          } else if(config[host]) {
            googlepay = host;
          } else {
            res.send('NO DATA');
          } 
          
          var obj = {};

          console.log(googlepay);
          console.log(config[googlepay]);

          let checkoutInfo = await getCheckoutCredentials(req.hostname,req);
        
          if((config[googlepay])&&(checkoutInfo))
          {
            let obj = {
              merchantIdentifier:config[googlepay].GooglePayMerchantIdentifier,
              merchantName:config[googlepay].GooglePayMerchantName ,
              mode:config[googlepay].GooglePayMode,
              publicKey:checkoutInfo.publicKey,
              checkoutUrl:config[googlepay].GooglePayTokenUrl
            };
            console.log(obj);
            res.send(obj);
            return;
          }
          res.send(obj);
  } catch (err) {
    console.log('Get GPay Merchant Info request failed with exception: ' + req.hostname);
    console.log(err);
    res.send(null);
  }
});


async function getApplePayMerchantInfo(req) {
  try {
        let host_a = req.hostname.split('.')
        let host = host_a[0];
        let applepay = '';
        if(req.hostname == DOMAIN_0) {
          applepay = 'domain_0';
        } else if(req.hostname == DOMAIN_1) {
          applepay = 'domain_1';
        } else if(req.hostname == DOMAIN_2) {
          applepay = 'domain_2';
        }else  if(req.hostname == DOMAIN_3) {
          applepay = 'domain_3';
        } else if(config[host]) {
          applepay = host;
        } else {
          return {};
        }

        let obj = {};

        console.log(config[applepay]);
        
        if(config[applepay])
        {
          let obj = {
            merchantIdentifier:config[applepay].ApplePayMerchantIdentifier,
            shopDisplayName:config[applepay].ApplePayShopDisplayName ,
            certificatePathKEY:config[applepay].ApplePayCertificatePathKEY,
            certificatePathPEM:config[applepay].ApplePayCertificatePathPEM,
            sessionEndpoint:(config[applepay].ApplePaySessionEndpoint ? config[applepay].ApplePaySessionEndpoint : 'https://apple-pay-gateway.apple.com/paymentservices/startSession'),
            passphrase: (config[applepay].ApplePayCertificatePassphrase ? config[applepay].ApplePayCertificatePassphrase : undefined)
          };
          let objRet = JSON.parse(JSON.stringify(obj));
          console.log(objRet);
          return objRet;
          
        }
        console.log(obj);
        return obj;
    } catch(err) {
      console.log(err);
      return null;
    }
}

///////////////////////////////REWARD////////////////////////////////////////

async function getPathUploadReward(req) {

  let result = log_directory;
  let host = (req.hostname.split('.'))[0];
  if(req.hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].IMAGE_UPLOAD_PATH) {
      result = config['domain_1'].IMAGE_UPLOAD_PATH;
    }
   }
  }
  else if(req.hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].IMAGE_UPLOAD_PATH) {
        result = config['domain_2'].IMAGE_UPLOAD_PATH;
      }
    }
  }
  else if(req.hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].IMAGE_UPLOAD_PATH) {
        result = config['domain_3'].IMAGE_UPLOAD_PATH;
      }
    }
  }
  else if(req.hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].IMAGE_UPLOAD_PATH) {
        result = config['domain_0'].IMAGE_UPLOAD_PATH;
      }
    }
  }
  else if(config[host]) {
    if(config[host].IMAGE_UPLOAD_PATH) {
      result = config[host].IMAGE_UPLOAD_PATH;
    }
  }


  return result;

}

/////////////Applepass////////////////////////////////////////

async function generatePassStripReward(pin, passdir) {

  const { createCanvas, loadImage } = require('canvas')

  const width = 604  // 1200 + 48
  const height = 490 -250

  const canvas = createCanvas(width, height)
  const context = canvas.getContext('2d')

  context.fillStyle = '#ffffff'
  context.fillRect(0, 0, width, height)



  context.textAlign = 'center'
  context.textBaseline = 'top'
  context.font = '30pt Menlo'
  //context.font =( (pin.length < 24) ?  '60pt Menlo':'40pt Menlo')
  context.fillStyle = '#0066cc'
  context.fillText(pin, 624-324, 310-240)

  loadImage(templatedir + 'pbe.png').then(image => {
    context.drawImage(image, 920-20-350-270, 425-250, 318, 56)
    const buffer = canvas.toBuffer('image/png')
    fs.writeFileSync(passdir + '/strip.png', buffer)
    fs.writeFileSync(passdir + '/strip@2x.png', buffer)
  })
}

async function generatePassReward(objPass) {

  const PassGenerator = require('passgenerator-js');

  folderName = folderNamePass + objPass.id;


  const passGenerator = new PassGenerator({
    appleWWDRCA: folderKeys + 'WWDR4.cer',
    signCert: folderKeys + 'keyStore.p12',
    password: 'ists'
  })

  const pass = passGenerator.createPass()

  try {
    if (!fs.existsSync(folderName)) {
      fs.mkdirSync(folderName);
    }
  } catch (err) {
    console.error(err);
  }

  try {
    const data = fs.readFileSync(templatedir + 'pass.json', 'utf8')

    // parse JSON string to JSON object
    var obj = JSON.parse(data)

    obj.serialNumber = objPass.reference;
    obj.barcode.message = objPass.pan;

    obj.storeCard.headerFields[0].value = objPass.amount;
    obj.storeCard.auxiliaryFields[0].label = 'Issued to:';
    obj.storeCard.auxiliaryFields[0].value = objPass.title + ' ' + objPass.firstname + ' ' + objPass.lastname;
    obj.storeCard.auxiliaryFields[1].value = objPass.expiry;
    obj.storeCard.backFields[0].label = 'Card ID:';
    obj.storeCard.backFields[0].value = objPass.pan;
    obj.storeCard.backFields[1].label = 'Reference:';
    obj.storeCard.backFields[1].value = objPass.reference;
    obj.storeCard.backFields[2].label = 'Serial:';
    obj.storeCard.backFields[2].value = objPass.serial;
    obj.storeCard.backFields[3].label = 'Value:';
    obj.storeCard.backFields[3].value = objPass.amount;
    obj.storeCard.backFields[4].label = 'Transaction Date:';
    obj.storeCard.backFields[4].value = objPass.txndate;
    obj.storeCard.backFields[5].label = 'Redeem Link:';
    obj.storeCard.backFields[5].value = objPass.actlink;
    obj.storeCard.backFields[6].label = 'Retailer:';
    obj.storeCard.backFields[6].value = objPass.store;
    obj.storeCard.backFields.push({key:'city',label:'City:',value:objPass.city});

    var newData = JSON.stringify(obj);

    try {
      // write file to disk
      fs.writeFileSync(folderName + '/' + 'pass.json', newData, 'utf8')

      console.log(`File is written successfully!`)
    } catch (err) {
      console.log(`Error writing file: ${err}`)
    }

  } catch (err) {
    console.log(`Error reading file from disk: ${err}`)
  }


  console.log(objPass.providerLogo);
  console.log(objPass.productLogo);

  try {

    const responseProv = await fetch(objPass.providerLogo,{},proxy_url);
    const blobProv = await responseProv.blob();
    const arrayBufferProv = await blobProv.arrayBuffer();
    const bufferProv = Buffer.from(arrayBufferProv);
    fs.writeFileSync(folderName + '/icon.png', bufferProv, 'binary', (err) => {
      if (err) {
        console.log(err);
      }
      console.log('Provider icon saved.');
    })
    fs.writeFileSync(folderName + '/icon@2x.png', bufferProv, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Provider icon saved.');
    })

    fs.writeFileSync(folderName + '/logo.png', bufferProv, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Provide logo saved.');
    })

    const response = await fetch(objPass.productLogo,{},proxy_url);
    const blob = await response.blob();
    const arrayBuffer = await blob.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(folderName + '/striplogo.png', buffer, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Product Logo saved.');
    })

  }
  catch (error) {
    console.log(error);
  }

  await generatePassStripReward(objPass.pan, folderName);

  pass.add('pass.json', folderName + '/pass.json')

  pass.add('icon.png', folderName + '/icon.png')
  pass.add('icon@2x.png', folderName + '/icon@2x.png')

  pass.add('logo.png', folderName + '/logo.png')


  pass.add('strip.png', folderName + '/strip.png')
  pass.add('strip@2x.png', folderName + '/strip@2x.png')

  const pkpass = pass.generate()

  fs.writeFileSync(folderName + '/' + objPass.reference + '.pkpass', pkpass);

  fs.unlinkSync(folderName + '/icon.png');
  fs.unlinkSync(folderName + '/icon@2x.png');
  fs.unlinkSync(folderName + '/logo.png');
  fs.unlinkSync(folderName + '/pass.json');
  fs.unlinkSync(folderName + '/strip.png');
  fs.unlinkSync(folderName + '/strip@2x.png');
  fs.unlinkSync(folderName + '/striplogo.png');
}
/////////////Applepass end/////////////////////////////////////

async function generatePassStripGoogleReward(pin, passdir,guid) {

  const { createCanvas, loadImage } = require('canvas')

  const width = 1200 + 48
  const height = 490 - 250

  const canvas = createCanvas(width, height)
  const context = canvas.getContext('2d')

  context.fillStyle = '#ffffff'
  context.fillRect(0, 0, width, height)



  context.textAlign = 'center'
  context.textBaseline = 'top'
  context.font =( (pin.length < 24) ?  '60pt Menlo':'40pt Menlo')
  context.fillStyle = '#0066cc'
  context.fillText(pin, 624, 310-200-40)

  loadImage(templatedir + 'pbe.png').then(image => {
    context.drawImage(image, 920-20, 425-250, 318, 56)
    const buffer = canvas.toBuffer('image/png')
    fs.writeFileSync(passdir + '/' + guid + '_strip.png', buffer)
    fs.writeFileSync(passdir + '/' + guid + '_strip@2x.png', buffer)
  })
}

async function generateGooglePassReward(obj) {
  folderName = basepath + 'static/media/Google/passes';// + obj.id;
  console.log(folderName);
 // fs.mkdirSync(folderName,{recursive: true});
  console.log(obj);

  const response = await fetch(obj.productLogo,{},proxy_url);
    const blob = await response.blob();
    const arrayBuffer = await blob.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(folderName + '/' + obj.id + '_striplogo.png', buffer, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Product Logo saved.');
    })
  
  await generatePassStripGoogleReward(obj.pan, folderName,obj.id);  

}

async function getXMLTagValue(start,end,jsonResponse) {
  let value = '';
  let resp = jsonResponse;
  if(resp.includes(start)){
    let a = resp.split(start);
    let b = a[1].split(end);
    value = b[0];  
  }
  return value;

}

async function getPassesReward(req,jsonResponse,refpass,log_prefix,log_suffix){
      let result = null;
      let pass_tag = '';

      let allowed_google = await getGooglePassAllowed(req.hostname);
      let allowed_apple = await getApplePassAllowed(req.hostname);
      if((allowed_apple == 'yes')||(allowed_google == 'yes')) {
      try {
        const findRemoveSync = require('find-remove');
        const UUID = require('pure-uuid');
        const id = new UUID(4).format();

        let reference= refpass;
        let txndate=(await getXMLTagValue('<LOCALDATETIME>','</LOCALDATETIME>',jsonResponse));
        let pan=(await getXMLTagValue('<PAN>','</PAN>',jsonResponse));
        let expiry= (await getXMLTagValue('<EXPIRY_DATE>','</EXPIRY_DATE>',jsonResponse));
        let serial=(await getXMLTagValue('<SERIAL>','</SERIAL>',jsonResponse));
        let title=(await getXMLTagValue('<ATTRIBUTE NAME="TITLE">','</ATTRIBUTE>',jsonResponse));
        let firstname=(await getXMLTagValue('<ATTRIBUTE NAME="FIRSTNAME">','</ATTRIBUTE>',jsonResponse));
        let lastname=(await getXMLTagValue('<ATTRIBUTE NAME="LASTNAME">','</ATTRIBUTE>',jsonResponse));
        let city=(await getXMLTagValue('<ATTRIBUTE NAME="CITY">','</ATTRIBUTE>',jsonResponse));
        let store=(await getXMLTagValue('<ATTRIBUTE NAME="STORE">','</ATTRIBUTE>',jsonResponse));
        let email=(await getXMLTagValue('<ATTRIBUTE NAME="EMAIL">','</ATTRIBUTE>',jsonResponse));
        let phone=(await getXMLTagValue('<ATTRIBUTE NAME="PHONENUMBER">','</ATTRIBUTE>',jsonResponse));
        let callingCode = (await getXMLTagValue('<ATTRIBUTE NAME="CALLINGCODE">','</ATTRIBUTE>',jsonResponse));
        let a = jsonResponse.split('<BALANCE>');
        let b = a[2].split('</BALANCE>');
        let bal = b[0];
        let currencycode = 'AED';
        let country_code = await getCountryCode(req.hostname);
        if(country_code == 'ZA') {
          currencycode = 'ZAR';
        } else if(country_code == 'TR') {
          currencycode = 'TRY';
        } else if(country_code == 'SA') {
          currencycode = 'SAR';
        }
        let balance = currencycode + ' 0.00';
        if(bal == 0) {
          balance = currencycode + ' 0.00';
        } else if(bal.length == 1) {
          balance = currencycode + ' 0.0' + bal;
        }
        else if(bal.length == 2) {
          balance = currencycode + ' 0.' + bal;
        } else {
          balance = currencycode + ' ' + bal.substring(0,bal.length-2) + '.' + bal.substring(bal.length-2, bal.length) ;
        }


        let objGoogle = [];
        objGoogle.push({
          reference:reference,
          txndate:txndate,
          pan:pan,
          expiry:expiry,
          serial:serial,
          title:title,
          firstname:firstname,
          lastname:lastname,
          city:city,
          store:store,
          amount:balance,
          email:email,
          phone:phone,
          callingCode:callingCode,
          actlink:'https://' + req.hostname,
          providerLogo: 'https://' + req.hostname + '/static/media/logos/epay_pass.png',
          productLogo: 'https://' + req.hostname + '/static/media/logos/epay_pass.png',  
          pin:pan,        
          id:id,
          stripe:''
        });


        console.log(objGoogle);


        
        if(allowed_google == 'yes') { 
 
            
          await generateGooglePassReward(objGoogle[0]);
          objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
          let googlePassUrl = await createPassObjectReward(objGoogle);

          pass_tag = pass_tag + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
          console.log('Response GPass Reward: ' + googlePassUrl);
          setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
        } else {
          pass_tag = pass_tag + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';
        }
          
          
          if(allowed_apple == 'yes')
          {
           await generatePassReward(objGoogle[0]);
           
           
            let encyptBlockTime = getTimeStamp();

            let block =  id + '/' + reference + '.pkpass' + ',' + encyptBlockTime;
            let token = encrypt(block);          

        
            let encyptBlockTimeGMT = new Date();
            let passLink = 'https://' + req.hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();
            pass_tag = pass_tag + '<PASS>' + passLink + '</PASS>';
            setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
           
          }else {
            pass_tag = pass_tag + '<PASS>' + '' + '</PASS>';
          }

          return pass_tag;
         
  
      }
      catch (err)
      {
          console.log(log_prefix + err + log_suffix);
      }
      }
      return result;
}


async function createPassObjectReward(obj) {

  try {
  // TODO: Create a new Generic pass for the user
  let objectSuffix = obj[0].reference;

  console.log(obj);
  
  let objectId = `${issuerId}.${objectSuffix}`;
  console.log(objectId);

  let genericObject = {
    'id':  `${objectId}`,
    'classId': classId,
    'genericType': 'GENERIC_TYPE_UNSPECIFIED',
    'hexBackgroundColor': '#FFFFFF',
    'logo': {
      'sourceUri': {
        'uri': obj[0].providerLogo
      }
    },
    'cardTitle': {
      'defaultValue': {
        'language': 'en',
        'value': obj[0].store
      }
    }, 

    
   'imageModulesData': [
      {
        'mainImage': {
          'sourceUri': {
            'uri':obj[0].stripe
          },
          
        },
        'id': 'event_banner'
      }
    ], 
    
   
    'header': {
      'defaultValue': {
        'language': 'en',
        'value': obj[0].amount
      }
    },
    'subheader': {
      'defaultValue': {
        'language': 'en',
        'value': (obj[0].title + ' ' + obj[0].firstname + ' ' + obj[0].lastname)
      }
    },
    'textModulesData': [
      
      {
        'header': 'Customer',
        'body': (obj[0].title + ' ' + obj[0].firstname + ' ' + obj[0].lastname),
        'id': 'customer'
      },
      {
        'header': 'Phone Number',
        'body': obj[0].phone, 
        'id': 'phone'
      },      
      {
        'header': 'CITY',
        'body': obj[0].city,
        'id': 'city'
      },
           
      {
        'header': 'STORE',
        'body': obj[0].store,
        'id': 'store'
      },
      {
        'header': 'Serial',
        'body': obj[0].serial,
        'id': 'serial'
      },
      {
        'header': 'Purchased On',
        'body': obj[0].txndate, 
        'id': 'txtime'
      },
      {
        'header': 'Expiry',
        'body': obj[0].expiry,
        'id': 'expiry'
      }
    ],
    'barcode': {
      'type': 'QR_CODE',
      'value': obj[0].pan 
    },
    'heroImage': {
      'sourceUri': {
        'uri':obj[0].stripe
      }
    },

    'linksModuleData': {
      'uris': [
        {
          'uri': obj[0].actlink,
          'description': 'Redeem Your Code',
          'id': 'official_site'
        }
      ]
    }
    
    
 
  };
console.log(genericObject);
  // TODO: Create the signed JWT and link
  const claims = {
    iss: credentials.client_email,
    aud: 'google',
    origins: [],
    typ: 'savetowallet',
    payload: {
      genericObjects: [
        genericObject
      ]
    }
  };

 console.log(claims);
  const token = jwt.sign(claims, credentials.private_key, { algorithm: 'RS256' });
  const saveUrl = `https://pay.google.com/gp/v/save/${token}`;
  console.log(saveUrl);
  return saveUrl;
}catch(err) {
  console.log(err);
  return 'exception google pass';
}
 
}

app.post('/getIncentiveUpload', async (req, res) => {

  const clientip = req.headers['incap-client-ip'] ;  
  console.log(req.headers.campaign + '>>API_CALL:getIncentiveUpload => clientip: ' + clientip);

  try {

  let txid = getTimeStamp();


  let strData = Buffer.from(req.body,'base64').toString('utf8');
  console.log(strData);
  let obj = JSON.parse(strData);
  let card_data  = decrypt(obj.loginENC) ;
  let x = card_data.split('<LOGINTIME>');
  let y = x[1].split('</LOGINTIME>');
  let loginTime = y[0];
  let timeout = await getDomainIdleTimeout(req.hostname);

  if(( txid - Number(loginTime)) > Number(timeout) ) {
    let resp = '<RESPONSE><RESULT>1202</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_109',req)+'</RESULTTEXT></RESPONSE>';
    console.log(resp);
    res.send(resp);
    return;
  }
  



  let a = card_data.split('<ATTRIBUTE NAME="PHONENUMBER">');
  let b = a[1].split('</ATTRIBUTE>');
  let phone = b[0];
  phone = phone.substring(phone.length-9,phone.length);

  let ref = (parseInt(txid)).toString(16).toUpperCase();

  let reference = 'EPAY-'+ ref + '-' + phone;

  let session_id = reference;
  let host_log = req.hostname.split('.');
  let method = 'GET_INCENTIVE_DATA_UPLOAD';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';
  console.log(log_prefix + req.headers.campaign + '>>API_CALL:getIncentiveUpload => clientip: ' + clientip + log_suffix);



  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {

          let pathupload = await getPathUploadReward(req);
          if(obj.imageData.length) {
              console.log('Writing image upload file.......');        
              if (!fs.existsSync(pathupload  + phone)) {
                fs.mkdirSync(pathupload  + phone);
              }
              fs.writeFileSync(pathupload + phone + '/' + phone + '-' + obj.cardId + '-' + ref + '.png', obj.imageData.split(",")[1], "base64");            
              console.log(log_prefix + 'Image file written successfully' + log_suffix);
            
          } 
      

          let objTemp = JSON.parse(JSON.stringify(obj));

          delete objTemp['imageData'];
          delete objTemp['fileName'];
          delete objTemp['loginENC'];

          let report = JSON.stringify(objTemp);
          console.log(report);  

          if (!fs.existsSync(pathupload  + phone)) {
            fs.mkdirSync(pathupload  + phone);
          }
          fs.writeFileSync(pathupload + phone + '/' + phone + '-' + obj.cardId + '-' + ref + '.txt', report, "utf8");
          console.log(log_prefix + 'Data file written successfully' + log_suffix);
          let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT><TXID>'+reference+'</TXID></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          res.send(resp);
          return;

      }
      catch (error) {
        console.log(log_prefix + 'Exception in report data generation: ' + JSON.stringify(error) + log_suffix);
        console.log(error);          
        let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
        console.log(log_prefix + resp + log_suffix);
        res.send(resp);    
        return;   
     
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } catch (error) {
    console.log('Exception in report data generation (processing): ' + JSON.stringify(error));
    console.log(error);
    let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
    console.log(resp);
    res.send(resp);
    return;
  }
})


//reward auth
app.get('/getPINCodeReward', cors(corsOptions), limiter, async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPINCodeReward => clientip: ' + clientip);
try {
  let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
  if(isIpTrusted)
  {

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {

      let body_token = Buffer.from(req.query.token,'base64').toString('utf8');
      let token_arr = body_token.split(',');
      let token = token_arr[0];
      let gtid = token_arr[1];


      if(await IsTokenAlreadyInCache(token)) {
        res.send('404');
        return;
      }

       
        
      if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
      {
         gtid = getDefaultTID(req.hostname,req);        
      }
      
      let use_checkout_key = '';
      let use_checkout_url = '';
      let bearer = '';
      let cred = await getCheckoutCredentials(req.hostname,req);
      if(cred)
      {
        use_checkout_key = cred.CheckoutSecretKey;
        use_checkout_url = cred.url;
        bearer = cred.prefix;
      }

      const fetchOptions1 = {
        method: 'GET',
        headers: {
          'Authorization': bearer + use_checkout_key,
          'Content-Type': 'application/json',
        },
      }
      var tokreq = use_checkout_url + '/' + token;
      const responsetok = await fetch(tokreq, fetchOptions1,proxy_url);

      console.log(responsetok);
      console.log(responsetok.status);

      if (responsetok.status != 404) {

        if (responsetok.status == 200) {        

          const jsonResponsetok = await responsetok.json();

         let session_id = jsonResponsetok.reference;
         let host_log = req.hostname.split('.');
         let method = 'GET_PINCODE_REWARD_SALE';
         let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         let log_suffix = '\n</LOG></SESSION_LOG>';         
         console.log(log_prefix + 'GET_PINCODE_SALE SESSION QUERY REQUEST: ' + tokreq + log_suffix);
         console.log(log_prefix + 'GET_PINCODE_SALE SESSION QUERY RESPONSE:' + log_suffix);

         console.log(log_prefix + req.headers.campaign + '>>API_CALL:getPINCodeReward => clientip: ' + clientip + log_suffix);
          
          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);
          console.log(jsonResponsetok.metadata.ean);
          console.log(log_prefix + jsonResponsetok.status + log_suffix);

          let temp_data = jsonResponsetok.metadata.moreInfo;
           let temp_arr = temp_data.split(',');
           let promoApplied_add = temp_arr[0] ? temp_arr[0] : "";
           let discount_add = temp_arr[1] ? temp_arr[1] : "";
           let promoCode_add = temp_arr[2] ? temp_arr[2] : "";
           let ActivationSerial_add = temp_arr[3] ? temp_arr[3] : "";
           let ProductTypeSale_add = temp_arr[4] ? temp_arr[4] : "";
           let CurrencyCodeProduct_add = temp_arr[5] ? temp_arr[5] : "";
           let instore_add = temp_arr[6] ? temp_arr[6] : "";
           let gpay_add = temp_arr[7] ? temp_arr[7] : "";
           let delivery_add = temp_arr[8] ? temp_arr[8] : "";
           let flashVoucher_add = temp_arr[9] ? temp_arr[9] : "none";
           let africanID_add = temp_arr[10] ? temp_arr[10] : "none";
           let cashier_add = temp_arr[11] ? temp_arr[11] : "";


           jsonResponsetok.metadata['promoApplied'] = promoApplied_add;
           jsonResponsetok.metadata['discount'] = discount_add;
           jsonResponsetok.metadata['promoCode'] = promoCode_add;
           jsonResponsetok.metadata['ActivationSerial'] = ActivationSerial_add;
           jsonResponsetok.metadata['ProductTypeSale'] = ProductTypeSale_add;
           jsonResponsetok.metadata['CurrencyCodeProduct'] = CurrencyCodeProduct_add;
           jsonResponsetok.metadata['instore'] = instore_add;
           jsonResponsetok.metadata['gpay'] = gpay_add;
           jsonResponsetok.metadata['delivery'] = delivery_add;
           jsonResponsetok.metadata['flashVoucher'] = flashVoucher_add;
           jsonResponsetok.metadata['africanID'] = africanID_add;
           jsonResponsetok.metadata['cashier'] = cashier_add;

           delete jsonResponsetok.metadata['moreInfo'];

           console.log(log_prefix + JSON.stringify(jsonResponsetok) + log_suffix);

          //---------------------------------

          if (((jsonResponsetok.status == 'Captured')||(jsonResponsetok.status == 'Authorized')||(jsonResponsetok.status == 'Card Verified')) && (jsonResponsetok.approved == true) && (jsonResponsetok.metadata.instore == '0')) {



            let pin_resp = await getPromoPinCode(req,clientip,jsonResponsetok.metadata.tid,jsonResponsetok,null);
            if(!pin_resp.includes('<RESULT>0</RESULT>')) {
              if(Number(jsonResponsetok.metadata.discount) > 0) {
              let promocode = jsonResponsetok.metadata.promoCode;
              let result_refund_promo = await refundPromoDiscount(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.reference, promocode,log_prefix,log_suffix,req);
              console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
            }

            }  else {
              //Update payment status to paymentinfo after sale
              await updatePaymentInfoInstore(jsonResponsetok.metadata.tid,jsonResponsetok.reference,jsonResponsetok.metadata.ean,jsonResponsetok.source.id,jsonResponsetok.source.last4,jsonResponsetok.source.scheme,jsonResponsetok.metadata.phone,jsonResponsetok.metadata.email,req.hostname, log_prefix,log_suffix,req);
 
          }
          
            ///////////////////////////////////////////////////////

            if(pin_resp.includes('<RESULT>0</RESULT>')) {
              let TID = getDefaultTID(req.hostname,req);
              let resp = await getPromoCardStatus(TID,jsonResponsetok.metadata.reference,jsonResponsetok.metadata.promoCode,log_prefix,log_suffix,clientip,req);
              console.log(resp);

              if(resp.includes('<CARD>')) {
                let a = resp.split('<CARD>');
                let b = a[1].split('</CARD>');
                let card_data =  b[0] + '<LOGINTIME>' + getTimeStamp() + '</LOGINTIME>';
                let enc = encrypt(card_data);
                let enctag = '<ENCBLOCK>' + enc + '</ENCBLOCK>';
                resp = resp.replace('</RESPONSE>', enctag + '</RESPONSE>');
              }

              pin_resp = pin_resp + '<CARDBLOCK>' + resp + '</CARDBLOCK>';

             }

             //////////////////////////////////////////////////////            
            console.log(pin_resp);
            res.send(pin_resp);         
          }
          else if (jsonResponsetok.approved == false) {
            if(Number(jsonResponsetok.metadata.discount) > 0) {
              let promocode = jsonResponsetok.metadata.promoCode;
              let result_refund_promo = await refundPromoDiscount(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.reference, promocode,log_prefix,log_suffix,req);
              console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
            }
            console.log(log_prefix + 'notapproved' + log_suffix);
            if(jsonResponsetok.actions.length > 0)
            {
              let errorSharaf = '. '+ getMessageIDText('MESSAGEID_135',req);
                
              let errorText = await getCheckoutErrorResponse(jsonResponsetok,req);
              // jsonResponsetok.actions[0].type + getMessageIDText('MESSAGEID_136',req) + jsonResponsetok.actions[0].response_code + '. ' + jsonResponsetok.actions[0].response_summary + errorSharaf ;
              console.log(log_prefix + errorText + log_suffix);
              res.send('<RESPONSE><RESULT>' + jsonResponsetok.actions[0].response_code + '</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT><EAN>'+jsonResponsetok.metadata.ean+'</EAN><HOME>'+jsonResponsetok.metadata.home+'</HOME></RESPONSE>');
            }
            else{
              let err = await getCheckoutErrorResponse(jsonResponsetok,req);
              if(err.length)
                err = Buffer.from(err).toString('base64');
              res.statusCode = 400;
              console.log(log_prefix + 'notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err + log_suffix);
              res.send('notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err);
            }
            
          }
          else {
            if(Number(jsonResponsetok.metadata.discount) > 0) {
              let promocode = jsonResponsetok.metadata.promoCode;
              let result_refund_promo = await refundPromoDiscount(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.reference, promocode,log_prefix,log_suffix,req);
              console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
            }
            console.log('failed1234');
            res.statusCode = 400;
            console.log(log_prefix + 'failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + log_suffix)
            res.send('failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean);
          }


        }
        else {
 
          console.log('failed2222');
          res.statusCode = 400;
          res.send(responsetok.status);
        }

      }
      else {

        console.log('404 error');
        res.statusCode = 404;
        res.send('404');
      }
    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

}
else
{  
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_111',req)+'</RESULTTEXT></RESPONSE>');
}
} catch(err) {
  console.log(err);
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>')
}

});

app.get('/getOTPReward', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;  
  console.log(req.headers.campaign + '>>API_CALL:getOTPReward => clientip: ' + clientip);
 
  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        console.log(req.headers);
        console.log('req.headers.host ==>> ' + req.headers.host);
 
        let strData = Buffer.from(req.query.body,'base64').toString('utf8');
        console.log(strData);
        if(req.query.mode == 'resend') {
          strData = decrypt(strData);
        }
        let obj = JSON.parse(strData);


        let TID = getDefaultTID(req.hostname,req); 
        let phone = obj.phone; 
        let txid = getTimeStamp();
        let reference = 'EPAY-'+ TID + (parseInt(txid)).toString(16).toUpperCase() + '-' + phone.substring(phone.length-9,phone.length);

        if(req.query.mode == 'resend') {
          reference = obj.reference;
        }

        let session_id = reference;
        let host_log = req.hostname.split('.');
        let api = 'SEND_OTP_REWARD';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ api +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';

        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getOTPReward => clientip: ' + clientip + log_suffix);

        if(req.query.mode == 'login') {
          let phone_str = obj.phone.substring(obj.phone.length-9,obj.phone.length);
          let jsonResponse = await getPromoCardStatus('tidhead',reference,obj.cardid,log_prefix,log_suffix,clientip,req);
          console.log(log_prefix + jsonResponse + log_suffix);
          if((!jsonResponse.includes('<RESULT>0</RESULT>'))||(!jsonResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))
            ||(!jsonResponse.includes('<ATTRIBUTE NAME="PHONENUMBER">0'+ phone_str +'</ATTRIBUTE>'))) {
             
             let resp = '<RESPONSE><RESULT>1200</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_112',req)+'</RESULTTEXT></RESPONSE>';;
             if(!jsonResponse.includes('<RESULT>0</RESULT>')){
              let a = jsonResponse.split('<RESULTTEXT>');
              let b = a[1].split('</RESULTTEXT>');
              resp = '<RESPONSE><RESULT>1201</RESULT><RESULTTEXT>' + b[0] + '</RESULTTEXT></RESPONSE>';
             
             }else if(!jsonResponse.includes('<ATTRIBUTE NAME="PHONENUMBER">0'+ phone_str +'</ATTRIBUTE>')){
               resp = '<RESPONSE><RESULT>1202</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_113',req)+'</RESULTTEXT></RESPONSE>';
           
             } else if(!jsonResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')) {
               resp = '<RESPONSE><RESULT>1203</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_114',req)+'</RESULTTEXT></RESPONSE>';
              
             }
             console.log(log_prefix + resp + log_suffix);
             res.send(resp);
             return;
          }
        }
        
        obj['reference'] = reference;
        obj['time'] = getTimeStamp();
        obj['mode'] = req.query.mode;
        

      

        var x = Math.floor(100000 + Math.random() * 900000);
        var y = x.toString().split('.');
        var otp = y[0];

         //TEST FIX OTP
         if(clientip == TEST_IP_AZURE)
          otp='123456';
    

        const hashValue = crypto.createHash('sha256', secret).update(otp).digest('hex');
        console.log("Hash Obtained is: ", hashValue);

        obj['otpHash'] = hashValue;

        let timestamp = getTimeStamp();
        console.log(timestamp);

        let host_name = await getCustomerName(req.hostname);
        let infoBipCred = await getDomainInfoBipCredential(req);
  
       // var infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infobip_msg_sender+ '","text":"Hi, your One Time Password is '+otp+' and will expire in 5 min. Do not share this with anyone. Don'+"'"+'t recognize this activity? Please call Customer Care.'+'"'+'}]}';
       var infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infoBipCred.infobip_msg_senderinfobip_msg_sender+ '","text":"Hi, your One Time Password is '+otp+' and will expire in 5 min. Do not share this with anyone. Don'+"'"+'t recognize this activity? Please call '+ host_name + getMessageIDText('MESSAGEID_154',req) +'"'+'}]}'; 
        mask_json_data(infobip_smsbody,log_prefix,log_suffix);
        //console.log(infobip_smsbody);
       
        
        const fetchOptions = {
          method: 'POST',

          body: infobip_smsbody,

          headers: {
            'Authorization': 'App ' + infoBipCred.infobipAuth,  
            'Content-Type': 'application/json',
          },
          
        }

        let infobipSMSURL = infoBipCred.infobipURL;  
        console.log(log_prefix + 'Request JSON to infobip server:' + infobipSMSURL + log_suffix);
        var smsTimeout = setTimeout(() => res.send('apiTimeout'), 30000);
        try {
           const response = await fetch(infobipSMSURL, fetchOptions,proxy_url);
           console.log(response.status);
          let jsonResponse = await response.json();
         // let jsonResponse = JSON.parse('{"messages":[{"messageId":"4071313962514335686996","status":{"description":"Message sent to next instance","groupId":1,"groupName":"PENDING","id":26,"name":"PENDING_ACCEPTED"},"to":"971*******11"}]}')
          console.log(log_prefix + 'Response JSON from infobip server:' + log_suffix);
          mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix);


          clearTimeout(smsTimeout);
 
          
          if(response.status == 200)
          {
            console.log(jsonResponse.messages[0].status.name) ; 
          if (jsonResponse.messages[0].status.name == 'PENDING_ACCEPTED') {
       
            var txnData = encrypt(JSON.stringify(obj));
            let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>Success</RESULTTEXT><JSONOBJ>' + txnData + '</JSONOBJ></RESPONSE>';
            console.log(log_prefix + resp + log_suffix);
            res.send(resp);
          }
          else {
            console.log(log_prefix + 'otpFailed not accpted' + log_suffix);
            let resp = '<RESPONSE><RESULT>1033</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_115',req)+'</RESULTTEXT></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          res.send(resp);

    
          }
        }
        else{
          console.log(log_prefix + 'otpFailed response code' + response.status  + log_suffix);
          let resp = '<RESPONSE><RESULT>1032</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_115',req)+'</RESULTTEXT></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          res.send(resp);
   
        }

          
        }
        catch (error) {
          console.log(error);
          clearTimeout(smsTimeout);
          console.log(log_prefix + 'exception' + log_suffix);          
          let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          res.send(resp);          
          return;
        }

 

      } catch (error) {
        console.log(error);
        clearTimeout(smsTimeout); 
        console.log(log_prefix + 'exception 2' + log_suffix);   
        let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          res.send(resp);         

       
     
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});

async function sendPromoterCardSuccessMessage_ib(cardid,phone,log_prefix,log_suffix)
{

//   Welcome! Your new Card ID is [Card ID number]. 
// Login now to your account at promoter.epayworldwide.ae and enjoy lots of Rewards.
  
  let smsBody = 'Welcome! Your new Card ID is ' + cardid  + '. Login now to your account at promoter.epayworldwide.ae and enjoy lots of Rewards.';
  let infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infobip_msg_sender+ '","text":"' + smsBody + '"}]}';
    
  
      

    mask_json_data(infobip_smsbody,log_prefix,log_suffix);
    const fetchOptions = {
      method: 'POST',

      body: infobip_smsbody,

      headers: {
        'Authorization': 'App ' + infobipAuth,  
        'Content-Type': 'application/json',
      },
      
    }

    let infobipSMSURL = infobipURL;  

    var smsTimeout = setTimeout(() => console.log('SMS send time out'), 30000);
    try {
      console.log(log_prefix + 'Infobip SMS Request:' + infobipSMSURL + log_suffix);
      const response = await fetch(infobipSMSURL, fetchOptions,proxy_url);
      console.log(response.status);
      let jsonResponse = await response.json();
      
      clearTimeout(smsTimeout);
      mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix); 
    } catch(error) {
      console.log(error);
    }

}


app.get('/getOTPVerifyReward', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;  
  console.log(req.headers.campaign + '>>API_CALL:sendSMS_ib => clientip: ' + clientip);
 
  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
       try {
        console.log(req.headers);
        console.log('req.headers.host ==>> ' + req.headers.host); 
      
        let strData = Buffer.from(req.query.body,'base64').toString('utf8');
        console.log(strData);
        let obj = JSON.parse(strData);

        let otpUser = obj.otp;

        let currentTimeStamp = getTimeStamp();
        let data = decrypt(obj.encBlock);

        let txndata = JSON.parse(data);
        console.log(txndata);

        let session_id = txndata.reference;
        let host_log = req.hostname.split('.');
        let api = 'VERIFY_OTP_REWARD';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ api +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';

        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getOTPVerifyReward => clientip: ' + clientip + log_suffix);
        

        let mode = obj.mode;
        const hashValueUser = crypto.createHash('sha256', secret).update(otpUser).digest('hex');
        if (Number(await date_difference(currentTimeStamp,txndata.time)) > 300) {
          let resp = '<RESPONSE><RESULT>1001</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_116',req)+'</RESULTTEXT></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          res.send(resp);
          return;
        }
        else {
          console.log(otpUser);
         
          if(hashValueUser != txndata.otpHash){
            let resp = '<RESPONSE><RESULT>1002</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_117',req)+'</RESULTTEXT></RESPONSE>';
            console.log(log_prefix + resp + log_suffix);
            res.send(resp);
            return;
          }
        }
        

        if((mode == 'login')&&(hashValueUser == txndata.otpHash)){
          let TID = getDefaultTID(req.hostname,req);
          let resp = await getPromoCardStatus(TID,txndata.reference,txndata.cardid,log_prefix,log_suffix,clientip,req);
          
          if(resp.includes('<CARD>')) {
            let a = resp.split('<CARD>');
            let b = a[1].split('</CARD>');
            let card_data =  b[0] + '<LOGINTIME>' + getTimeStamp() + '</LOGINTIME>';
            let enc = encrypt(card_data);
            let enctag = '<ENCBLOCK>' + enc + '</ENCBLOCK>';
            resp = resp.replace('</RESPONSE>', enctag + '</RESPONSE>');
          }

          let resp_log = resp ;
          resp_log = resp_log.replace(/\r?\n|\r/g, " ");
          console.log(log_prefix + 'Login CARDSTATUS Response: ' + resp_log  + log_suffix); 

          console.log(resp);
          res.send(resp);
          return;
        } else if(mode == 'signup') {
           let TID = getDefaultTID(req.hostname,req);
          let result = await getPaySerial(TID,txndata.reference,'0', log_prefix,log_suffix,req.hostname,clientip,'',req,txndata);
          if(TEST_IP_AZURE == clientip) {
            result = '<RESPONSE><RESULT>0</RESULT><PAN>9712905041699683620</PAN><PANCARD>9712905041699683620</PANCARD></RESPONSE>';
          }
          let resp_log = result ;
          resp_log = resp_log.replace(/\r?\n|\r/g, " ");
          console.log(log_prefix + 'Signup CARD Activation Response: ' + resp_log  + log_suffix);

          console.log(result);
          if(result.includes('<RESULT>0</RESULT>')){
            let p = result.split('<PANCARD>');
            let p1 = p[1].split('</PANCARD>');
            let pan = p1[0];
            let resp = await getPromoCardStatus(TID,txndata.reference,pan,log_prefix,log_suffix,clientip,req);
            console.log(resp);
            if(resp.includes('<RESULT>0</RESULT>')) {
              let gwp = await getPassesReward(req,resp,txndata.reference,log_prefix,log_suffix);
              resp = resp.replace('</RESPONSE>', gwp + '</RESPONSE>' );
              await sendPromoterCardSuccessMessage_ib(pan,txndata.phone,log_prefix,log_suffix);
            }
            let resp_log = resp ;
            resp_log = resp_log.replace(/\r?\n|\r/g, " ");
            console.log(log_prefix + 'Sign up SUCCESS Response: ' + resp_log  + log_suffix);

            res.send(resp);
            return;
          }
          
          res.send(result);
          return;
        }

      } catch (error) {
        console.log(error);  
        let resp = '<RESPONSE><RESULT>1003</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
        console.log(resp);
        res.send(resp);
        return;     
       
     
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});
///////////////////////////////REWARD////////////////////////////////////////

//===================================================//

app.get('/getPINCodeFlash', cors(corsOptions),async(req,res)=> {
    
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPINCodeFlash => clientip: ' + clientip);


  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {

      try {
      let body_token = Buffer.from(req.query.token,'base64').toString('utf8');
      let token_arr = body_token.split(',');
      let token = token_arr[0];
      let gtid = token_arr[1];
           

      if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
      {
          gtid = getDefaultTID(req.hostname,req);        
      }
      let tid_used = gtid;
      let use_checkout_key = '';
      let use_checkout_url = '';
      let bearer = '';
      let cred = await getCheckoutCredentials(req.hostname,req);
      if(cred)
      {
        use_checkout_key = cred.CheckoutSecretKey;
        use_checkout_url = cred.url;
        bearer = cred.prefix;
      }
      
      const fetchOptions1 = {
        method: 'GET',
        headers: {
          'Authorization': bearer + use_checkout_key,
          'Content-Type': 'application/json',
        },
      }
      var tokreq = use_checkout_url + '/' + token;
      const responsetok = await fetch(tokreq, fetchOptions1,proxy_url);

      console.log(responsetok);
      console.log(responsetok.status);

      if (responsetok.status != 404) {

        if (responsetok.status == 200) {

          const jsonResponsetok = await responsetok.json();
   
          console.log(jsonResponsetok.metadata.ean);
          console.log(jsonResponsetok.status);
          //-----------------------------------

          let session_id = jsonResponsetok.reference;
          let host_log = req.hostname.split('.');
          let method = 'GET_PIN_CODE_FLASH';
          let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
          let log_suffix = '\n</LOG></SESSION_LOG>';

          console.log(log_prefix + req.headers.campaign + '>>API_CALL:getAuthSerialStatus => clientip: ' + clientip + log_suffix);

          console.log(log_prefix + 'Session Query on Checkout: ' + tokreq + log_suffix);

          console.log(log_prefix + 'RESPONSE To Session Query on Checkout:' + log_suffix);
          

          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);

          if(jsonResponsetok.metadata.moreInfo) {

            let temp_data = jsonResponsetok.metadata.moreInfo;
            let temp_arr = temp_data.split(',');
            let promoApplied_add = temp_arr[0] ? temp_arr[0] : "";
            let discount_add = temp_arr[1] ? temp_arr[1] : "";
            let promoCode_add = temp_arr[2] ? temp_arr[2] : "";
            let ActivationSerial_add = temp_arr[3] ? temp_arr[3] : "";
            let ProductTypeSale_add = temp_arr[4] ? temp_arr[4] : "";
            let CurrencyCodeProduct_add = temp_arr[5] ? temp_arr[5] : "";
            let instore_add = temp_arr[6] ? temp_arr[6] : "";
            let gpay_add = temp_arr[7] ? temp_arr[7] : "";
            let delivery_add = temp_arr[8] ? temp_arr[8] : "";
            let flashVoucher_add = temp_arr[9] ? temp_arr[9] : "none";
            let africanID_add = temp_arr[10] ? temp_arr[10] : "none";
            let cashier_add = temp_arr[11] ? temp_arr[11] : "";

            jsonResponsetok.metadata['promoApplied'] = promoApplied_add;
            jsonResponsetok.metadata['discount'] = discount_add;
            jsonResponsetok.metadata['promoCode'] = promoCode_add;
            jsonResponsetok.metadata['ActivationSerial'] = ActivationSerial_add;
            jsonResponsetok.metadata['ProductTypeSale'] = ProductTypeSale_add;
            jsonResponsetok.metadata['CurrencyCodeProduct'] = CurrencyCodeProduct_add;
            jsonResponsetok.metadata['instore'] = instore_add;
            jsonResponsetok.metadata['gpay'] = gpay_add;
            jsonResponsetok.metadata['delivery'] = delivery_add;
            jsonResponsetok.metadata['flashVoucher'] = flashVoucher_add;
            jsonResponsetok.metadata['africanID'] = africanID_add;
            jsonResponsetok.metadata['cashier'] = cashier_add;
            

            delete jsonResponsetok.metadata['moreInfo'];

          }

          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);

          ///////// Additional Security check for promo discount /////////////////
          
          let promoConfigValue =  await getPaymentMethods(req.hostname);
          let promoEnabled = 'no';
          if(promoConfigValue.includes('redeem')) {
            promoEnabled = 'yes';
          }
          let obj = JSON.parse(JSON.stringify(jsonResponsetok));
          if(Number(obj.metadata.discount)>0) {
            try{
              jsonResponsetok.metadata.promoApplied = '1';
              let tidhead = '<TERMINALID>' + obj.metadata.tid + '</TERMINALID>' ;
              let txid = obj.reference;
              if((obj.metadata.promoCode) && (obj.metadata.promoCode != 'none')&&(redeem_option == '1')&&(promoEnabled == 'yes')) {                
                  let cardStatusResponse = await getPromoCardStatus(tidhead,txid + '_D',obj.metadata.promoCode,log_prefix,log_suffix,clientip,req);
                  if(((cardStatusResponse.includes('<RESULT>0</RESULT>'))&&(cardStatusResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')))&&(cardStatusResponse.includes('<BALANCE>'))&&(!cardStatusResponse.includes('<ATTRIBUTE NAME="PROXY'))) {
                    let a1 = cardStatusResponse.split('<BALANCE>');
                    let a2 = a1[2].split('</BALANCE>');
                    let balance= a2[0];
                    console.log('promo balance while get pay serial check: ' + balance); 
                    if(Number(balance) >= Number(obj.metadata.discount))  {
                      console.log(log_prefix +'Promo code balance: ' + balance + ' | Discount from client: ' + obj.metadata.discount + log_suffix);
                      console.log(log_prefix +'Promo code check passed' + log_suffix);
                      jsonResponsetok.metadata.promoApplied = '1';
                    } else {
                      
                        console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
                        let resp = '<RESPONSE><RESULT>155</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
                        console.log(log_prefix +resp+ log_suffix);
                        let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_PAYMENT_SERIAL balance insufficient'
                        console.log(log_prefix + alert + log_suffix);
                        if(BlockedIPs) {
                          BlockedIPs = BlockedIPs + ',' + clientip;
                        }else {
                          BlockedIPs = clientip;
                        }
                        res.send(resp);
                        return;
                      }               
                  } else {
                    
                    console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
                    let resp = '<RESPONSE><RESULT>156</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
                    console.log(log_prefix +resp+ log_suffix);
                    let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_PAYMENT_SERIAL CARDSTATUS is not valid'
                    console.log(log_prefix + alert + log_suffix);
                    if(BlockedIPs) {
                      BlockedIPs = BlockedIPs + ',' + clientip;
                    }else {
                      BlockedIPs = clientip;
                    }
                    res.send(resp);
                    return;
                  }
            } else {
              
              console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
              let resp = '<RESPONSE><RESULT>157</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
              console.log(log_prefix +resp+ log_suffix);
              let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_PAYMENT_SERIAL promo info is not valid'
              console.log(log_prefix + alert + log_suffix);
              if(BlockedIPs) {
                BlockedIPs = BlockedIPs + ',' + clientip;
              }else {
                BlockedIPs = clientip;
              }
              res.send(resp);
              return;
            }

          }catch(err) {
            console.log(log_prefix +'Discount security check exception get auth serial'+ log_suffix);
            console.log(log_prefix +JSON.stringify(err)+ log_suffix);
            let resp = '<RESPONSE><RESULT>158</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>'
            console.log(log_prefix +resp+ log_suffix);
            res.send(resp);
            return;
          }
          }
    
          /////////////////////////////////////////////////////////////////////////

          //---------------------------------
          let amount_product = await getAmountEAN(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.ean,log_prefix,log_suffix,req.hostname,clientip,req);
          console.log(log_prefix + 'EAN (' + jsonResponsetok.metadata.ean + ')::Product Amount: ' + amount_product + log_suffix);
          if ((jsonResponsetok.status == 'Card Verified') && (jsonResponsetok.approved == true)) {


            if((jsonResponsetok.metadata.promoApplied == '1')&&(jsonResponsetok.metadata.discount != '0')&&(jsonResponsetok.metadata.promoCode.length > 0))
            {
              
              let result = await chargePromoCode(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.promoCode,jsonResponsetok.metadata.discount,jsonResponsetok.metadata.reference,log_prefix,log_suffix,amount_product,req.hostname,clientip,req);
              console.log(log_prefix + result + log_suffix); 
              if(result != 'Success')
              {
                res.send(result);
                return;
              }
            } 
            else if(jsonResponsetok.metadata.promoApplied == '1')
            {
	           let home_ean_tag = '<HOME>' + 'https://' + req.hostname + '</HOME>' + '<EAN>' + (jsonResponsetok.metadata.ean ? jsonResponsetok.metadata.ean : '') + '</EAN>' ;
              let resp = '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_119',req)+'</RESULTTEXT>'+home_ean_tag+'</RESPONSE>';
              
              console.log(log_prefix + resp + log_suffix); 
              res.send(resp);
              return;
            }

            ///////////////////////////////////

            if(obj.metadata.flashVoucher) {
              let payment_methods = await getPaymentMethods(req.hostname);
              if((obj.metadata.flashVoucher.length > 0)&&(obj.metadata.flashVoucher != 'none')&&(payment_methods.includes('akani'))) {
                  let result_akani_payment = await processAkaniPayment(obj,req,clientip,log_prefix,log_suffix);
                  if(result_akani_payment.responseCode == 0) {

                    let pin_resp = await getPromoPinCode(req,clientip,tid_used,obj,result_akani_payment);
                    if(!pin_resp.includes('<RESULT>0</RESULT>')) {
                      if(Number(obj.metadata.discount) > 0) {
                        let promocode = obj.metadata.promoCode;
                        let result_refund_promo = await refundPromoDiscount(tid_used,obj.metadata.reference, promocode,log_prefix,log_suffix,req);
                        console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                      }

                      let result_akani = await processRefundAkaniVoucher(result_akani_payment,obj,req,clientip,log_prefix,log_suffix);
                      console.log(log_prefix + 'result_refund_akani_voucher: ' + log_suffix);
                      console.log(result_akani);

                    } else {
                        //Update payment status to paymentinfo after sale
                        await updatePaymentInfoInstore(jsonResponsetok.metadata.tid,jsonResponsetok.reference,jsonResponsetok.metadata.ean,jsonResponsetok.source.id,jsonResponsetok.source.last4,jsonResponsetok.source.scheme,jsonResponsetok.metadata.phone,jsonResponsetok.metadata.email,req.hostname, log_prefix,log_suffix,req);
           
                    }
                                   
                    //console.log(log_prefix + pin_resp + log_suffix);
                    res.send(pin_resp);
                    return;

                  } else {
                    if(Number(obj.metadata.discount) > 0) {
                      let promocode = obj.metadata.promoCode;
                      let result_refund_promo = await refundPromoDiscount(tid_used,obj.metadata.reference, promocode,log_prefix,log_suffix,req);
                      console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                    }
                                
                    let result_akani = '<RESPONSE>' + '<RESULT>' + result_akani_payment.responseCode + '</RESULT>' + '<RESULTTEXT>' + result_akani_payment.responseMessage + '</RESULTTEXT>' + '</RESPONSE>'
                    console.log(log_prefix + result_akani + log_suffix);
                    res.send(result_akani);
                    return;
                  }
              } else if((obj.metadata.flashVoucher.length > 0)&&(obj.metadata.flashVoucher != 'none')&&(!payment_methods.includes('akani'))) {
                  // block ip
                  let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_SALE Akani Payment method not enabled'
                  console.log(log_prefix + alert + log_suffix);
                  if(BlockedIPs) {
                    BlockedIPs = BlockedIPs + ',' + clientip;
                  }else {
                    BlockedIPs = clientip;
                  }
                  let home_ean_tag = '<HOME>' + 'https://' + req.hostname + '</HOME>' + '<EAN>' + (jsonResponsetok.metadata.ean ? jsonResponsetok.metadata.ean : '') + '</EAN>' ;
                  let err = '<RESPONSE><RESULT>177</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>'+home_ean_tag+'</RESPONSE>';
                  
                  console.log(log_prefix + err + log_suffix);
                
                  res.send(err);
                  return;
              } else {
                let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
                console.log(log_prefix + resp + log_suffix); 
                res.send(resp);
              }
            } else {
              let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
              console.log(log_prefix + resp + log_suffix); 
              res.send(resp);
            }
            
    

          }
          else {
            let home_ean_tag = '<HOME>' + 'https://' + req.hostname + '</HOME>' + '<EAN>' + (jsonResponsetok.metadata.ean ? jsonResponsetok.metadata.ean : '') + '</EAN>' ;
            let resp = '<RESPONSE><RESULT>17</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_120',req)+'</RESULTTEXT>'+home_ean_tag+'</RESPONSE>';
            console.log(log_prefix + resp + log_suffix); 
            res.send(resp);
          }
      
         } else {      
              let resp = '<RESPONSE><RESULT>'+responsetok.status+'</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_120',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
              console.log(resp);
              res.send(resp);
            }
        

      } else {      
         let resp = '<RESPONSE><RESULT>'+responsetok.status+'</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_121',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
         console.log(resp); 
         res.send(resp);
      }
    } catch (error) {
        console.log('exception in payment flash auth staus::' + error); 
        let resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
        console.log(resp); 
        res.send(resp)
      }
    
    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

  
});

app.get('/getAuthSerialStatus', cors(corsOptions),async(req,res)=> {
    
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getAuthSerialStatus => clientip: ' + clientip);


  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
        try {
          let body_token = Buffer.from(req.query.token,'base64').toString('utf8');
      let token_arr = body_token.split(',');
      let token = token_arr[0];
      let gtid = token_arr[1];
             

      if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
      {
          gtid = getDefaultTID(req.hostname,req);        
      }

     
      let use_checkout_key = '';
      let use_checkout_url = '';
      let bearer = '';
      let cred = await getCheckoutCredentials(req.hostname,req);
      if(cred)
      {
        use_checkout_key = cred.CheckoutSecretKey;
        use_checkout_url = cred.url;
        bearer = cred.prefix;
      }
      
      const fetchOptions1 = {
        method: 'GET',
        headers: {
          'Authorization': bearer + use_checkout_key,
          'Content-Type': 'application/json',
        },
      }
      var tokreq = use_checkout_url + '/' + token;
      const responsetok = await fetch(tokreq, fetchOptions1,proxy_url);

      console.log(responsetok);
      console.log(responsetok.status);

      if (responsetok.status != 404) {

        if (responsetok.status == 200) {

          const jsonResponsetok = await responsetok.json();
   
          console.log(jsonResponsetok.metadata.ean);
          console.log(jsonResponsetok.status);
          //-----------------------------------

          let session_id = jsonResponsetok.reference;
          let host_log = req.hostname.split('.');
          let method = 'SAVE_CARD_SERIAL_STATUS';
          let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
          let log_suffix = '\n</LOG></SESSION_LOG>';

          console.log(log_prefix + req.headers.campaign + '>>API_CALL:getAuthSerialStatus => clientip: ' + clientip + log_suffix);

          console.log(log_prefix + 'Session Query on Checkout: ' + tokreq + log_suffix);

          console.log(log_prefix + 'RESPONSE To Session Query on Checkout:' + log_suffix);
          

          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);

          if(jsonResponsetok.metadata.moreInfo) {

            let temp_data = jsonResponsetok.metadata.moreInfo;
            let temp_arr = temp_data.split(',');
            let promoApplied_add = temp_arr[0] ? temp_arr[0] : "";
            let discount_add = temp_arr[1] ? temp_arr[1] : "";
            let promoCode_add = temp_arr[2] ? temp_arr[2] : "";
            let ActivationSerial_add = temp_arr[3] ? temp_arr[3] : "";
            let ProductTypeSale_add = temp_arr[4] ? temp_arr[4] : "";
            let CurrencyCodeProduct_add = temp_arr[5] ? temp_arr[5] : "";
            let instore_add = temp_arr[6] ? temp_arr[6] : "";
            let gpay_add = temp_arr[7] ? temp_arr[7] : "";
            let delivery_add = temp_arr[8] ? temp_arr[8] : "";
            let flashVoucher_add = temp_arr[9] ? temp_arr[9] : "none";
            let africanID_add = temp_arr[10] ? temp_arr[10] : "none";
            let cashier_add = temp_arr[11] ? temp_arr[11] : "";

            jsonResponsetok.metadata['promoApplied'] = promoApplied_add;
            jsonResponsetok.metadata['discount'] = discount_add;
            jsonResponsetok.metadata['promoCode'] = promoCode_add;
            jsonResponsetok.metadata['ActivationSerial'] = ActivationSerial_add;
            jsonResponsetok.metadata['ProductTypeSale'] = ProductTypeSale_add;
            jsonResponsetok.metadata['CurrencyCodeProduct'] = CurrencyCodeProduct_add;
            jsonResponsetok.metadata['instore'] = instore_add;
            jsonResponsetok.metadata['gpay'] = gpay_add;
            jsonResponsetok.metadata['delivery'] = delivery_add;
            jsonResponsetok.metadata['flashVoucher'] = flashVoucher_add;
            jsonResponsetok.metadata['africanID'] = africanID_add;
            jsonResponsetok.metadata['cashier'] = cashier_add;

            delete jsonResponsetok.metadata['moreInfo'];

          }

          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);


          ///////// Additional Security check for promo discount /////////////////
          
          let promoConfigValue =  await getPaymentMethods(req.hostname);
          let promoEnabled = 'no';
          if(promoConfigValue.includes('redeem')) {
            promoEnabled = 'yes';
          }
          let obj = JSON.parse(JSON.stringify(jsonResponsetok));
          if(Number(obj.metadata.discount)>0) {
            try{
              jsonResponsetok.metadata.promoApplied = '1';
              let tidhead = '<TERMINALID>' + obj.metadata.tid + '</TERMINALID>' ;
              let txid = obj.reference;
              if((obj.metadata.promoCode) && (obj.metadata.promoCode != 'none')&&(redeem_option == '1')&&(promoEnabled == 'yes')) {                
                  let cardStatusResponse = await getPromoCardStatus(tidhead,txid + '_D',obj.metadata.promoCode,log_prefix,log_suffix,clientip,req);
                  if(((cardStatusResponse.includes('<RESULT>0</RESULT>'))&&(cardStatusResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')))&&(cardStatusResponse.includes('<BALANCE>'))&&(!cardStatusResponse.includes('<ATTRIBUTE NAME="PROXY'))) {
                    let a1 = cardStatusResponse.split('<BALANCE>');
                    let a2 = a1[2].split('</BALANCE>');
                    let balance= a2[0];
                    console.log('promo balance while get pay serial check: ' + balance); 
                    if(Number(balance) >= Number(obj.metadata.discount))  {
                      console.log(log_prefix +'Promo code balance: ' + balance + ' | Discount from client: ' + obj.metadata.discount + log_suffix);
                      console.log(log_prefix +'Promo code check passed' + log_suffix);
                      jsonResponsetok.metadata.promoApplied = '1';
                    } else {
                      
                        console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
                        let resp = '<RESPONSE><RESULT>155</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
                        console.log(log_prefix +resp+ log_suffix);
                        let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_PAYMENT_SERIAL balance insufficient'
                        console.log(log_prefix + alert + log_suffix);
                        if(BlockedIPs) {
                          BlockedIPs = BlockedIPs + ',' + clientip;
                        }else {
                          BlockedIPs = clientip;
                        }
                        res.send(resp);
                        return;
                      }               
                  } else {
                    
                    console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
                    let resp = '<RESPONSE><RESULT>156</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
                    console.log(log_prefix +resp+ log_suffix);
                    let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_PAYMENT_SERIAL CARDSTATUS is not valid'
                    console.log(log_prefix + alert + log_suffix);
                    if(BlockedIPs) {
                      BlockedIPs = BlockedIPs + ',' + clientip;
                    }else {
                      BlockedIPs = clientip;
                    }
                    res.send(resp);
                    return;
                  }
            } else {
              
              console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
              let resp = '<RESPONSE><RESULT>157</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
              console.log(log_prefix +resp+ log_suffix);
              let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_PAYMENT_SERIAL promo info is not valid'
              console.log(log_prefix + alert + log_suffix);
              if(BlockedIPs) {
                BlockedIPs = BlockedIPs + ',' + clientip;
              }else {
                BlockedIPs = clientip;
              }
              res.send(resp);
              return;
            }

          }catch(err) {
            console.log(log_prefix +'Discount security check exception get auth serial'+ log_suffix);
            console.log(log_prefix +JSON.stringify(err)+ log_suffix);
            let resp = '<RESPONSE><RESULT>158</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>'
            console.log(log_prefix +resp+ log_suffix);
            res.send(resp);
            return;
          }
          }
    
          /////////////////////////////////////////////////////////////////////////

          //---------------------------------
          let amount_product = await getAmountEAN(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.ean,log_prefix,log_suffix,req.hostname,clientip,req);
          console.log(log_prefix + 'EAN (' + jsonResponsetok.metadata.ean + ')::Product Amount: ' + amount_product + log_suffix);
          if ((jsonResponsetok.status == 'Card Verified') && (jsonResponsetok.approved == true)) {


            if((jsonResponsetok.metadata.promoApplied == '1')&&(jsonResponsetok.metadata.discount != '0')&&(jsonResponsetok.metadata.promoCode.length > 0))
            {
              
              let result = await chargePromoCode(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.promoCode,jsonResponsetok.metadata.discount,jsonResponsetok.metadata.reference,log_prefix,log_suffix,amount_product,req.hostname,clientip,req);
              console.log(log_prefix + result + log_suffix); 
              if(result != 'Success')
              {
                res.send(result);
                return;
              }
            } 
            else if(jsonResponsetok.metadata.promoApplied == '1')
            {
	      let home_ean_tag = '<HOME>' + 'https://' + req.hostname + '</HOME>' + '<EAN>' + (jsonResponsetok.metadata.ean ? jsonResponsetok.metadata.ean : '') + '</EAN>' ;
              let resp = '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_119',req)+'</RESULTTEXT>'+home_ean_tag+'</RESPONSE>';
              
              //let resp = '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_119',req)+'</RESULTTEXT></RESPONSE>';
              console.log(log_prefix + resp + log_suffix); 
              res.send(resp);
              return;
            }


            let resp = await getPaySerial(jsonResponsetok.metadata.tid,jsonResponsetok.reference,jsonResponsetok.metadata.partialPay,log_prefix,log_suffix,req.hostname,clientip,jsonResponsetok.metadata.ean,req);
            console.log(log_prefix + resp + log_suffix); 
            if((resp.includes('<RESULT>0</RESULT>'))||(resp.includes('<RESULT>1012</RESULT>')))
            {
              if(resp.includes('<RESULT>1012</RESULT>')) {
              await updatePaymentInfoInstore(jsonResponsetok.metadata.tid,jsonResponsetok.reference,jsonResponsetok.metadata.ean,jsonResponsetok.source.id,jsonResponsetok.source.last4,jsonResponsetok.source.scheme,jsonResponsetok.metadata.phone,jsonResponsetok.metadata.email,req.hostname, log_prefix,log_suffix,req);
                } 
              // Add code to generate encypted info for promo payment, ean and serial for validation and append to response
              let a1 = resp.split('<PAN>');
              let a2 = a1[1].split('</PAN>');
              let payment_serial = a2[0];
              // let block = amount_product + ',' + payment_serial + ',' + obj.ean + ',' + obj.promoCode + ',' + obj.discountApplied + ',' + obj.reference + ',' + obj.promoApplied;
              let block = amount_product + ',' + payment_serial + ',' + jsonResponsetok.metadata.ean + ',' + jsonResponsetok.metadata.promoCode + ',' + jsonResponsetok.metadata.discount + ',' + jsonResponsetok.metadata.reference + ',' + jsonResponsetok.metadata.promoApplied;
              let token = encrypt(block);
              let add_tag_enc = '<ENCBLOCK>' + token + '</ENCBLOCK>' ;
              resp = resp.replace('</RESPONSE>', add_tag_enc + '</RESPONSE>');

              block = jsonResponsetok.source.id + ',' + jsonResponsetok.source.last4 + ',' +  jsonResponsetok.source.scheme + ','+
              jsonResponsetok.source.bin + ',' + jsonResponsetok._links.actions.href + ',' + jsonResponsetok.id;
              token = encrypt(block);
              add_tag_enc = '<ENCBLOCKSUBS>' + token + '</ENCBLOCKSUBS>' ;
              resp = resp.replace('</RESPONSE>', add_tag_enc + '</RESPONSE>');


         

              let metadata = JSON.stringify(jsonResponsetok.metadata);
              resp = resp.replace('</RESPONSE>', '<METADATA>' + metadata + '</METADATA>' + '</RESPONSE>');

              ////////////
              let blockToParse = await getCatalog(req.hostname,jsonResponsetok.metadata.tid,jsonResponsetok.metadata.ean,0,req);
             // console.log(blockToParse);
                
              if(blockToParse != 'no_data')
              {

                let desc_info = await getDescriptionInfo(blockToParse,req.hostname,jsonResponsetok.metadata.ean,req);        
                let add_info = '';
            
                let terms = '';           
                let shortdesciption = '';
              
                if(desc_info.includes('<ADD_INFO>'))
                {
                    let arr = desc_info.split('<ADD_INFO>');
                    let arr1 = arr[1].split('</ADD_INFO>');
                
                    add_info = arr1[0];
                    console.log(add_info);

                    arr = add_info.split('<SHORTDESC>');
                    arr1 = arr[1].split('</SHORTDESC>');
                    shortdesciption = arr1[0];

                    arr = add_info.split('<TERMS>');
                    arr1 = arr[1].split('</TERMS>');
                    terms = arr1[0];

                    resp = resp.replace('</RESPONSE>', '<SHORTDESC>' + shortdesciption + '</SHORTDESC>' + '</RESPONSE>');
                    resp = resp.replace('</RESPONSE>', '<EAN>' + jsonResponsetok.metadata.ean + '</EAN>' + '</RESPONSE>');
                    // add vat
                    let vat = await getItemVAT(req,jsonResponsetok.metadata.ean,jsonResponsetok.metadata.tid);
                    let vat_tag = '<VAT>' + vat + '</VAT>';
                    resp = resp.replace('</RESPONSE>', vat_tag + '</RESPONSE>');
                }  

              }


            }
            console.log(log_prefix + resp + log_suffix); 
            res.send(resp);

          }
          else {
            let home_ean_tag = '<HOME>' + 'https://' + req.hostname + '</HOME>' + '<EAN>' + (jsonResponsetok.metadata.ean ? jsonResponsetok.metadata.ean : '') + '</EAN>' ;
            let resp = '<RESPONSE><RESULT>17</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_120',req)+'</RESULTTEXT>'+home_ean_tag+'</RESPONSE>';
           
            console.log(log_prefix + resp + log_suffix); 
            res.send(resp);
          }


        }
        else {      
         let resp = '<RESPONSE><RESULT>'+responsetok.status+'</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_120',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
          res.send(resp);
        }

      }
      else {      
         let resp = '<RESPONSE><RESULT>'+responsetok.status+'</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_121',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
        res.send(resp);
      }

        } catch (error) {
          console.log('exception in payment serial auth staus::' + error); 
          let resp = '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT><HOME>https://'+ req.hostname +'</HOME><EAN></EAN></RESPONSE>';
          console.log(log_prefix + resp + log_suffix); 
          res.send(resp)
        }

      } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

      } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }


})




async function updatePaymentInfoInstore(tid,reference,ean,tokenid,last4,cardtype,phone,email,hostname, log_prefix,log_suffix,req) {
  let phone_tag = '<PHONE></PHONE>' ;
  let email_tag = '<EMAIL></EMAIL>' ;

  if(phone.length)
    phone_tag = '<PHONE>' + phone  + '</PHONE>';

  if(email.length)
    email_tag = '<EMAIL>' + email  + '</EMAIL>';

  
  let up_cred = await getUPCredentials(req);
  let userIdHost = up_cred.userIdHost;
  let userPaswdHost = up_cred.userPaswdHost;


  let body = '<REQUEST TYPE="SUBSCRIPTION" MODE="PAYMENTINFO">'+ 
             '<TERMINALID>' + tid + '</TERMINALID>' +
             '<AUTHORIZATION>' +
                '<USERNAME>' + userIdHost + '</USERNAME>' +
                '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
             '</AUTHORIZATION>' +
             '<PRODUCTID>'+ ean + '</PRODUCTID>' +
             '<TXID>'+ (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference) + '_PI'+'</TXID>' +
             '<LOCALDATETIME>' + getFormattedTime() + '</LOCALDATETIME>' +
             '<SUBSCRIPTION>' +
                '<TOKENID>' + tokenid + '</TOKENID>'+
                '<LASTFOUR>' + last4 + '</LASTFOUR>'+
                '<CARDTYPE>' + cardtype + '</CARDTYPE>'+
                phone_tag + 
                email_tag +
             '</SUBSCRIPTION>' +
             '</REQUEST>';

             const fetchOptions = {
              method: 'POST',
              body: body,
              headers: {
                'Content-Type': 'application/xml',
              },
  
            }
            mask_xml_data(fetchOptions.body,log_prefix,log_suffix)
            console.log(log_prefix + 'PAYMENTINFO URL: ' + UPInterfaceURL + log_suffix);
            var upSaleTimeout = setTimeout(() => {console.log(log_prefix + 'PAYMENTINFO URL: TIMEOUT' + log_suffix);}, 30000);
            try {
              const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
              let jsonResponse = await response.text();            
              clearTimeout(upSaleTimeout);  
              mask_xml_data(jsonResponse,log_prefix,log_suffix);
            } catch(err) {
              console.log(err);

            }       

}

async function getDomainPaymentPROMOTID(hostname) {

    let result = 'NO_TID';
    let host = (hostname.split('.'))[0];
  
    if(hostname == DOMAIN_1)
    {
      if(config['domain_1']) {
      if(config['domain_1'].REDEEM_TID) {
        result = config['domain_1'].REDEEM_TID;
      }
     }
    }
    else if(hostname == DOMAIN_2)
    {
      if(config['domain_2']) {
        if(config['domain_2'].REDEEM_TID) {
          result = config['domain_2'].REDEEM_TID;
        }
      }
    }
    else if(hostname == DOMAIN_3)
    {
      if(config['domain_3']) {
        if(config['domain_3'].REDEEM_TID) {
          result = config['domain_3'].REDEEM_TID;
        }
      }
    }
    else if(hostname == DOMAIN_0)
    {
      if(config['domain_0']) {
        if(config['domain_0'].REDEEM_TID) {
          result = config['domain_0'].REDEEM_TID;
        }
      }
    } else if(config[host]) {
      if(config[host].REDEEM_TID) {
        result = config[host].REDEEM_TID;
      }
    }
  
    return result;
  
  

}

async function removeTagFromXML(xml,tag) {
  let final_xml = xml;
  try {   
   let tag_to_remove_start = '<' + tag + '>';
   let tag_to_remove_end = '</' + tag + '>';
   if(final_xml.includes(tag_to_remove_start) && final_xml.includes(tag_to_remove_end)) {

    let arr = final_xml.split(tag_to_remove_start);
    let arr_1 = arr[1].split(tag_to_remove_end);
    final_xml = arr[0] + arr_1[1];
   }
   return final_xml;
  } catch(err) {
    console.log(err);
    return final_xml;
  }

}

async function getPaySerial(tid,reference,amount, log_prefix,log_suffix,hostname,clientip,ean,req,data) {

  let PAYMENT_EAN = '';
  let host = (hostname.split('.'))[0];
  if (hostname == DOMAIN_0) {    
     PAYMENT_EAN = DOMAIN_0_PAYMENT_EAN;    
  } else if (hostname == DOMAIN_1) {    
    PAYMENT_EAN = DOMAIN_1_PAYMENT_EAN;    
 }
  else if(hostname == DOMAIN_3) {    
      PAYMENT_EAN = DOMAIN_3_PAYMENT_EAN;
  }
  else if(hostname == DOMAIN_2) {
      PAYMENT_EAN = DOMAIN_2_PAYMENT_EAN;
  } else if(config[host]) {
    if(config[host].REDEEM_EAN) {
      PAYMENT_EAN = config[host].REDEEM_EAN;
    }
  }

  

  let jsonResponse = '';
  
  let blockToParse = await getCatalog(hostname,tid,PAYMENT_EAN,1,req);


  if(blockToParse.includes('<EAN>'+ ean + '</EAN>')) {
  let arr = blockToParse.split('<EAN>'+ ean + '</EAN>');
  let arr_1 = arr[1].split('</ARTICLE>');
  let ean_block = arr_1[0];
  if(ean_block.includes('<TECHNICAL_INFORMATION>')) {
    let a = ean_block.split('<TECHNICAL_INFORMATION>');
    for(let i=1; i<a.length; i++) {
      let b = a[i].split('</TECHNICAL_INFORMATION>');
      if(b[0].includes('REDEEM_EAN=')) {
       let c = b[0].split('REDEEM_EAN=');
       if(c[1].length) {
         if(c[1].includes(',')) {
           let d = c[1].split(',');
           PAYMENT_EAN = d[0];
         }
         else {
           PAYMENT_EAN = c[1];
         }
         break;
       }

      }
    }
  }
 }

  if(!data) {
    
  if(!blockToParse.includes(('<EAN>'+ PAYMENT_EAN + '</EAN>'))) {
 
    jsonResponse = '<RESPONSE><RESULT>1012</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_122',req)+'</RESULTTEXT><CARD><EAN>'+ PAYMENT_EAN + '</EAN><PAN></PAN></CARD></RESPONSE>';
    console.log(log_prefix + jsonResponse + log_suffix);
    return jsonResponse;
  }
}

  let cred_precision = await getDomainPromoCredentials(req);
  
  userIdHost = cred_precision.precisionUser;
  userPaswdHost = cred_precision.precisionPassword;


const date_n = new Date();
console.log(date_n);
date = JSON.stringify(date_n);
let date_1 = date.toString().replace('T', ' ');
let e2_arr = date_1.toString().split('.');
let local_time = e2_arr[0];

const inc = 1000 * 60 * 60 * 24;
let exp = new Date(date_n);
let e1 = new Date(exp.getTime() + inc);
e1 = JSON.stringify(e1);
let e2 = e1.toString().replace('T',' ');
e2_arr = e2.split('.');
let expiry_time = e2_arr[0];

local_time = local_time.replace('"','');
expiry_time = expiry_time.replace('"','');

let promo_tid = await getDomainPaymentPROMOTID(hostname);
  
  const fetchOptions = {
    method: 'POST',

    body: '<REQUEST type="CREATECUSTOMERCARD">' +
      '<LOCALDATETIME>' + local_time + '</LOCALDATETIME>' +
      '<PASSWORD>' + cred_precision.precisionPassword + '</PASSWORD>' +
      '<TERMINALID>' + promo_tid + '</TERMINALID>' + //tid
      //cashierhead +
      '<TXID>' + reference + '_ps' + '</TXID>' +
      '<USERNAME>' + cred_precision.precisionUser  + '</USERNAME>' +
      '<CARD>' +
      '<EAN>' + PAYMENT_EAN + '</EAN>' +                 
      '</CARD>' +
      //'<AMOUNT>'+ amount +'</AMOUNT>' + 
      ((data) ?  '':('<AMOUNT>'+ amount +'</AMOUNT>')) +
      '<EXPIRY_DATE>' + expiry_time + '</EXPIRY_DATE>' +    
      '</REQUEST>',

    headers: {
      'Content-Type': 'application/xml',
    },

  }
 
  console.log(log_prefix + 'PAYMENT SERIAL SALE Request: ' + cred_precision.precisionURL + log_suffix);
  mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
  
   
   const response = await fetch(cred_precision.precisionURL, fetchOptions,proxy_url);
   jsonResponse = await response.text();
      
  console.log(jsonResponse);



  if(jsonResponse.includes('<RESULT>0</RESULT>'))
  {
    jsonResponse = await removeTagFromXML(jsonResponse,'SECRETCODE');
    jsonResponse = await removeTagFromXML(jsonResponse,'STRIPE2');
    jsonResponse = jsonResponse.replace('</RESPONSE>','<EAN>'+PAYMENT_EAN+'</EAN><HOME>https://'+hostname+'</HOME></RESPONSE>');
    mask_xml_data(jsonResponse,log_prefix,log_suffix);

    if(data) {

      let a = jsonResponse.split('<PAN>');
      let b = a[1].split('</PAN>');
      let pan = b[0];
      let selectedCallingCode = data.phone.substring(0,data.phone.length-9);
      const fetchOptionsActivate = {
        method: 'POST',
    
        body: '<REQUEST TYPE="activate">' +
          '<LOCALDATETIME>' + local_time + '</LOCALDATETIME>' +
          '<PASSWORD>' + cred_precision.precisionPassword + '</PASSWORD>' +
          '<TERMINALID>' + promo_tid + '</TERMINALID>' +
          '<TXID>' + reference + '_act' + '</TXID>' +
          '<USERNAME>' + cred_precision.precisionUser  + '</USERNAME>' +
          '<CARD>' +
          '<PAN>' + pan + '</PAN>' + 
          '<SETATTR NAME="PHONENUMBER">0' + data.phone.substring(data.phone.length-9,data.phone.length) + '</SETATTR>'+ 
          '<SETATTR NAME="TITLE">' + data.title + '</SETATTR>'+
          '<SETATTR NAME="CALLINGCODE">' + selectedCallingCode + '</SETATTR>'+
          '<SETATTR NAME="FIRSTNAME">' + data.name + '</SETATTR>'+  
          '<SETATTR NAME="LASTNAME">' + data.surname + '</SETATTR>'+ 
          '<SETATTR NAME="EMAIL">' + data.email + '</SETATTR>'+    
          '<SETATTR NAME="STORE">' + data.storeName + '</SETATTR>'+
          '<SETATTR NAME="CITY">' + data.location + '</SETATTR>'+       
          '</CARD>' +   
          '</REQUEST>',
    
        headers: {
          'Content-Type': 'application/xml',
        },
    
      }

      console.log(log_prefix + 'REWARD CARD ACTIVATION REQUEST: ' + cred_precision.precisionURL + log_suffix);
      mask_xml_data(fetchOptionsActivate.body,log_prefix,log_suffix);
      
       
       const responseActivate = await fetch(cred_precision.precisionURL, fetchOptionsActivate,proxy_url);
       let jsonResponseActivate = await responseActivate.text();
       jsonResponseActivate = jsonResponseActivate.replace('</RESPONSE>','<EAN>'+PAYMENT_EAN+'</EAN><HOME>https://'+hostname+'</HOME></RESPONSE>');
       mask_xml_data(jsonResponseActivate,log_prefix,log_suffix);
       if(jsonResponseActivate.includes('<PAN>')) {
          jsonResponseActivate = jsonResponseActivate.replace('</PAN>','</PAN><PANCARD>'+pan+'</PANCARD>');
          console.log(jsonResponseActivate);
       }

       return jsonResponseActivate;
    }
    return jsonResponse;
  }
  else if(jsonResponse.includes('<RESULT>'))
  {
    jsonResponse = jsonResponse.replace('</RESPONSE>','<EAN>'+ean+'</EAN><HOME>https://'+hostname+'</HOME></RESPONSE>');
    mask_xml_data(jsonResponse,log_prefix,log_suffix);
    return jsonResponse;
  }
  else {
    let resp = '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+ jsonResponse +'</RESULTTEXT>'+'<EAN>'+ean+'</EAN><HOME>https://'+hostname+'</HOME></RESPONSE>';
    console.log(log_prefix + resp + log_suffix);
    return resp;
  }

}



async function getAkaniRewardsBussinessEANs(req) {
  let EANs = '';
  let hostname = req.hostname;
  let host = (hostname.split('.'))[0];
  if((hostname == DOMAIN_0)&&(config['domain_0'].AKANI_REWARDS_BIZZ_EAN))
  {
    EANs = config['domain_0'].AKANI_REWARDS_BIZZ_EAN;

  }
  else if((hostname == DOMAIN_1)&&(config['domain_1'].AKANI_REWARDS_BIZZ_EAN))
  {
    EANs = config['domain_1'].AKANI_REWARDS_BIZZ_EAN;

  }
  else if((hostname == DOMAIN_3)&&(config['domain_3'].AKANI_REWARDS_BIZZ_EAN))
  {
    EANs = config['domain_3'].AKANI_REWARDS_BIZZ_EAN;

  }
  else if((hostname == DOMAIN_2)&&(config['domain_2'].AKANI_REWARDS_BIZZ_EAN))
  {
    EANs = config['domain_2'].AKANI_REWARDS_BIZZ_EAN;
    
  } else if(config[host]) {
    if(config[host].AKANI_REWARDS_BIZZ_EAN) {
      EANs = config[host].AKANI_REWARDS_BIZZ_EAN;
    }
  }



  return EANs;
}

async function isBusinesInABoxAkani(tid,ean,req) {
  console.log('isBusinesInABoxAkani ==>> tid:' + tid + '&& ean:' + ean);
  
  let AKANI_REWARDS_BIZZ_EAN = await getAkaniRewardsBussinessEANs(req);
  if(AKANI_REWARDS_BIZZ_EAN.includes(ean)) { 
    console.log('Akani rewards business ean list: ' + AKANI_REWARDS_BIZZ_EAN);
    console.log('Akani rewards business ean matched: ' + ean);
    return true;
  }
  return false;
}


async function getAmountEAN(tid,ean,log_prefix,log_suffix,hostname,clientip,req) {
  console.log('tid:' + tid + '&& ean:' + ean);
  let blockToParse = await getCatalog(hostname,tid,ean,0,req);
   
  if(blockToParse != 'no_data')
  { 
     
    
      let arr_amt = blockToParse.split('<AMOUNT CURRENCY');
      let arr_amt_1 = arr_amt[1].split('</AMOUNT>');
      let arr_amt_2 = arr_amt_1[0].split('>');
      let str =  arr_amt_2[1];
      let amount_long = str;
      console.log(log_prefix + 'Amount for EAN: ' + amount_long + log_suffix);
      return amount_long;
    
      
  }
  else {
    console.log(log_prefix + 'Amount for EAN: none' + log_suffix);
    return 'none';
  }

}

async function checkIfVariableProductAndInRange(amtlong,ean,tid,log_prefix,log_suffix,req) {

  console.log('tid:' + tid + '&& ean:' + ean);
  let blockToParse = await getCatalog(req.hostname,tid,ean,0,req);
  //console.log(blockToParse);    
  if(blockToParse != 'no_data')
  { 
    if(!blockToParse.includes(' MAXAMOUNT="0">')) {

      let arrm = blockToParse.split('MINAMOUNT="');
      let arrm_1 = arrm[1].split('"');
      let minamount = arrm_1[0];
      arrm = blockToParse.split('MAXAMOUNT="');
      arrm_1 = arrm[1].split('"');
      let maxamount = arrm_1[0];
      console.log(log_prefix + 'Max & Min amount for EAN: ' + minamount + '::' + maxamount + log_suffix);
  
      if((Number(maxamount) > 0)&&(Number(amtlong) >= Number(minamount))&&(Number(amtlong) <= Number(maxamount))) {
        return 2;
      } else {
        return 1;
      }
    } else {
      return 0;
    }  
      
  }
  else {
    console.log(log_prefix + 'Amount for EAN: none' + log_suffix);
    return -1;
  }

}



async function getDomainPromoCredentials(req) {

  let precisionUser  = config.PRECISION.precisionUser;
  let precisionPassword = config.PRECISION.precisionPassword;
  let precisionURL = config.PRECISION.precisionURL;                
  let host = (req.hostname.split('.'))[0];

    if(req.hostname == DOMAIN_1)
    {
      if(config['domain_1']) {
        if(config['domain_1'].precisionUser)
          precisionUser = config['domain_1'].precisionUser; 
        
        if(config['domain_1'].precisionPassword) 
          precisionPassword = config['domain_1'].precisionPassword;        

        if(config['domain_1'].precisionURL)
          precisionURL = config['domain_1'].precisionURL; 
      }
    }
    else if(req.hostname == DOMAIN_2)
    {
      if(config['domain_2']) {
        if(config['domain_2'].precisionUser)
          precisionUser = config['domain_2'].precisionUser; 
        
        if(config['domain_2'].precisionPassword) 
          precisionPassword = config['domain_2'].precisionPassword;        

        if(config['domain_2'].precisionURL)
          precisionURL = config['domain_2'].precisionURL; 
      }
    }
    else if(req.hostname == DOMAIN_3)
    {
      if(config['domain_3']) {
        if(config['domain_3'].precisionUser)
          precisionUser = config['domain_3'].precisionUser; 
        
        if(config['domain_3'].precisionPassword) 
          precisionPassword = config['domain_3'].precisionPassword;
        

        if(config['domain_3'].precisionURL)
          precisionURL = config['domain_3'].precisionURL; 
      }
    }
    else if(req.hostname == DOMAIN_0)
    {
      if(config['domain_0']) {
        if(config['domain_0'].precisionUser)
          precisionUser = config['domain_0'].precisionUser; 
        
        if(config['domain_0'].precisionPassword) 
          precisionPassword = config['domain_0'].precisionPassword;
        

        if(config['domain_0'].precisionURL)
          precisionURL = config['domain_0'].precisionURL; 
      }
    } else if(config[host]) {    
        if(config[host].precisionUser)
          precisionUser = config[host].precisionUser;
        
          
        if(config[host].precisionPassword) 
          precisionPassword = config[host].precisionPassword;
        

        if(config[host].precisionURL)
          precisionURL = config[host].precisionURL; 
        
  }
  if(precisionPassword.length > 5) {
    if(precisionPassword.substring(0,5) == '!PWD!')
    {
      precisionPassword = decrypt_pwd(precisionPassword.substring(5,precisionPassword.length),PWD_SECRET_KEY,PWD_IV);
    }
  }

  let obj = {
    precisionUser: precisionUser,
    precisionPassword: precisionPassword,
    precisionURL: precisionURL
  }

  return obj;

}

async function refundProxySamsungCare(reference,redeemCode,amount,ean,log_prefix,log_suffix,req,clientip)
{

  let cred_precision = await getDomainPromoCredentials(req);

  let promo_tid = await getDomainPaymentPROMOTID(req.hostname);
  let tidhead = '<TERMINALID>' + promo_tid + '</TERMINALID>';
  let local_date = getFormattedTime();
  let body = '<REQUEST type="REFUND">' +
   '<USERNAME>' + cred_precision.precisionUser + '</USERNAME>' +
   '<PASSWORD>' + cred_precision.precisionPassword + '</PASSWORD>' +
  tidhead +  
  '<LOCALDATETIME>' + local_date + '</LOCALDATETIME>'+
  '<TXID>' + reference + '_' + 'rf'  + '</TXID>' +
  '<CARD>' +
          '<PAN>'+ redeemCode + '</PAN>'+
          '<EAN>'+ ean + '</EAN>'+
  '</CARD>' +
  '<AMOUNT>' + amount + '</AMOUNT>' + 

  '</REQUEST>';

    const fetchOptions = {
      method: 'POST',
      body: body,
      headers: {
        'Content-Type': 'application/xml',
      },
    }

    console.log(log_prefix + 'SAMSUNG proxy refund request URL: ' + cred_precision.precisionURL  + log_suffix);
    mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
    var upPreAuthTimeout = setTimeout(() => {return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_123',req)+ '</RESULTTEXT></RESPONSE>';} , 30000);
    try {
       const response = await fetch(cred_precision.precisionURL, fetchOptions,proxy_url);
       let  jsonResponse = await response.text();

      clearTimeout(upPreAuthTimeout);

      console.log(log_prefix + 'SAMSUNG proxy refund response received from server' + log_suffix);
          let jsonResponse_log = jsonResponse;
          jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
          mask_xml_data(jsonResponse_log,log_prefix,log_suffix);   
         
          if(!jsonResponse.includes('<RESULT>'))
          {
            return  ('<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + jsonResponse + '</RESULTTEXT></RESPONSE>');
          }else
          {
     
            return jsonResponse ;
          }
    } catch (err) {
      console.log(log_prefix + JSON.stringify(err) + log_suffix);
      console.log(log_prefix + 'samsung proxy refund failed with exception' + log_suffix);
      return 'samsung proxy refund failed with exception.';
    }


}

async function getPromoCardStatus(tidhead,reference,code,log_prefix,log_suffix,clientip,req)
{ 

  if((clientip == TEST_IP_AZURE)&&(req.hostname == 'endlessaisle.epayworldwide.com')) {
    let resp = fs.readFileSync('/var/www/html/ca/cardstatus_proxy.txt', 'utf8');
    console.log('hardcoded response cardstatus: ' + resp);
    return resp;
  }  

      let cred_precision = await getDomainPromoCredentials(req);
      
      let promo_tid = await getDomainPaymentPROMOTID(req.hostname); 
      let local_date = getFormattedTime();
      let body = '<REQUEST type="CARDSTATUS">' +
		 	'<USERNAME>' + cred_precision.precisionUser + '</USERNAME>' +
        		'<PASSWORD>' + cred_precision.precisionPassword + '</PASSWORD>' +
			//tidhead +  
      '<TERMINALID>' + promo_tid + '</TERMINALID>' +
			'<TXID>' + reference + '_' + 'CS'  + '</TXID>' +
			'<CARD>' +
        			'<PAN>'+ code + '</PAN>'+
                  
        		'</CARD>' +
			'<LOCALDATETIME ENFORCE="1">' + local_date + '</LOCALDATETIME>'+
			'</REQUEST>';

        const fetchOptions = {
          method: 'POST',
          body: body,
          headers: {
            'Content-Type': 'application/xml',
          },
        }

        console.log(log_prefix + 'CARDSTATUS Info Request: ' + cred_precision.precisionURL  + log_suffix);
        mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
  

        var upPreAuthTimeout = setTimeout(() => {return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_123',req) + '</RESULTTEXT></RESPONSE>';} , 30000);
        try {
          let  jsonResponse = '';
                        const response = await fetch(cred_precision.precisionURL, fetchOptions,proxy_url);
                jsonResponse = await response.text();
                if(jsonResponse.includes('<RESULTTEXT>card unknown</RESULTTEXT>')) {
                  jsonResponse = jsonResponse.replace('<RESULTTEXT>card unknown</RESULTTEXT>','<RESULTTEXT>'+ getMessageIDText('MESSAGEID_124',req)+'</RESULTTEXT>');
                }
          clearTimeout(upPreAuthTimeout);

          console.log(log_prefix + 'CARDSTATUS Info Response received from server' + log_suffix);
              let jsonResponse_log = jsonResponse;
              jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
              mask_xml_data(jsonResponse_log,log_prefix,log_suffix);  
            
	            if(jsonResponse.includes('<!DOCTYPE HTML PUBLIC'))
	            {
		             let resp = 'Service unavailable';
                 if(jsonResponse.includes('<title>'))
                 {
                   let a1 = jsonResponse.split('<title>');
                   let a2 = a1[1].split('</title>');
                   resp = a2[0];
                 }
                 return  ('<RESPONSE><RESULT>503</RESULT><RESULTTEXT>' + resp + '</RESULTTEXT></RESPONSE>');

	            }
              else if(!jsonResponse.includes('<RESULT>'))
              {
                return  ('<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + jsonResponse + '</RESULTTEXT></RESPONSE>');
              }else
              {
               
                console.log(jsonResponse);
                return jsonResponse ;
              }
        } catch (err) {
          console.log(err);
          return 'failed';
        }

}

app.get('/getSamsungCarePlus', cors(corsOptions),async(req,res)=> {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getSamsungCarePlus => clientip: ' + clientip);
  let log_prefix = '';
  let log_suffix = '';
  let obj = JSON.parse(Buffer.from(req.query.data,'base64').toString('utf8'));

  let tid = obj.tid;
  if((obj.tid == '') ||  (obj.tid == 'undefined') || (obj.tid == 'notid') ){
    tid = getDefaultTID(req.hostname,req);
  }

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
     try{
      let tidhead = '<TERMINALID>' + tid + '</TERMINALID>' ;
      var txid = getTimeStamp();
      var x = Math.random() * 1000000;
      console.log(x);
      var y = x.toString().split('.');
      console.log(y[0]);
      txid = txid + y[0];
      console.log(txid);
  
       let ref =  getTimeStamp() + '0';
       let reference = 'EPAY-' + tid + (parseInt(ref)).toString(16).toUpperCase() + '-' + txid.substring(0,9);
  
      let session_id = reference;
      let host_log = req.hostname.split('.');

      let method = 'REDEEM_CODE_SAMSUNG_CARE_PLUS';
      log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
      log_suffix = '\n</LOG></SESSION_LOG>';
      console.log(log_prefix + req.headers.campaign + '>>API_CALL:getSamsungCarePlus => clientip: ' + clientip + log_suffix);

      console.log(log_prefix + req.query.data + log_suffix);
      console.log(log_prefix + JSON.stringify(obj) + log_suffix);
  
      let up_cred = await getUPCredentials(req);
  
      let userIdHost = up_cred.userIdHost;
      let userPaswdHost = up_cred.userPaswdHost;
      let customer = up_cred.customer;
    
  
  
    let PreAuthAddInfoResponse = await getPromoCardStatus(tidhead,reference,obj.redeemCode,log_prefix,log_suffix,clientip,req);
    console.log(log_prefix + PreAuthAddInfoResponse + log_suffix);
    
    let error_proxy = '';
    
  
    if((PreAuthAddInfoResponse.includes('<RESULT>0</RESULT>'))&&(PreAuthAddInfoResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))&&(PreAuthAddInfoResponse.includes('<ATTRIBUTE NAME="Samsung_EAN">')))
    {
        
        let arr  = PreAuthAddInfoResponse.split('<ATTRIBUTE NAME="Samsung_EAN">');
        let arr1 = arr[1].split('</ATTRIBUTE>');
        let ean_to_use = arr1[0];
        let ret_resp = '';

        let blockToParse = await getCatalog(req.hostname,tid,ean_to_use,0,req);
    
          
        if(blockToParse != 'no_data')
        {      

            let desc_info = await getDescriptionInfo(blockToParse,req.hostname,ean_to_use,req);        
            let add_info = '';
            let add_info_append = '';      
            let product = '';
            let amount = '';
            let amt = '';
            let terms = '';
            let productlogo = '';
            let shortdesciption = '';
            let company = '';
            let provLogo = '';
            if(desc_info.includes('<ADD_INFO>'))
            {
                let arr = desc_info.split('<ADD_INFO>');
                let arr1 = arr[1].split('</ADD_INFO>');
            
                add_info = arr1[0];
                console.log(add_info);      

                arr = add_info.split('<PRODUCT_INFO>');
                arr1 = arr[1].split('</PRODUCT_INFO>');
                product = arr1[0];

                arr = add_info.split('<AMOUNT_INFO>');
                arr1 = arr[1].split('</AMOUNT_INFO>');
                amount = arr1[0];
                add_info_append = arr[0];

                arr = add_info.split('<AMT_INFO>');
                arr1 = arr[1].split('</AMT_INFO>');
                amt = arr1[0];

                arr = add_info.split('<SHORTDESC>');
                arr1 = arr[1].split('</SHORTDESC>');
                shortdesciption = arr1[0];

                arr = add_info.split('<TERMS>');
                arr1 = arr[1].split('</TERMS>');
                terms = arr1[0];

                arr = add_info.split('<LOGO>');
                arr1 = arr[1].split('</LOGO>');
                productlogo = arr1[0];

                arr = add_info.split('<PROVLOGO>');
                arr1 = arr[1].split('</PROVLOGO>');
                provLogo = arr1[0];

                arr = add_info.split('<COMPANY>');
                arr1 = arr[1].split('</COMPANY>');
                company = arr1[0];

                arr = add_info.split('<TYPE>');
                arr1 = arr[1].split('</TYPE>');
                type = arr1[0];

                ret_resp = '<ADD_INFO>' + '<SHORTDESC>' + shortdesciption + '</SHORTDESC>' + '<TERMS>' + terms + '</TERMS>' + '<LOGO>' + productlogo + '</LOGO>' +  '<COMPANY>' + company + '</COMPANY>' +  '<PROVLOGO>' + provLogo + '</PROVLOGO>' + '<PRODUCT>' + product + '</PRODUCT>' + '<EAN>' + ean_to_use+'</EAN>' + '</ADD_INFO>' ;
  
          }

          if((obj.imei.length == 0)&&(obj.mode == 0)) {
            let result = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+'success'+'</RESULTTEXT>'+ ret_resp +'</RESPONSE>';
            console.log(log_prefix + result + log_suffix);
            res.send(result);
            return;
          }


        let chargeResponse =  await getChargePromoCard(tidhead,reference,amount,obj.redeemCode,log_prefix,log_suffix,true,req.hostname,clientip,req);
        
        if(!chargeResponse.includes('<RESULT>0</RESULT>')) {
          chargeResponse = chargeResponse.replace('</RESPONSE>', ret_resp + '</RESPONSE>');
          console.log(log_prefix + chargeResponse + log_suffix);
          res.send(chargeResponse);
          return;
        }
       

        let extrahead = '<EXTRADATA>' +
                        '<DATA name="FNAME">' + obj.firstname + '</DATA>' +
                        '<DATA name="LNAME">'+ obj.lastname + '</DATA>' +
                        '<DATA name="EMAIL">'+ obj.mail + '</DATA>' +
                        '</EXTRADATA>';

        let serial_proxy_tag = '<Comment>' + 'PaymentMethod=proxySamsung|SERIAL=' + '</Comment>';
        if(PreAuthAddInfoResponse.includes('<SERIAL>')) {
    
            let a =  PreAuthAddInfoResponse.split('<SERIAL>');
            let b = a[1].split('</SERIAL>');
            serial_proxy_tag =  '<Comment>' + 'PaymentMethod=proxySamsung|SERIAL=' +  b[0] + '</Comment>';
        }

        const fetchOptions = {
          method: 'POST',

          body: '<REQUEST type="SALE" STORERECEIPT="1">' +         
            
            '<AUTHORIZATION>' + 
            '<USERNAME>' + userIdHost + '</USERNAME>' +
            '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
            '</AUTHORIZATION>' + 
            tidhead +
            '<LOCALDATETIME>' + getFormattedTime() + '</LOCALDATETIME>' +
            '<TXID>' + (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference) + '</TXID>' +
            '<CARD>' +
            '<PAN>' + obj.imei + '</PAN>' +
            '<EAN>' + ean_to_use + '</EAN>' +                  
            '</CARD>' +           
            serial_proxy_tag +
            extrahead +
            '</REQUEST>',

          headers: {
            'Content-Type': 'application/xml',
          },

        }
      
        console.log(log_prefix + 'SALE Request samsung care plus: ' + UPInterfaceURL + log_suffix);


        mask_xml_data(fetchOptions.body,log_prefix,log_suffix);

        const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
        let jsonResponse = await response.text();
        jsonResponse = await updateRedeemptionURL(jsonResponse);
       
        
        let result = '';
        if(jsonResponse.includes('<RESULT>0</RESULT>')) {
           result  = jsonResponse.replace('</RESPONSE>','<HOME>'+ req.headers.referer +'</HOME>'+ '<CODE>' + obj.redeemCode + '</CODE>' + '<IMEI>' + obj.imei + '</IMEI>' + ret_resp + '</RESPONSE>');
        }else {
          let result_refund_promo_samsung = await refundProxySamsungCare(reference,obj.redeemCode,amount,ean_to_use,log_prefix,log_suffix,req,clientip);
          console.log(log_prefix + 'result_refund_promo_samsung: ' + result_refund_promo_samsung + log_suffix);
          result = jsonResponse.replace('</RESPONSE>', ret_resp + '</RESPONSE>');
        }
        console.log(log_prefix + 'result_sale_promo_samsung: ' + result + log_suffix);

        res.send(result);       
        return;
        } else {        
          error_proxy = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_125',req)+'</RESULTTEXT></RESPONSE>';
        }
     

    } else if(!PreAuthAddInfoResponse.includes('<RESULT>0</RESULT>')){
      error_proxy = PreAuthAddInfoResponse;
    } else if(!PreAuthAddInfoResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')) {
       let errorText = getMessageIDText('MESSAGEID_126',req);
       if(PreAuthAddInfoResponse.includes('<CARDSTATUS>NOTACTIVATED</CARDSTATUS>'))
       {
         errorText = getMessageIDText('MESSAGEID_127',req)
       }
       else if(PreAuthAddInfoResponse.includes('<CARDSTATUS>DEACTIVATED</CARDSTATUS>'))
       {
         errorText = getMessageIDText('MESSAGEID_128',req)
       }
       else if(PreAuthAddInfoResponse.includes('<CARDSTATUS>REDEEMED</CARDSTATUS>'))
       {
         errorText = getMessageIDText('MESSAGEID_129',req);
       }       
       error_proxy = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT></RESPONSE>';  

       
    } else {
        error_proxy = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_130',req)+'</RESULTTEXT></RESPONSE>';
    }
    console.log(log_prefix + error_proxy + log_prefix);
    res.send(error_proxy);
    }catch(err) {
            console.log(log_prefix +'Exception in processing samsung request'+ log_suffix);
            console.log(log_prefix +JSON.stringify(err)+ log_suffix);
            let resp = '<RESPONSE><RESULT>1022</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>'
            console.log(log_prefix +resp+ log_suffix);
            res.send(resp);
            return;
          }


    }else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  

})


app.get('/getPaymentSerial', cors(corsOptions),async(req,res)=> {

  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPaymentSerial => clientip: ' + clientip);

  let obj_p = JSON.parse(Buffer.from(req.query.data,'base64').toString('utf8'));
  let obj = obj_p[0];
  console.log(obj);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
        try {
              let session_id = obj.reference;
              let host_log = req.hostname.split('.');
              let method = 'GET_PAYMENT_SERIAL';
              let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
              let log_suffix = '\n</LOG></SESSION_LOG>';

              console.log(log_prefix + req.headers.campaign + '>>API_CALL:getPaymentSerial => clientip: ' + clientip + log_suffix);

              ///////// Additional Security check for promo discount /////////////////
          
          let promoConfigValue =  await getPaymentMethods(req.hostname);
          let promoEnabled = 'no';
          if(promoConfigValue.includes('redeem')) {
            promoEnabled = 'yes';
          }

          if(Number(obj.discountApplied)>0) {
            try {
              obj.promoApplied = '1';
              let tidhead = '<TERMINALID>' + obj.tid + '</TERMINALID>' ;
              let txid = obj.reference;
              if((obj.promoCode) && (obj.promoCode != 'none')&&(redeem_option == '1')&&(promoEnabled == 'yes')) {                
                  let cardStatusResponse = await getPromoCardStatus(tidhead,txid + '_D',obj.promoCode,log_prefix,log_suffix,clientip,req);
                  if(((cardStatusResponse.includes('<RESULT>0</RESULT>'))&&(cardStatusResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')))&&(cardStatusResponse.includes('<BALANCE>'))&&(!cardStatusResponse.includes('<ATTRIBUTE NAME="PROXY'))) {
                    let a1 = cardStatusResponse.split('<BALANCE>');
                    let a2 = a1[2].split('</BALANCE>');
                    let balance= a2[0];
                    console.log('promo balance while get pay serial check: ' + balance); 
                    if(Number(balance) >= Number(obj.discountApplied))  {
                      console.log(log_prefix +'Promo code balance: ' + balance + ' | Discount from client: ' + obj.discountApplied + log_suffix);
                      console.log(log_prefix +'Promo code check passed' + log_suffix);
                      obj.promoApplied = '1';
                    } else {
                      
                        console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
                        let resp = '<RESPONSE><RESULT>155</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
                        console.log(log_prefix +resp+ log_suffix);
                        let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.tid + ' Reason: GET_PAYMENT_SERIAL balance insufficient'
                        console.log(log_prefix + alert + log_suffix);
                        if(BlockedIPs) {
                          BlockedIPs = BlockedIPs + ',' + clientip;
                        }else {
                          BlockedIPs = clientip;
                        }
                        res.send(resp);
                        return;
                      }               
                  } else {
                    
                    console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
                    let resp = '<RESPONSE><RESULT>156</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
                    console.log(log_prefix +resp+ log_suffix);
                    let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.tid + ' Reason: GET_PAYMENT_SERIAL CARDSTATUS is not valid'
                    console.log(log_prefix + alert + log_suffix);
                    if(BlockedIPs) {
                      BlockedIPs = BlockedIPs + ',' + clientip;
                    }else {
                      BlockedIPs = clientip;
                    }
                    res.send(resp);
                    return;
                  }
            } else {
              
              console.log(log_prefix +'Promo discount amount suspicious'+ log_suffix);
              let resp = '<RESPONSE><RESULT>157</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>'
              console.log(log_prefix +resp+ log_suffix);
              let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.tid + ' Reason: GET_PAYMENT_SERIAL promo info is not valid'
              console.log(log_prefix + alert + log_suffix);
              if(BlockedIPs) {
                BlockedIPs = BlockedIPs + ',' + clientip;
              }else {
                BlockedIPs = clientip;
              }
              res.send(resp);
              return;
            }

          }catch(err) {
            console.log(log_prefix +'Discount security check exception get payment serial'+ log_suffix);
            console.log(log_prefix +JSON.stringify(err)+ log_suffix);
            let resp = '<RESPONSE><RESULT>158</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>'
            console.log(log_prefix +resp+ log_suffix);
            res.send(resp);
            return;
          }
          }
    
          /////////////////////////////////////////////////////////////////////////

              let amount_product = await getAmountEAN(obj.tid,obj.ean,log_prefix,log_suffix,req.hostname,clientip,req);
              let reslt = await checkIfVariableProductAndInRange(obj.amtlong,obj.ean,obj.tid,log_prefix,log_suffix,req);
              if(reslt == 2) {
                amount_product = obj.amtlong;
              } else if(reslt == 1) {
                  //Security error block ip
                  let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_PAYMENT_SERIAL Variable product range check failed'
                  console.log(log_prefix + alert + log_suffix);
                  if(BlockedIPs) {
                    BlockedIPs = BlockedIPs + ',' + clientip;
                  }else {
                    BlockedIPs = clientip;
                  }
              } else if(reslt == -1) {
                //Security error block ip
                let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_PAYMENT_SERIAL product ean not found'
                console.log(log_prefix + alert + log_suffix);
                if(BlockedIPs) {
                  BlockedIPs = BlockedIPs + ',' + clientip;
                }else {
                  BlockedIPs = clientip;
                }
              } 

              if(amount_product != 'none') 
              {
                   console.log(log_prefix + 'amount product :' + amount_product + log_suffix);
                   console.log(log_prefix + 'obj promo:' + JSON.stringify(obj) + log_suffix);

                  if((obj.promoApplied == '1')&&(obj.discountApplied != '0')&&(obj.promoCode.length > 0))
                  {
                    console.log(log_prefix + 'promoApplied :' + obj.promoApplied + log_prefix);

                    let result = await chargePromoCode(obj.tid,obj.promoCode,obj.discountApplied,obj.reference,log_prefix,log_suffix,amount_product,req.hostname,clientip,req)
                    console.log(log_prefix + 'charge result :' + result + log_suffix);
                    if(result != 'Success')
                    {
                      console.log(log_prefix + result + log_suffix);
                      res.send(result);
                      return;
                    }
                  } 
                  else if(obj.promoApplied == '1')
                  {
                    let resp = '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_119',req)+'</RESULTTEXT></RESPONSE>';
                    console.log(log_prefix + resp + log_suffix);
                    res.send(resp);
                    return;
                  }
                  
                  let amount_serial = Number(amount_product) - Number(obj.discountApplied);
               
                  let resp = await getPaySerial(obj.tid,obj.reference,amount_serial.toString(),log_prefix,log_suffix,req.hostname,clientip,obj.ean,req);
                  //console.log(resp);
                  if((resp.includes('<RESULT>0</RESULT>'))||(resp.includes('<RESULT>1012</RESULT>')))
                  {                    
                    // Add code to generate encypted info for promo payment, ean and serial for validation and append to response
                    let a1 = resp.split('<PAN>');
                    let a2 = a1[1].split('</PAN>');
                    let payment_serial = a2[0];
                    let block = amount_product + ',' + payment_serial + ',' + obj.ean + ',' + obj.promoCode + ',' + obj.discountApplied + ',' + obj.reference + ',' + obj.promoApplied;
                    console.log(block);
                    let token = encrypt(block);
                    let add_tag_enc = '<ENCBLOCK>' + token + '</ENCBLOCK>' ;
                    console.log(add_tag_enc);
                    resp = resp.replace('</RESPONSE>', add_tag_enc + '</RESPONSE>');
                   
                  }
                  console.log(log_prefix + resp + log_suffix);
                  res.send(resp);
              }
              else {
                console.log(log_prefix + 'Product not found in catalog' + log_suffix); 
                res.send('<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>')
              }

        } catch (error) {
          console.log('exception in payment serial::' + error); 
          let resp = '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>';
          //console.log(log_prefix + resp + log_suffix);
          res.send(resp);
        }

      } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

      } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

})

/////////////////////////////////////////In Store END ///////////////////////////////////////////////////////

async function getAuth201SaleResponse(jsonResponsetok,metadata,req,clientip) {

  

      jsonResponsetok.metadata = metadata;
      console.log(jsonResponsetok);

      let session_id = jsonResponsetok.reference;
      let host_log = req.hostname.split('.');
      let method = 'GET_AUTH_SALE_201';
      let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
      let log_suffix = '\n</LOG></SESSION_LOG>';         
      try {

        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getAuthPinCode201 => clientip: ' + clientip + log_suffix);
        
        mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);
        console.log(jsonResponsetok.metadata.ean);
        console.log(log_prefix + jsonResponsetok.status + log_suffix);



        let temp_data = jsonResponsetok.metadata.moreInfo;
        let temp_arr = temp_data.split(',');
        let promoApplied_add = temp_arr[0] ? temp_arr[0] : "";
        let discount_add = temp_arr[1] ? temp_arr[1] : "";
        let promoCode_add = temp_arr[2] ? temp_arr[2] : "";
        let ActivationSerial_add = temp_arr[3] ? temp_arr[3] : "";
        let ProductTypeSale_add = temp_arr[4] ? temp_arr[4] : "";
        let CurrencyCodeProduct_add = temp_arr[5] ? temp_arr[5] : "";
        let instore_add = temp_arr[6] ? temp_arr[6] : "";
        let gpay_add = temp_arr[7] ? temp_arr[7] : "";
        let delivery_add = temp_arr[8] ? temp_arr[8] : "";
        let flashVoucher_add = temp_arr[9] ? temp_arr[9] : "none";
        let africanID_add = temp_arr[10] ? temp_arr[10] : "none";
        let cashier_add = temp_arr[11] ? temp_arr[11] : "";

        jsonResponsetok.metadata['promoApplied'] = promoApplied_add;
        jsonResponsetok.metadata['discount'] = discount_add;
        jsonResponsetok.metadata['promoCode'] = promoCode_add;
        jsonResponsetok.metadata['ActivationSerial'] = ActivationSerial_add;
        jsonResponsetok.metadata['ProductTypeSale'] = ProductTypeSale_add;
        jsonResponsetok.metadata['CurrencyCodeProduct'] = CurrencyCodeProduct_add;
        jsonResponsetok.metadata['instore'] = instore_add;
        jsonResponsetok.metadata['gpay'] = gpay_add;
        jsonResponsetok.metadata['delivery'] = delivery_add;
        jsonResponsetok.metadata['flashVoucher'] = flashVoucher_add;
        jsonResponsetok.metadata['cashier'] = africanID_add;
        jsonResponsetok.metadata['africanID'] = cashier_add;

        delete jsonResponsetok.metadata['moreInfo'];

        //////////////////////////////////////////////
        let instore_txn = '0';
        if(jsonResponsetok.metadata.instore)
        {
            instore_txn = '1';
        }

        //---------------------------------

        let bApplePay = false;
        if(((jsonResponsetok.status == 'Captured')||(jsonResponsetok.status == 'Authorized'))&&(jsonResponsetok.approved == true)) {
          try  {
          if(jsonResponsetok.source.card_wallet_type) {
            if(jsonResponsetok.source.card_wallet_type == 'applepay') {
              bApplePay = true;
            } 
          }
        
        
          if(!bApplePay) {              
              let jsonResponse201 = '<RESPONSE><RESULT>180</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_131',req)+'</RESULTTEXT></RESPONSE>';
              let refund_status_promo_txn = false;
              let refund_status_card_txn = false;
              if(jsonResponsetok.amount > 0) {
                let customer = await getCustomerName(req.hostname);
                let act_id = await getActionIdCaptureCheckout(jsonResponsetok.id,log_prefix,log_suffix,jsonResponsetok.metadata.tid,req.hostname,req);
                if((act_id != 'none')&&(act_id.includes('act_')))
                { 
                    let response = await processRefundCheckout(jsonResponsetok.amount,jsonResponsetok.reference + '_r',act_id,jsonResponsetok.id,jsonResponsetok.metadata.ean,jsonResponsetok.metadata.tid,jsonResponsetok.reference,customer,log_prefix,log_suffix,req.hostname,req);
                  
                    console.log(log_prefix +  response + log_suffix);
                    if(response.includes('<RESULT>0</RESULT>'))
                    {
                      refund_status_card_txn = true;
                    }
                }
              } else {
                refund_status_card_txn = true;
              }

              if((jsonResponsetok.metadata.promoApplied == '1')&&(Number(jsonResponsetok.metadata.discount) > 0)&&(jsonResponsetok.metadata.promoCode.length)) {
                let promocode = jsonResponsetok.metadata.promoCode;                
                
                let tid_used = jsonResponsetok.metadata.tid;
                  let result_refund_promo = await refundPromoDiscount(tid_used,jsonResponsetok.reference, promocode,log_prefix,log_suffix,req);
                  console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                  if(result_refund_promo.includes('<RESULT>0</RESULT>'))
                  {
                    refund_status_promo_txn = true;               
                    
                  }  
                  
              } else {
                refund_status_promo_txn = true;
              }

                  
              let refund_status = 'Any charges occured during this transaction will be refunded. Please contact ' + await getCustomerName(req.hostname) + getMessageIDText('MESSAGEID_133',req);
              
              jsonResponse201 = jsonResponse201.replace('</RESULTTEXT>', '\n' + refund_status + '</RESULTTEXT>');
              jsonResponse201 = jsonResponse201 + '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>';
              console.log(log_prefix + jsonResponse201 + log_suffix);
              return (jsonResponse201);
          }
        }  catch(err) {
          console.log(err);
          let refund_status = getMessageIDText('MESSAGEID_132',req) + await getCustomerName(req.hostname) + getMessageIDText('MESSAGEID_133',req);
          let jsonResponse201 = '<RESPONSE><RESULT>181</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_134',req)+'</RESULTTEXT></RESPONSE>';
          jsonResponse201 = jsonResponse201.replace('</RESULTTEXT>', '\n' + refund_status + '</RESULTTEXT>');
          jsonResponse201 = jsonResponse201 + '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>';
          console.log(log_prefix + jsonResponse201 + log_suffix);
          return (jsonResponse201);
        }
        
        } 

        if (((jsonResponsetok.status == 'Captured')||(jsonResponsetok.status == 'Authorized')||(jsonResponsetok.status == 'Card Verified')) && (jsonResponsetok.approved == true) && (jsonResponsetok.metadata.instore == '0')) {

        
          
        let shortdesciption = '';
        let longdescriptiontag = '';
        let redeemptiondesciptiontag = '';
        let terms = '';
        let termstag = '';
        let host = req.hostname.split('.');
        let blockToParse = await getCatalog(req.hostname , jsonResponsetok.metadata.tid, jsonResponsetok.metadata.ean,0,req);
        
        if(blockToParse != 'no_data')
        {
          let lang = req.headers.campaign;
          if(lang && (language_list.includes(lang))) {
                let jsonInfoXML = await getJSONInfoCatalog(blockToParse,req,true);            
                //console.log('jsonInfoXML: ' + jsonInfoXML);
                let a = jsonInfoXML.split('<INFOSJSON>');
                let b = a[1].split('</INFOSJSON>');
                if(b[0] != '{}') {
                  let jsonInfo = JSON.parse(b[0]);
                  console.log(JSON.stringify(jsonInfo[lang]));
                  desc = jsonInfo[lang].DESCRIPTION_SHORT[0];
                  redeemptiondesciptiontag = '<REDEEMDESC>' + jsonInfo[lang].DESCRIPTION_REDEMPTION[0] + '</REDEEMDESC>';
                  longdescriptiontag = '<LONGDESC>' + jsonInfo[lang].DESCRIPTION_LONG[0] + '</LONGDESC>';
                  termstag = '<TERMS>' + jsonInfo[lang].TERMS_AND_CONDITIONS[0] + '</TERMS>';
                  terms = jsonInfo[lang].TERMS_AND_CONDITIONS[0];
                  shortdesciption = jsonInfo[lang].DESCRIPTION_SHORT[0];
                }
          } else {
                  var parseString = require('xml2js').parseString;
                  parseString(blockToParse, function (err, result) {
                    console.log(result.RESPONSE);
                    console.log(result.RESPONSE.INFOS);
                    let short_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_SHORT;
                    let long_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_LONG;
                    let redeem_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_REDEMPTION;
                  
                    if(redeem_desc.length)
                      redeemptiondesciptiontag = '<REDEEMDESC>' + redeem_desc + '</REDEEMDESC>';
                    
                    if(long_desc.length)
                      longdescriptiontag = '<LONGDESC>' + long_desc + '</LONGDESC>';

                    let desc = (short_desc.length > 0)? short_desc : long_desc;
                    shortdesciption = desc;
                    terms = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].TERMS_AND_CONDITIONS;

                    if(terms.length)
                      termstag = '<TERMS>'+terms+'</TERMS>';
                    
                    
                  });
          }
        }
          
          var txnarr = jsonResponsetok.processed_on.toString().split(".");
          let metaTID = jsonResponsetok.metadata.tid;

          let up_cred = await getUPCredentials(req);

          var userIdHost = up_cred.userIdHost;
          var userPaswdHost = up_cred.userPaswdHost;   

          let customer = up_cred.customer;
          

          console.log(txnarr);
          var txnTime = txnarr[0].replace('T', ' ');
          txnTime = txnTime.replace('Z','');
          console.log(txnTime);

          var ref = getTimeStamp();
          var refjsonarr = jsonResponsetok.metadata.reference.split('-');
          let reftxntemp = refjsonarr[1];
          let reftxntemp2 = '';
          if(refjsonarr[2]){
            if(refjsonarr[2].length >= 9){
              reftxntemp2 = refjsonarr[2].substring(0,9);
            }
          }
          var inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + ((reftxntemp2.length == 9) ? reftxntemp2:reftxntemp.substring(0,8));

          let tidhead = '<TERMINALID>'+ metaTID +'</TERMINALID>';  
          let gtid = metaTID;
          if((metaTID == '') || (metaTID == 'undefined') || (metaTID == 'notid'))
          {
            gtid = getDefaultTID(req.hostname,req);
            tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
          }

                              
        
          {
            
            var extrahead = '';
            var eanhead = '<EAN>' + jsonResponsetok.metadata.ean + '</EAN>';
            var eantouse = jsonResponsetok.metadata.ean;
            if (jsonResponsetok.metadata.product.includes('Renewal') || jsonResponsetok.metadata.product.includes('renewal')) {
              extrahead = '<EXTRADATA>' +
                '<DATA name="CONTRACT">' + jsonResponsetok.metadata.reference + '</DATA>' +
                '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
                '</EXTRADATA>';
              
            }

        

          if(jsonResponsetok.metadata.product.toLowerCase().includes('renewal')) { 
                let info = await getTestSubscriptionInfo(req.hostname,jsonResponsetok.metadata.ean);
                if(info) {
                tidhead = '<TERMINALID>' + info.TestSubscriptionTID + '</TERMINALID>';
                eanhead = '<EAN>' + info.TestSubscriptionEAN + '</EAN>';
                }
            }

            let cashierhead = '';
            if(jsonResponsetok.metadata.cashier)
            {
              cashierhead = '<CASHIER>' + jsonResponsetok.metadata.cashier + '</CASHIER>';
            }
            let send_sms_tag = '';
            let send_email_tag = '';
        
            let delivery_m = null;
            
            let del_mode = getDeliveryMode(req.hostname,delivery_m);

            if(del_mode.includes('SMS'))
            {
              send_sms_tag = '<SMS>' + '+' + jsonResponsetok.metadata.phone + '</SMS>' ;
              
            }

            if(del_mode.includes('EMAIL'))
            {
              send_email_tag = '<EMAIL>' + jsonResponsetok.metadata.email + '</EMAIL>' ;                
            }
            let PAN_TAG = '';
            let CURRENTCY_TAG = '';

            if(jsonResponsetok.metadata.ProductTypeSale == 'POSA')
            {
              PAN_TAG = '<PAN>' + jsonResponsetok.metadata.ActivationSerial + '</PAN>';
              CURRENTCY_TAG = '<CURRENCY>' + jsonResponsetok.metadata.CurrencyCodeProduct + '</CURRENCY>';
            }

        /*    if((jsonResponsetok._links.actions.href.includes('api.sandbox.checkout'))) {
              let test_tid = await getTestTID(req.hostname,jsonResponsetok.metadata.product);
              tidhead = '<TERMINALID>' + test_tid + '</TERMINALID>';
              console.log(log_prefix + 'Checkout sandbox payment confirmation received. Test TID will be used for SALE.' + log_suffix);
            }*/

       

            if(jsonResponsetok.metadata.africanID) {
                if((jsonResponsetok.metadata.africanID != 'none')&&(jsonResponsetok.metadata.africanID.length)) {
                  let gender = ((jsonResponsetok.metadata.title == 'Mr') ? 'm' : 'f' );
                  let areacode = jsonResponsetok.metadata.phone.substring(0,jsonResponsetok.metadata.phone.length-9);
                  let mobile = jsonResponsetok.metadata.phone.substring(jsonResponsetok.metadata.phone.length-9,jsonResponsetok.metadata.phone.length);
                  let AFRICANID_TAG = '<DATA name="AK_CUSTOMER_ID">' + jsonResponsetok.metadata.africanID + '</DATA>' 
                  + '<DATA name="AK_CUSTOMER_FIRST_NAME">' + jsonResponsetok.metadata.firstname + '</DATA>' 
                  + '<DATA name="AK_CUSTOMER_LAST_NAME">' + jsonResponsetok.metadata.lastname + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_EMAIL">' + jsonResponsetok.metadata.email + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_GENDER">' + gender + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_MOBILE_CODE">' + areacode + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_MOBILE_NUMBER">' + mobile + '</DATA>';

                  if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                    extrahead = extrahead.replace('</EXTRADATA>',AFRICANID_TAG+'</EXTRADATA>')
                  }
                  else {
                    extrahead = '<EXTRADATA>'+ AFRICANID_TAG + '</EXTRADATA>';
                  }
                 
                }

              }
            //Business in a box
            if(await isBusinesInABoxAkani(gtid,jsonResponsetok.metadata.ean,req)) {
              let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + jsonResponsetok.reference + '</DATA>';
              if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                extrahead = extrahead.replace('</EXTRADATA>',REFID_URL_TAG+'</EXTRADATA>')
              }
              else {
                extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
              }
              
            }

            const fetchOptions = {
              method: 'POST',

              body: '<REQUEST type="SALE" STORERECEIPT="1">' +
                '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
                '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                tidhead +
                cashierhead +
                '<TXID>' + (jsonResponsetok.reference.includes('EPAY-undefined') ? jsonResponsetok.reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): jsonResponsetok.reference) + '</TXID>' +
                '<USERNAME>' + userIdHost + '</USERNAME>' +
                '<CARD>' +
                PAN_TAG +
                eanhead +                  
                '</CARD>' +
                '<AMOUNT>'+ jsonResponsetok.amount +'</AMOUNT>' +
                '<Comment>' + 'PaymentMethod=card|</Comment>' +
                CURRENTCY_TAG +
                '<CONSUMER>' +
                '<NAME>' + jsonResponsetok.metadata.firstname + '</NAME>' +
                '<SURNAME>' + jsonResponsetok.metadata.lastname + '</SURNAME>' +
   
                send_sms_tag +
                send_email_tag +
                '<TITLE>' + jsonResponsetok.metadata.title + '</TITLE>' +
               
                '<CUSTOMERID>' + (jsonResponsetok.customer ? jsonResponsetok.customer.id : jsonResponsetok.metadata.email) + '</CUSTOMERID>' +
                '</CONSUMER>' +
                extrahead +
                '</REQUEST>',

              headers: {
                'Content-Type': 'application/xml',
              },
    
            }
          
            console.log(log_prefix + 'SALE Request: ' + UPInterfaceURL + log_suffix);


            mask_xml_data(fetchOptions.body,log_prefix,log_suffix);

          const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
          var jsonResponse = await response.text();

          jsonResponse = await updateRedeemptionURL(jsonResponse);

            const UUID = require('pure-uuid');
            const id = new UUID(4).format();
            let encyptBlockTime = getTimeStamp();
  
            let block =  id + '/' + jsonResponsetok.metadata.reference + '.pkpass' + ',' + encyptBlockTime;
            let token = encrypt(block);
            let jsonResponse_log = jsonResponse ;
            jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
            
            console.log(log_prefix + 'SALE Response:' + log_suffix);
  
            mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

           
            let encyptBlockTimeGMT = new Date();
            let passLink = 'https://' + req.hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();

            if(jsonResponse.includes('<RESULT>0</RESULT>'))
            {

              let serial_upload = '';
          
              if (jsonResponse.includes('<SERIAL>')) {
                let newarr = jsonResponse.split('<SERIAL>');
                if (newarr.length > 1) {
                  let arr1 = newarr[1].split('</SERIAL>');
                  serial_upload = arr1[0];
                }
              }
              let uploadTxn = await isUploadRequired(req);
              if(uploadTxn == 'yes')
              {
              await uploadTxnCarrefour(txnTime,jsonResponsetok.metadata.reference,serial_upload,
                jsonResponsetok.metadata.email,jsonResponsetok.metadata.phone,
                jsonResponsetok.metadata.firstname + ' ' + jsonResponsetok.metadata.lastname,
                jsonResponsetok.source.last4,jsonResponsetok.amount.toString(),jsonResponsetok.metadata.ean,
                jsonResponsetok.metadata.tid,jsonResponsetok.metadata.product,req,log_prefix,log_suffix);
              }

              let product_vat = '0';
                let item_code_vat_str = await getItemCode(req,jsonResponsetok.metadata.ean,jsonResponsetok.metadata.tid,log_prefix,log_suffix);
                if(item_code_vat_str.includes(',')) {
                   let a = item_code_vat_str.split(',');
                   if(a[1].length) {
                    product_vat = a[1];
                   }
                }

          
              let activation_serial_tag = '<ACTIVATIONSERIAL>' + jsonResponsetok.metadata.ActivationSerial + '</ACTIVATIONSERIAL>';
              let product_type_tag = '<PRODUCTTYPE>' + jsonResponsetok.metadata.ProductTypeSale + '</PRODUCTTYPE>';
              let discount_tag = '<PROMODISCOUNT>0</PROMODISCOUNT>';;
              let promo_tag = '<PROMOCODE>none</PROMOCODE>' ;
              let currency_tag = '<CURRENCYCODEP>'+ jsonResponsetok.metadata.CurrencyCodeProduct +'</CURRENCYCODEP>';
              let amount_part = (jsonResponsetok.status == 'Card Verified') ? '000' : jsonResponsetok.amount;
              let partial_tag = '<PARTIALPAY>'+ amount_part +'</PARTIALPAY>' ;
              if(jsonResponsetok.metadata.promoApplied == '1')
              {
                let promo_code = jsonResponsetok.metadata.promoCode;
                discount_tag = '<PROMODISCOUNT>' + jsonResponsetok.metadata.discount + '</PROMODISCOUNT>';
                promo_tag = '<PROMOCODE>' + 'xxxx' +promo_code.substring(promo_code.length - 4, promo_code.length) + '</PROMOCODE>';
                
              }

              let discRRP = await getDiscountRRP(jsonResponsetok.metadata.ean,gtid,req);

             let discountrrp_tag = '<PREDISCOUNTRRP>' + discRRP + '</PREDISCOUNTRRP>';

              jsonResponse = jsonResponse + '<CARDTYPE>' + jsonResponsetok.source.scheme + ' x' + jsonResponsetok.source.last4 + '</CARDTYPE>' +
                '<PAID>' + jsonResponsetok.metadata.amt + '</PAID>' + '<PRODUCT>' + jsonResponsetok.metadata.product + '</PRODUCT>' +
                '<SHORTDESC>' + shortdesciption + '</SHORTDESC>' + redeemptiondesciptiontag + longdescriptiontag + termstag + '<LOGO>' + jsonResponsetok.metadata.productlogo + '</LOGO>' +
                '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>' + '<URLREDEEM>' + jsonResponsetok.metadata.redeemURL + '</URLREDEEM>' +
                '<PASS>' + passLink + '</PASS>' + discount_tag + promo_tag + currency_tag + partial_tag + activation_serial_tag + product_type_tag +
                    '<VAT>' + product_vat + '</VAT>' + discountrrp_tag;     
        
              jsonResponse_log = jsonResponse ;
              jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

              mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
            }

            
            if (jsonResponse.includes('<RESULT>0</RESULT>')) {
              console.log(jsonResponsetok.metadata.reference);
              var strref = jsonResponsetok.metadata.reference;
              var arrRefSplit = strref.split('-');
              var actlink = jsonResponsetok.metadata.redeemURL;
              var productKey = '';
              var prodSerial = '';
              if (jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
                var newarr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
                if (newarr.length > 1) {
                  var arr1 = newarr[1].split('</DATA>');
                  actlink = arr1[0];
                }
              }

              if (jsonResponse.includes('<PIN>')) {
                var newarr = jsonResponse.split('<PIN>');
                if (newarr.length > 1) {
                  var arr1 = newarr[1].split('</PIN>');
                  productKey = arr1[0];
                }
              }

              if (jsonResponse.includes('<SERIAL>')) {
                var newarr = jsonResponse.split('<SERIAL>');
                if (newarr.length > 1) {
                  var arr1 = newarr[1].split('</SERIAL>');
                  prodSerial = arr1[0];
                }
              }
              var prodExpiry = '';
              if (jsonResponse.includes('<VALIDTO>')) {
                var newarr = jsonResponse.split('<VALIDTO>');
                if (newarr.length > 1) {
                  var arr1 = newarr[1].split('</VALIDTO>');
                  prodExpiry = arr1[0];
                  if (prodExpiry == '3000-01-01 00:00:00') {
                    prodExpiry = 'Never Expires';
                  }
                }
              }
          
              

        let emailToSend =  jsonResponsetok.metadata.email;
        let phoneToSend =  jsonResponsetok.metadata.phone;
        let emailTAG= '<EMAIL></EMAIL>';
        let phoneTAG = '<PHONE></PHONE>';
        if(emailToSend)
        {
          if(emailToSend.length > 0)
          {
              emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
          }
        }
        if(phoneToSend)
        {
          if(phoneToSend.length > 0)
          {
              phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
          }
        }

      
              if (((jsonResponsetok.metadata.product.includes('Renewal')) || jsonResponsetok.metadata.product.includes('renewal'))) {

                 console.log(jsonResponsetok._links.actions.href);
                 let auth_code = await getAuthCode(jsonResponsetok._links.actions.href,gtid,req.hostname,log_prefix,log_suffix,req);
                
                console.log(log_prefix + 'auth_code: ' + auth_code + log_suffix);
                
                if(auth_code != 'none')
                {
                  auth_code = '-' + auth_code;
                }
                else
                {
                  auth_code = '';
                }
                console.log(auth_code);

                const fetchOptionsInfo = {
                  method: 'POST',

                  body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
                    '<USERNAME>' + userIdHost + '</USERNAME>' +
                    '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                    tidhead +
                    '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
                    // '<TXID>' + inforef + '-' + jsonResponsetok.source.bin + auth_code + '</TXID>' +
                    '<TXID>' + (inforef.includes('EPAY-undefined') ? inforef.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): inforef)
                       + '</TXID>' + //+ '-' + jsonResponsetok.source.bin + auth_code
                    '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
                    '<SUBSCRIPTION>' +
                    '<TOKENID>' + jsonResponsetok.source.id + '</TOKENID>' +
                    '<LASTFOUR>' + jsonResponsetok.source.last4 + '</LASTFOUR>' +
                    '<CARDTYPE>' + jsonResponsetok.source.scheme + '</CARDTYPE>' +
                    '<PAYMENTID>' + jsonResponsetok.id + '</PAYMENTID>' +
                    emailTAG +
                    phoneTAG +
                    '<BIN>' + jsonResponsetok.source.bin + '</BIN>' +
                    '<AUTHCODE>' + auth_code.replace('-','') + '</AUTHCODE>' +
                    '</SUBSCRIPTION>' +
                    '<TRANSACTIONREF>' +
                    '<REFTYPE>SERIAL</REFTYPE>' +
                    '<REF>' + jsonResponsetok.metadata.reference + '</REF>' +
                    '</TRANSACTIONREF>' +
                    '</REQUEST>',

                  headers: {
                    'Content-Type': 'application/xml',
                  },
            
                }

            
              console.log(log_prefix + 'PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
              mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
              console.log(log_prefix + paymentInfoURL + log_suffix);
            const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
            var jsonResponseInfo = await response.text();
          
            console.log(log_prefix + 'PAYMENTINFO Response:' + log_suffix);
            let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
              mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);

              }

              try {
                const findRemoveSync = require('find-remove');
                let allowed_google = await getGooglePassAllowed(req.hostname);
                let allowed_apple = await getApplePassAllowed(req.hostname);
                if(allowed_google == 'yes') { 
                  let objGoogle = [];
                  objGoogle.push({
                  reference:jsonResponsetok.metadata.reference,
                  productLogo:jsonResponsetok.metadata.productlogo,
                  product:jsonResponsetok.metadata.product,
                  provider:jsonResponsetok.metadata.company,
                  serial:prodSerial,
                  expiry:prodExpiry,
                  amount:jsonResponsetok.metadata.amt,
                  pin:productKey,
                  //description:shortdesciption[0],
                  description:((shortdesciption[0].length > 1) ? shortdesciption[0]:shortdesciption),
                  tx_time:txnTime,
                  refSplit:arrRefSplit[1],
                  phone:jsonResponsetok.metadata.phone,
                  //terms:terms[0],
                  terms:((terms[0].length > 1) ? terms[0]:terms),
                  actlink:actlink,
                  providerLogo:jsonResponsetok.metadata.provLogo,
                  id:id,
                  stripe:''
                });
                await generateGooglePass(objGoogle[0]);
              // objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '/strip@2x.png';
              objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
              let googlePassUrl = await createPassObject(objGoogle);

                jsonResponse = jsonResponse + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
                console.log('Response GPass: ' + googlePassUrl);
                setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
              } else {
                jsonResponse = jsonResponse + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';
              }

            
                if(allowed_apple == 'yes')
                {
                  await generatePass(jsonResponsetok.metadata.productlogo, jsonResponsetok.metadata.reference, jsonResponsetok.metadata.product, prodSerial, prodExpiry, jsonResponsetok.metadata.amt, productKey,((shortdesciption[0].length > 1) ? shortdesciption[0]:shortdesciption), txnTime, arrRefSplit[1], jsonResponsetok.metadata.phone, ((terms[0].length > 1) ? terms[0]:terms), actlink, jsonResponsetok.metadata.provLogo, id);
                  setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
                }                 
                
               
              }
              catch (err)
              {
                console.log(log_prefix + err + log_suffix);
              }
              
              return jsonResponse;
              
            }
            else if(jsonResponse.includes('<RESULT>34</RESULT>')) {

              let session_id = 'SECURITY-ERROR';
              let host_log = req.hostname.split('.');
              let method = 'GET_AUTH_SALE_201';
              let log_prefix_block = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
              let log_suffix_block = '\n</LOG></SESSION_LOG>'; 
          
              let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid + ' Reason: GET_AUTH_SALE_201 Transaction Duplicated.'
              console.log(log_prefix_block + alert + log_suffix_block);
              if(BlockedIPs) {
                BlockedIPs = BlockedIPs + ',' + clientip;
              }else {
                BlockedIPs = clientip;
              }
              let resp = '<RESPONSE><RESULT>151</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT><HOME>'+jsonResponsetok.metadata.home+'</HOME><EAN>'+jsonResponsetok.metadata.ean+'</EAN></RESPONSE>';
              //res.send(resp);
              //return (jsonResponse + '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>');
              return resp;

            }
            else{
              let refund_status_card_txn = false;
              let refund_status_promo_txn = false;
              let refund_status = getMessageIDText('MESSAGEID_180',req) + await getCustomerName(req.hostname) + getMessageIDText('MESSAGEID_133',req);
              if(jsonResponsetok.metadata.partialPay != '0')
              {
                let act_id = await getActionIdCaptureCheckout(jsonResponsetok.id,log_prefix,log_suffix,jsonResponsetok.metadata.tid,req.hostname,req);
                if((act_id != 'none')&&(act_id.includes('act_')))
                {            
                  let response = await processRefundCheckout(jsonResponsetok.amount,jsonResponsetok.reference + '_r',act_id,jsonResponsetok.id,jsonResponsetok.metadata.ean,jsonResponsetok.metadata.tid,jsonResponsetok.reference,customer,log_prefix,log_suffix,req.hostname,req);
                  response = response.replace('</RESPONSE>','<CUSTOMER>' + customer + '</CUSTOMER></RESPONSE>');
                  console.log(log_prefix +  response + log_suffix);
                  if(response.includes('<RESULT>0</RESULT>'))
                  {
                    refund_status_card_txn = true;
                  }                 
                }
              }
              else {
                refund_status_card_txn = true;
              }
              if((jsonResponsetok.metadata.promoApplied == '1')&&(jsonResponsetok.metadata.discount != '0')) {
                let promocode = jsonResponsetok.metadata.promoCode;                 
                let a1 = tidhead.split('<TERMINALID>');
                let a2 = a1[1].split('</TERMINALID>');
                let tid_used = a2[0];
                  let result_refund_promo = await refundPromoDiscount(tid_used,jsonResponsetok.metadata.reference, promocode,log_prefix,log_suffix,req);
                  console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                  if(result_refund_promo.includes('<RESULT>0</RESULT>'))
                  {
                    refund_status_promo_txn = true;                  
                    
                  }  
                  
              } else {
                refund_status_promo_txn = true;
              }

              if((refund_status_card_txn == true) && (refund_status_promo_txn == true))
              {
                //refund_status = 'Your refund for this transaction is processed successfully.';
                refund_status = getMessageIDText('MESSAGEID_179',req);
              } 
              else {
                refund_status = getMessageIDText('MESSAGEID_180',req) + await getCustomerName(req.hostname) + getMessageIDText('MESSAGEID_133',req);
              }          
              

              jsonResponse = jsonResponse.replace('</RESULTTEXT>', '\n' + refund_status + '</RESULTTEXT>');
              return (jsonResponse + '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>');
            }

          }
      
        }
        else if (jsonResponsetok.approved == false) {
          console.log(log_prefix + 'notapproved' + log_suffix);
          if(jsonResponsetok.actions.length > 0)
          {
            let errorSharaf = '. '+ getMessageIDText('MESSAGEID_135',req);
              
            let errorText = await getCheckoutErrorResponse(jsonResponsetok,req);
            // jsonResponsetok.actions[0].type + getMessageIDText('MESSAGEID_136',req) + jsonResponsetok.actions[0].response_code + '. ' + jsonResponsetok.actions[0].response_summary + errorSharaf ;
            console.log(log_prefix + errorText + log_suffix);
            return ('<RESPONSE><RESULT>' + jsonResponsetok.actions[0].response_code + '</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT><EAN>'+jsonResponsetok.metadata.ean+'</EAN><HOME>'+jsonResponsetok.metadata.home+'</HOME></RESPONSE>');
          }
          else{
            let err = await getCheckoutErrorResponse(jsonResponsetok,req);
            if(err.length)
              err = Buffer.from(err).toString('base64');
            res.statusCode = 400;
            console.log(log_prefix + 'notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err + log_suffix);
            return ('notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err);
          }
          
        }
        else {
          console.log('failed1234');
          res.statusCode = 400;
          console.log(log_prefix + 'failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + log_suffix)
          return ('failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean);
        }


      

    
  
      }catch(err){
        let err_resp = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>';
        console.log(log_prefix+err_resp+log_suffix);
        console.log(log_prefix + err + log_suffix);
        return err_resp;
      }

}

async function isPromoPeriodApplicable(req) {
  let promo = 'no';
  let host = (req.hostname.split('.'))[0];
  if(req.hostname == DOMAIN_0) {
    promo = config['domain_0'].DISCOUNTRRP ? config['domain_0'].DISCOUNTRRP:'no';
  } else if(req.hostname == DOMAIN_1) {
   promo = config['domain_1'].DISCOUNTRRP ? config['domain_1'].DISCOUNTRRP:'no';
 } else if(req.hostname == DOMAIN_2) {
   promo = config['domain_2'].DISCOUNTRRP ? config['domain_2'].DISCOUNTRRP:'no';
 } else if(req.hostname == DOMAIN_3) {
   promo = config['domain_3'].DISCOUNTRRP ? config['domain_3'].DISCOUNTRRP:'no';
 } else if(config[host]) {
  if(config[host].DISCOUNTRRP) {
    promo = config[host].DISCOUNTRRP;
  }
}
 return promo;
} 


async function updateCatalogDataDiscountRRP(xml,req) {


  let finalxml = '';
   let rrp_enabled = await isPromoPeriodApplicable(req);
   if(xml.includes('</ARTICLE>')) {
      let a  =  xml.split('<ARTICLE ID=');   
      finalxml = finalxml + a[0]; 
      for(let i=1;i<a.length;i++) {
        let discountrrp = '0';
        if((a[i].includes('DISCOUNTRRP='))&&(rrp_enabled == 'yes')) {
            let r = a[i].split('DISCOUNTRRP=') 
            let r1 = r[1].split('<');
            if(r1[0].includes(',')) {
              let x = r1[0].split(',');
              discountrrp = x[0];
              
            } else {              
              discountrrp = r1[0];
            }
        
            discountrrp = discountrrp.replace('.','');
            if(a[i].includes('<AMOUNT CURRENCY=')) {
              let aa = a[i].split('<AMOUNT CURRENCY=');
              let bb = aa[1].split('</AMOUNT>');
              let amount_tag = bb[0];
              if(amount_tag.includes('MAXAMOUNT="')) {
                let cc  = amount_tag.split('MAXAMOUNT="');
                let dd = cc[1].split('"');
                if(Number(dd[0]) == 0) {
                  let ee = amount_tag.split('>');
                  let amount_ee = '>' + ee[1] + '</AMOUNT>';
                  let current = a[i].replace(amount_ee,'>' + discountrrp + '</AMOUNT>' + '<PREDISCOUNTRRP>' + ee[1] +'</PREDISCOUNTRRP>');
                  finalxml = finalxml + '<ARTICLE ID=' + current;
                }
              }
            }
        }else {
          let toadd = a[i].replace('</AMOUNT>', '</AMOUNT>\n\t<PREDISCOUNTRRP>none</PREDISCOUNTRRP>' )
          finalxml = finalxml + '<ARTICLE ID=' + toadd;
        }

      }
   } else {
    finalxml = xml;
   }

   return finalxml;
}

async function getDiscountRRP(ean,tid,req) {
  let discountrrp = 'none';

  let blockToParse = await getCatalog(req.hostname,tid,ean,0,req);                
                    
  if((blockToParse != 'no_data')&&(blockToParse.includes('<PREDISCOUNTRRP>')))
  {   
    let arr = blockToParse.split('<PREDISCOUNTRRP>');
    let arr_1 = arr[1].split('</PREDISCOUNTRRP>');
    discountrrp = arr_1[0];
  }
  return discountrrp;
}

async function getPaymentMethods(hostname) {
  let paysupported = '';
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    paysupported = payment_methods_supported_domain_0;

  }
  else if(hostname == DOMAIN_1)
  {
    paysupported = payment_methods_supported_domain_1;

  }
  else if(hostname == DOMAIN_3)
  {
    paysupported = payment_methods_supported_domain_3;

  }
  else if(hostname == DOMAIN_2)
  {
    paysupported = payment_methods_supported_domain_2;
    
  } else if(config[host]) {
    if(config[host].payment_methods) {
      paysupported = config[host].payment_methods;
    }
  }

  return paysupported;
}

async function validateRequestGetAuth(objStr,hostname,req,clientip,log_prefix,log_suffix) {
  try {
  console.log('=================Original Request from client=================');
  console.log(objStr);
  let obj = JSON.parse(objStr);
  let proxy = "no";
  if(!obj.metadata.flashVoucher) {
    obj.metadata['flashVoucher'] = 'none';
  }

  obj.reference = obj.reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req)));
  obj.metadata['reference'] = obj.reference;

  if((obj.metadata.promoCode)&&(obj.metadata.flashVoucher)) {

    if((obj.metadata.promoCode != 'none')&&(obj.metadata.flashVoucher != 'none')){

      let error_send = 'ERROR::::' +  JSON.stringify(
        {
            request_id: '46c52f94-49e0-4eb6-856e-b4e4bcfb1a3e',
            error_type: 'Sorry, promo discount is not applicable with this payment method.',
            error_codes: ['Please contact customer care for more info.'] 
        });
        console.log(error_send);
        return error_send;
        
    }

  }
  if((!obj.metadata.home)&&(!obj.metadata.redeemURL)&&(obj.metadata.promoCode.length > 0)) {
    //proxy = "yes";
      let tidL = '';
      if((obj.metadata.tid == '') || (obj.metadata.tid == 'undefined') || (obj.metadata.tid == 'notid'))
      {
        tidL = getDefaultTID(req.hostname,req);   
      } else {
        tidL = obj.metadata.tid;
      }
      let tidhead = '<TERMINALID>' + tidL + '</TERMINALID>';
      let cardStatus = await getPromoCardStatus(tidhead,obj.reference + '_DS',obj.metadata.promoCode,log_prefix,log_suffix,clientip,req);
      console.log(cardStatus);
      if((cardStatus.includes('<RESULT>0</RESULT>'))&&(cardStatus.includes('<ATTRIBUTE NAME="PROXY'))) {
        proxy = 'yes';
      }
    
  }
  
  
  delete obj.metadata['provLogo'];
  delete obj.metadata['company'];
  delete obj.metadata['product_type'];
  delete obj.metadata['productlogo'];
  delete obj.metadata['provider'];
  delete obj.metadata['product'];
  delete obj.metadata['amt'];
  delete obj.metadata['partialPay'];
  delete obj.metadata['promoApplied'];
  delete obj.metadata['discount'];
  delete obj.metadata['ProductTypeSale'];
  delete obj.metadata['CurrencyCodeProduct'];

  console.log('=================Removed product info from Request from client=================');
  console.log(JSON.stringify(obj));

  let amount_fv = obj.amount;
  
  let ean = obj.metadata.ean;

  let promoCode = obj.metadata.promoCode;


  if((obj.metadata.tid == '') || (obj.metadata.tid == 'undefined') || (obj.metadata.tid == 'notid'))
  {
    obj.metadata.tid = getDefaultTID(req.hostname,req);   
  }

  let tid = obj.metadata.tid;

  let error_send = 'ERROR::::' +  JSON.stringify(
    {
        request_id: '46c52f94-49e0-4eb6-856e-b4e400bb1a3e',
        error_type: getMessageIDText('MESSAGEID_118',req),
        error_codes: [' '] 
    });


  let eanInfo = await getCatalog(hostname,tid,ean,0,req); 
  console.log(eanInfo);
  if(eanInfo != 'no_data') {
     console.log('step 1');
    if(eanInfo.includes('<MEDIA>')) {
      let arr_media = eanInfo.split('<MEDIA>');
      let arr_media_1 = arr_media[1].split('</MEDIA>');
      let media = arr_media_1[0];

      let provider_logo1 = '';
      let provider_logo2 = '';
      let provider_logo_default = 'https://' + hostname + '/static/media/epay_default.png';
      console.log('step 2');
      let prodType = '0';
      let partialPay = '0';
      let company = '';
      let minamount = '0';
      let maxamount = '0';
      let product_name = '';
      let amt = '';
      let amount_long_fv = '';
      let currency_num = '';
      let type = 'PIN';
      let provider_ean = '';


      let product_logo1 = '';
      let product_logo2 = '';
      let product_logo_default = 'https://' + hostname + '/static/media/epay_default.png';

      if(media.includes('<PROVIDER_LOGO>')) {
        let pl  = media.split('<PROVIDER_LOGO>');
        let pl_1 = pl[1].split('</PROVIDER_LOGO>');
        provider_logo1 = pl_1[0];
      }
console.log('step 3');
      if(media.includes('<PROVIDER>')) {
        let pl  = media.split('<PROVIDER>');
        let pl_1 = pl[1].split('</PROVIDER>');
        provider_logo2 = pl_1[0];
      }

      if(media.includes('<ARTICLE_IMAGE>')) {
        let pl  = media.split('<ARTICLE_IMAGE>');
        let pl_1 = pl[1].split('</ARTICLE_IMAGE>');
        product_logo1 = pl_1[0];
      }

      if(media.includes('<LOGO>')) {
        let pl  = media.split('<LOGO>');
        let pl_1 = pl[1].split('</LOGO>');
        product_logo2 = pl_1[0];
      }

      let product_logo = '';
      let provider_logo = '';

      if(product_logo1.length) {
        product_logo = product_logo1;
      } else if(product_logo2.length) {
        product_logo = product_logo2;
      }else {
        product_logo = product_logo_default;
      }

      if(provider_logo1.length) {
        provider_logo = provider_logo1;
      } else if(provider_logo2.length) {
        provider_logo = provider_logo2;
      }else {
        provider_logo = provider_logo_default;
      }
       
      let desc_info = await getDescriptionInfo(eanInfo,hostname,ean,req);        
      let add_info = '';
      console.log(desc_info);
      if(desc_info.includes('<ADD_INFO>'))
      {
        let arr = desc_info.split('<ADD_INFO>');
        let arr1 = arr[1].split('</ADD_INFO>');
    
        add_info = arr1[0];
        console.log(add_info);

        if(add_info.includes('<COMPANY>')) {
          arr = add_info.split('<COMPANY>');
          arr1 = arr[1].split('</COMPANY>');
          company = arr1[0];
        }

        
         
        if(add_info.includes('<MINAMOUNT>')) {
          arr = add_info.split('<MINAMOUNT>');
          arr1 = arr[1].split('</MINAMOUNT>');
          minamount = arr1[0];
        }

        if(add_info.includes('<MAXAMOUNT>')) {
          arr = add_info.split('<MAXAMOUNT>');
          arr1 = arr[1].split('</MAXAMOUNT>');
          maxamount = arr1[0];
        }
        
        if(Number(maxamount) > 0) {
          prodType = '1';
        }
        
        if(add_info.includes('<PRODUCT_INFO>')) {
          arr = add_info.split('<PRODUCT_INFO>');
          arr1 = arr[1].split('</PRODUCT_INFO>');
          product_name = arr1[0];
          product_name = product_name.replace(',','.');
        }

        if(add_info.includes('<AMT_INFO>')) {
          arr = add_info.split('<AMT_INFO>');
          arr1 = arr[1].split('</AMT_INFO>');
          amt = arr1[0];          
         }

         if(add_info.includes('<CURRENCY>')) {
          arr = add_info.split('<CURRENCY>');
          arr1 = arr[1].split('</CURRENCY>');
          currency_num = arr1[0];
          
        }

        
        
        if(prodType == '1' ) {
          let currencycode = 'AED';
          let country_code = await getCountryCode(req.hostname);
          if(country_code == 'ZA') {
            currencycode = 'ZAR';
          } else if(country_code == 'TR') {
            currencycode = 'TRY';
          } else if(country_code == 'SA') {
            currencycode = 'SAR';
          }
          let cc = require('currency-codes');
          if(currency_num.length > 0) {
            currencycode = cc.number(currency_num).code;
          }
          let getSymbolFromCurrency = require('currency-symbol-map');
          let symbol = getSymbolFromCurrency(currencycode);
          if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
            symbol = '\u{2800}';
          }
          let str = obj.amount;
          let str1 = '';

          if (str == 0) {
             str1 = symbol + '0.00';
          }
          else {
             str1 = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
          }

          if (product_name.toString().includes('1 Month Renewal')) {
             
            str1 = str1 + ' per month';
          }
          else
           if (product_name.toString().toLowerCase().includes('12 month renewal') || product_name.toString().toLowerCase().includes('12 months renewal') || product_name.toString().includes('1 year renewal')) {
              str1 = str1 + ' per year';
           }

           amt = str1;

        } 

        
       
        
        if(add_info.includes('<AMOUNT_INFO>')) {
          arr = add_info.split('<AMOUNT_INFO>');
          arr1 = arr[1].split('</AMOUNT_INFO>');
          amount_long_fv = arr1[0];
          
        }

        if(add_info.includes('<CURRENCY>')) {
          arr = add_info.split('<CURRENCY>');
          arr1 = arr[1].split('</CURRENCY>');
          currency_num = arr1[0];
          
        }

        if(add_info.includes('<TYPE>')) {
          arr = add_info.split('<TYPE>');
          arr1 = arr[1].split('</TYPE>');
          type = arr1[0]; //PIN/POSA
          
        }

        if(add_info.includes('<PROVIDEREAN>')) {
          arr = add_info.split('<PROVIDEREAN>');
          arr1 = arr[1].split('</PROVIDEREAN>');
          provider_ean = arr1[0];           
        }

        
        

      }

    
      let promoConfigValue =  await getPaymentMethods(req.hostname);
      let promoEnabled = 'no';
      if(promoConfigValue.includes('redeem')) {
        promoEnabled = 'yes';
      }

   

      if(Number(maxamount) > 0) {
        
        amount_long_fv = obj.amount;

        if((Number(amount_long_fv) < Number(minamount)||(Number(amount_long_fv) > Number(maxamount)))) {
          //return error amount is not in range / also check MAXAMOUNT in config for domain
          
            let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_SALE Variable product range check failed'
            console.log(log_prefix + alert + log_suffix);
            if(BlockedIPs) {
              BlockedIPs = BlockedIPs + ',' + clientip;
            }else {
              BlockedIPs = clientip;
            }
            return error_send;
        }
      }

      partialPay = amount_long_fv;
      

      let discount = '0';
      let promoApplied = '0';

      if((obj.metadata.promoCode) && (obj.metadata.promoCode.length) && (obj.metadata.promoCode != 'none')&&(redeem_option == '1')&&(promoEnabled == 'yes')) 
      {
          let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';                
          let cardStatusResponse = await getPromoCardStatus(tidhead,obj.reference + '_DS',obj.metadata.promoCode,log_prefix,log_suffix,clientip,req);
             console.log(cardStatusResponse);
            if(((cardStatusResponse.includes('<RESULT>0</RESULT>'))&&(cardStatusResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')))&&(cardStatusResponse.includes('<BALANCE>'))&&(!cardStatusResponse.includes('<ATTRIBUTE NAME="PROXY'))) {
            let a1 = cardStatusResponse.split('<BALANCE>');
            let a2 = a1[2].split('</BALANCE>');
            let balance= a2[0];
            console.log('promo balance: ' + balance); 
            if(Number(amount_long_fv) >= Number(balance)) {
              discount = Number(balance).toString();
              partialPay = (Number(amount_long_fv) - Number(balance)).toString();
            }
            else {
              partialPay = '0';
              discount = amount_long_fv;
            }

            promoApplied = '1';
            proxy = 'no';
          }
          else if(((cardStatusResponse.includes('<RESULT>0</RESULT>'))&&(cardStatusResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>')))&&(cardStatusResponse.includes('<ATTRIBUTE NAME="PROXY'))) {
              proxy = 'yes';
          }
          else {
            if(proxy == 'no') {
            console.log('Invalid promocode !!');
            //send error resp           
             
              let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_SALE Invalid promo code.'
              console.log(log_prefix + alert + log_suffix);
              if(BlockedIPs) {
                BlockedIPs = BlockedIPs + ',' + clientip;
              }else {
                BlockedIPs = clientip;
              }
              return error_send;
            } else {
                let error = JSON.stringify(
                {
                  request_id: '153',
                  error_type: getMessageIDText('MESSAGEID_166',req),
                  error_codes: [getMessageIDText('MESSAGEID_167',req)]
                });
                console.log(log_prefix + error + log_suffix);
                return 'ERROR::::' + error;

            }
          }

      }

      if(proxy != 'yes') {
      
      obj.metadata['provLogo'] = provider_logo;
      obj.metadata['productlogo'] = product_logo;
      obj.metadata['product_type'] = prodType;
      obj.metadata['provider'] = provider_ean;
      obj.metadata['company'] = company;
      obj.metadata['product'] = product_name;
      obj.metadata['amt'] = amt;
      obj.metadata['ProductTypeSale'] = type;
      obj.metadata['CurrencyCodeProduct'] = currency_num;
      obj.metadata['partialPay'] = partialPay;
      obj.amount = obj.metadata.partialPay;
      
      
      
      obj.metadata['discount'] = discount;
      obj.metadata['promoApplied'] = promoApplied;
      }
      
      obj.currency = 'AED';
      let country_code = await getCountryCode(req.hostname);
      if(country_code == 'ZA') {
        obj.currency = 'ZAR';
      }else if(country_code == 'TR') {
        obj.currency = 'TRY';
      }else if(country_code == 'SA') {
        obj.currency = 'SAR';
      }
      obj.merchant_initiated = false;
      if(product_name) {
      if(product_name.toLowerCase().includes('renewal')) {
        obj.payment_type = 'Recurring';        
      } else {
        obj.payment_type = 'Regular'; 
      }
    }

    

      if(proxy == "yes") {
        obj.metadata.partialPay = '0';
        obj.metadata.discount = '0';
        obj.amount = 0;
        obj.metadata['product'] = 'Renewal';
     }
      obj.source.stored = false;
      obj.source.store_for_future_use = true;
      obj.source.type = "token";
      
      if((Number(obj.amount) + Number(obj.metadata.discount)) != amount_fv) {
          let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_SALE Amount mismatch!!'
          console.log(log_prefix + alert + log_suffix);
          if(BlockedIPs) {
            BlockedIPs = BlockedIPs + ',' + clientip;
          }else {
            BlockedIPs = clientip;
          }
          return error_send;
      }

      let key = "processing_channel_id";
      let credential = await getCheckoutCredentials(req.hostname,req);
        console.log('credential received:');
        // console.log(credential);
        if(credential.processingChannelID.length)
        {
          obj.processing_channel_id = credential.processingChannelID;
        }
        else {
          delete obj[key];
        }

        obj["3ds"].enabled = true;
        obj["3ds"].attempt_n3d = false;


        obj.customer.phone.country_code = '+' + obj.customer.phone.country_code;
        
       if(obj.source.token) {
        if(obj.source.token.includes('::::')) {
          let tok = obj.source.token;
          let a = tok.split('::::');
          obj.source.token = a[0];
        } 
       }



       let url_host_arr = obj.success_url.split('?');
       let req_hostname = req.hostname;

       // azure test start // TEST_IP_AZURE
       if(req.headers.referer.includes('endlessaisle.epayworldwide.com/akani')) {
        req_hostname = req_hostname + '/akani';
       } else if(req.headers.referer.includes('endlessaisle.epayworldwide.com/android')) {
        req_hostname = req_hostname + '/android';
       } else if(req.headers.referer.includes('endlessaisle.epayworldwide.com/alt')) {
        req_hostname = req_hostname + '/alt';
       } else if(req.headers.referer.includes('endlessaisle.epayworldwide.com/carrefour')) {
        req_hostname = req_hostname + '/carrefour';
       } else if(req.headers.referer.includes('endlessaisle.epayworldwide.com/turkey')) {
        req_hostname = req_hostname + '/turkey';
       // obj.metadata.amt.replace('??','?');
       }

       // azure test end //
       
       let success_url_host_new = 'https://' + req_hostname +  '?' + url_host_arr[1] ;
       success_url_host_new = success_url_host_new.replaceAll('amp2rep','&');
       console.log('success_url_host_new: ' + success_url_host_new);
       console.log('obj.success_url: ' + obj.success_url);


       let temp_url_arr = success_url_host_new.split('&gTID=');
       let temp_url = temp_url_arr[0];
       let mode_redirect = '';


       if(proxy == 'yes') {
        mode_redirect = '&mode=proxy'
       } else if(obj.metadata.instore == '1') {
         mode_redirect = '&mode=instore'
       } else if(obj.metadata.instore == '2') { //reward auth
        mode_redirect = '&mode=reward'
      }else if(obj.metadata.flashVoucher != 'none') {
        mode_redirect = '&mode=flash'
       }

      let final_url = temp_url + '&gTID=' + obj.metadata.tid + mode_redirect;

      if(obj.metadata.instore == '2') { //reward auth test
          
        if(TEST_IP_AZURE == clientip) {
            final_url = final_url.replace('.com','.com/tc');
        }else {
           final_url = final_url.replace('.com','.com/promoter');
        }
      }

      obj.success_url = final_url;
      obj.failure_url = final_url;
      obj.cancel_url = final_url;

      let paymentConfig =  await getPaymentMethods(req.hostname);
      
      if((!paymentConfig.includes('barcode'))&&(obj.metadata.instore != '2')) {
        obj.metadata.instore = '0';
      }


        
        console.log(log_prefix + '=================Validated product info in Request from client=================' + log_suffix);
        console.log(log_prefix + JSON.stringify(obj) + log_suffix);
        let validatedRespose = JSON.stringify(obj);
        return validatedRespose;
    }

  } else if(proxy == 'yes') {

    obj.metadata.partialPay = '0';
    obj.metadata.discount = '0';
    obj.amount = 0;
    obj.metadata['product']='Renewal';

    obj.source.stored = false;
    obj.source.store_for_future_use = true;
    obj.source.type = "token";

    let key = "processing_channel_id";
      let credential = await getCheckoutCredentials(req.hostname,req);
        console.log('credential received:');
 
        if(credential.processingChannelID.length)
        {
          obj.processing_channel_id = credential.processingChannelID;
        }
        else {
          delete obj[key];
        }

        obj["3ds"].enabled = true;
        obj["3ds"].attempt_n3d = false;


        obj.customer.phone.country_code = '+' + obj.customer.phone.country_code;
        
       if(obj.source.token) {
        if(obj.source.token.includes('::::')) {
          let tok = obj.source.token;
          let a = tok.split('::::');
          obj.source.token = a[0];
        } 
       }

       let temp_url_arr = obj.success_url.split('&gTID=');
       let temp_url = temp_url_arr[0];
       let mode_redirect = '&mode=proxy'; 
       
       if(TEST_IP_AZURE == clientip) {
          
            if((req.headers.referer.includes('endlessaisle.epayworldwide.com/alt')||(req.headers.referer.includes('endlessaisle.epayworldwide.com/mcafee')))) {
              temp_url = temp_url.replace('endlessaisle.epayworldwide.com','endlessaisle.epayworldwide.com/alt');
              if(req.headers.referer.includes('endlessaisle.epayworldwide.com/mcafee')) {
                temp_url = temp_url.replace('alt','mcafee');

              }
            }

            if(req.headers.referer.includes('endlessaisle.epayworldwide.com/carrefour')) {
        
              temp_url = temp_url.replace(req.hostname,req.hostname + '/carrefour');
            }
       }
       
       if(req.headers.referer.includes('/redeem')) {
        
        temp_url = temp_url.replace(req.hostname,req.hostname + '/redeem');
        
       }
       
       
      let final_url = temp_url + '&gTID=' + obj.metadata.tid + mode_redirect;

      obj.success_url = final_url;
      obj.failure_url = final_url;
      obj.cancel_url = final_url;      
        
       if(obj.metadata.instore != '2')
            obj.metadata.instore = '0';
    


        
        console.log(log_prefix + '=================Validated product info in Request from client=================' + log_suffix);
        console.log(log_prefix + JSON.stringify(obj) + log_suffix);
        let validatedRespose = JSON.stringify(obj);
        return validatedRespose;

  } else {

    let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_SALE EAN info missing in catalog.'
    console.log(log_prefix + alert + log_suffix);
    if(BlockedIPs) {
      BlockedIPs = BlockedIPs + ',' + clientip;
    }else {
      BlockedIPs = clientip;
    }
    return error_send;

  }
 }catch(err) {
  console.log(err);
   let error = JSON.stringify(
    {
      request_id: '102',
      error_type: getMessageIDText('MESSAGEID_134',req),
      error_codes: [getMessageIDText('MESSAGEID_104',req)]
    });
    console.log(log_prefix + error + log_suffix);
    return 'ERROR::::' + error;

 }


}

async function isIPBlocked(ip,hostname,req)
{

  const clientip = req.headers['incap-client-ip'] ;
  var txid = getTimeStamp();
  var x = Math.random() * 1000000000;    
  var y = x.toString().split('.');  
  txid =  'EPAY-' + '00000000'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
  

  let session_id = txid;
  let host_log = req.hostname.split('.');
  let method = 'BLOCKED_IP_CHECK';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';

 
    if(BlockedIPs)
    {
      if(BlockedIPs.includes(ip))
      {
          console.log( log_prefix + 'IP blocked: ' + ip + log_suffix);
          return true;
      }
      else 
      {    
        
        return false;
      }
    }
    else
       return false;
  
  
}

async function getFlashCredentialsAkani(hostname) {

  try {
      let flash_host = '';
      let host_a = hostname.split('.');
      let host = host_a[0];
      if(hostname == DOMAIN_0) {
        flash_host = 'domain_0';
      } else if(hostname == DOMAIN_1) {
        flash_host = 'domain_1';
      } else if(hostname == DOMAIN_2) {
        flash_host = 'domain_2';
      }else  if(hostname == DOMAIN_3) {
        flash_host = 'domain_3';
      } else if(config[host]) {
        flash_host = host;
      } else {
        return null;
      } 

      let obj = {
        flash_url_token: config[flash_host].flash_url_token,
        flash_url_redeem: config[flash_host].flash_url_redeem,
        flash_url_refund: config[flash_host].flash_url_refund,
        flash_authorisation: config[flash_host].flash_authorisation,
        flash_accountnumber: config[flash_host].flash_accountnumber
      }  

      return obj;
    } catch(err) {
      console.log(err);
      return null;
    }
}

async function processAkaniPayment(obj,req,clientip,log_prefix,log_suffix) {
  try {
  let responseCode = '';
  let responseMessage = '';

  let flash_cred = await getFlashCredentialsAkani(req.hostname);
  console.log(flash_cred);
  if(flash_cred) {
  const fetchOptions_token = {
    method: 'POST',
    body: new URLSearchParams ({
      grant_type: 'client_credentials'
    }),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',      
      'Authorization': 'Basic ' +  flash_cred.flash_authorisation
    },
    
  }
  console.log(log_prefix + 'Flash token request: ' + JSON.stringify(fetchOptions_token) + log_suffix);

  if(clientip == TEST_IP_AZURE) {
    let resp = {
      responseCode: 0,
      responseMessage: 'Success'
    }
    console.log('Harcoded flash payment response: ' + JSON.stringify(resp));
    return resp;
 }


//============================================================
  const responsetok = await fetch(flash_cred.flash_url_token, fetchOptions_token,proxy_url);
  console.log(log_prefix + 'Flash voucher payment token status code: ' + responsetok.status + log_suffix);
  if(responsetok.status == 200) {

   const jsonResponse_token = await responsetok.json();
   console.log(log_prefix + 'Flash token response: ' +  JSON.stringify(jsonResponse_token) + log_suffix);

   const fetchOptions_redeem = {
    method: 'POST',
    body: JSON.stringify( {
      "reference":obj.reference + '-ak',
      "accountNumber":flash_cred.flash_accountnumber,
      "pin":obj.metadata.flashVoucher.replaceAll('-',''),      
      "amount": Number(obj.metadata.partialPay)
  
    }),
    headers: {
      'Content-Type': 'application/json',      
      'Authorization': 'Bearer ' +  jsonResponse_token.access_token
    },
    
  }
  console.log(log_prefix + 'Flash redeem request: ' + JSON.stringify(fetchOptions_redeem) + log_suffix);
   const response = await fetch(flash_cred.flash_url_redeem, fetchOptions_redeem,proxy_url);
   console.log(log_prefix + 'Flash voucher redeem status code: ' + response.status + log_suffix);
   if(response.status == 200) {

      let jsonResponse_redeem = await response.json();
      jsonResponse_redeem['access_token'] = jsonResponse_token.access_token;
      console.log(log_prefix + 'Flash redeem response: ' +  JSON.stringify(jsonResponse_redeem) + log_suffix);
      
      return jsonResponse_redeem;
   } else {
    responseCode = response.status;
    responseMessage = getMessageIDText('MESSAGEID_168',req)
   }
  } else {
    responseCode = responsetok.status;
    responseMessage = getMessageIDText('MESSAGEID_168',req)
  }

  } else {
    responseCode = '137';
    responseMessage = getMessageIDText('MESSAGEID_169',req)
  }

    let resp_failure = {
      "responseCode": responseCode,
      "responseMessage":responseMessage
    }
    console.log(log_prefix + 'Flash redeem response (failed): ' +  JSON.stringify(resp_failure) + log_suffix);
    return resp_failure;
  }catch(err) {
    console.log(log_prefix + JSON.stringify(err) + log_suffix);
    let resp_failure = {
      "responseCode": "102",
      "responseMessage":getMessageIDText('MESSAGEID_165',req)
    }
    console.log(log_prefix + 'Flash redeem response (Exception): ' +  JSON.stringify(resp_failure) + log_suffix);
    return resp_failure;

  }
}


async function processRefundAkaniVoucher(akani,obj,req,clientip,log_prefix,log_suffix) {
  try {

    if(clientip == TEST_IP_AZURE) {
      let resp = {
        responseCode: 0,
        responseMessage: 'Success'
      }
      console.log('Harcoded flash refund response: ' + JSON.stringify(resp));
      return resp;
   }
  
    let responseCode = '';
    let responseMessage = '';

    let flash_cred = await getFlashCredentialsAkani(req.hostname);
    if(flash_cred) {
      const fetchOptions_refund = {
        method: 'POST',
        body: JSON.stringify( {
          "reference":obj.reference + '-akr',
          "originalReference":akani.reference,
          "accountNumber":flash_cred.flash_accountnumber

      
        }),
        headers: {
          'Content-Type': 'application/json',      
          'Authorization': 'Bearer ' +  akani.access_token
        },
        
      }
      console.log(log_prefix + 'Flash reversal request: ' + JSON.stringify(fetchOptions_refund) + log_suffix);
      const response = await fetch(flash_cred.flash_url_refund, fetchOptions_refund,proxy_url);
      console.log(log_prefix + 'Flash reversal status code: ' +  response.status  + log_suffix);
      if(response.status == 200) {
    
          const jsonResponse_refund = await response.json();
          console.log(log_prefix + 'Flash reversal response: ' + JSON.stringify(jsonResponse_refund)  + log_suffix);
          return jsonResponse_refund;
      } else {
        responseCode = response.status;
        responseMessage = getMessageIDText('MESSAGEID_168',req)
      }
    } else {
      responseCode = '137';
      responseMessage = getMessageIDText('MESSAGEID_169',req)
    }

    let resp_failure = {
      "responseCode": responseCode,
      "responseMessage":responseMessage
    }
    console.log(log_prefix + 'Flash reversal response (failure): ' + JSON.stringify(resp_failure)  + log_suffix);
    return resp_failure;
  }catch(err) {
    console.log(log_prefix + 'Flash reversal (exception info): ' + JSON.stringify(err)  + log_suffix);
    let resp_failure = {
      "responseCode": "102",
      "responseMessage":getMessageIDText('MESSAGEID_165',req)
    }
    console.log(log_prefix + 'Flash reversal response (exception): ' + JSON.stringify(resp_failure)  + log_suffix);
    return resp_failure;

  }

}

async function getDomainCheckoutErrorsRetry(req){

  let result = null;

  let host = (req.hostname.split('.'))[0];

  if(req.hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].RETRY_CHECKOUT_CODES) {
      result = config['domain_1'].RETRY_CHECKOUT_CODES;
    }
   }
  }
  else if(req.hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].RETRY_CHECKOUT_CODES) {
        result = config['domain_2'].RETRY_CHECKOUT_CODES;
      }
    }
  }
  else if(req.hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].RETRY_CHECKOUT_CODES) {
        result = config['domain_3'].RETRY_CHECKOUT_CODES;
      }
    }
  }
  else if(req.hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].RETRY_CHECKOUT_CODES) {
        result = config['domain_0'].RETRY_CHECKOUT_CODES;
      }
    }
  } else if(config[host]) {
    if(config[host].RETRY_CHECKOUT_CODES) {
      result = config[host].RETRY_CHECKOUT_CODES;
    }
  }

  return result;
   

}

var testUAENumberRegex = /^5(0|1|2|4|5|6|8)\d{7}$/

app.get('/getAuth', cors(corsOptions), limiter_amount_mismatch, limiter, async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getAuth => clientip: ' + clientip);
  console.log(req.headers);
console.log('req.query.body');
console.log(req.query.body);
    
  let isIpBlocked = await isIPBlocked(clientip,req.hostname,req);
if(isIpBlocked) {
   let err = JSON.stringify(
   {
       request_id: '46c52f94-49e0-4eb6-856e-b4e400bb7be6',
       error_type: getMessageIDText('MESSAGEID_118',req),
       error_codes: [' '] 
   });

   res.send(err);
   return;
}

  let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
  if(isIpTrusted)
  {

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {

        //var body = req.query.body;
        var body = Buffer.from(req.query.body,'base64').toString('utf8');  
        /////////////////////////////////////
         let obj_int = JSON.parse(body);
         if(obj_int.metadata.enc) {//enc check
            let card_data  = decrypt(obj_int.metadata.enc) ;
            let x = card_data.split('<LOGINTIME>');
  	    let y = x[1].split('</LOGINTIME>');
            let loginTime = y[0];
            let timeout = await getDomainIdleTimeout(req.hostname);

            if(( txid - Number(loginTime)) > Number(timeout) ) {
                let resp = '<RESPONSE><RESULT>1202</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_109',req)+'</RESULTTEXT></RESPONSE>';
                res.send(resp);
                return;
            }           
         }
         ///////////////////////////////////////
         if(!obj_int.reference.includes('EPAY-'))
         {
            obj_int.reference = 'EPAY-' + obj_int.reference;
         }
         let session_id = obj_int.reference.replace('EPAY-undefined','EPAY-'+getDefaultTID(req.hostname,req));
         let host_log = req.hostname.split('.');
         let method = 'GET_AUTH_SALE';
         let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         let log_suffix = '\n</LOG></SESSION_LOG>';

        let pay_methods =  await getPaymentMethods(req.hostname);
  
  /*    if(((await getCountryCode(req.hostname)) == 'AE')&&(!req.headers.referer.includes('/akani'))) {  
      var uaePhoneTest = testUAENumberRegex.test(obj_int.customer.phone.number);
      console.log('testUAENumberRegex Result: '+ uaePhoneTest);
      if(!((obj_int.customer.phone.country_code == '971')&&(uaePhoneTest))) {
        let err = JSON.stringify(
          {
              request_id: '46c52f94-49e0-4eb6-856e-b4e400bb7be6',
              error_type: 'Only UAE phone number is allowed.',
              error_codes: ['Please change phone number to continue.'] 
          });
       
          res.send(err);
          return;

      }
      }*/
       
        let response_validation = await validateRequestGetAuth(body,req.hostname,req,clientip,'','');
        console.log(log_prefix + response_validation + log_suffix);
        if(response_validation.substring(0,9) == 'ERROR::::') {
          let error_send = response_validation.substring(9,response_validation.length);
          res.send(error_send);
          return;
        } 

        
        /////////////////////////////////////
        var obj = JSON.parse(response_validation);
        //var obj = JSON.parse(body);
        
        console.log(log_prefix +  obj + + log_suffix);
        if(!obj.reference.includes('EPAY-'))
        {
          obj.reference = 'EPAY-' + obj.reference;
        }
        
          console.log(log_prefix + req.headers.campaign + '>>API_CALL:getAuth => clientip: ' + clientip + log_suffix);
         console.log(log_prefix + 'Request Body Received from Client App:' + log_suffix);
         
         mask_json_data(body, log_prefix, log_suffix);

         console.log(log_prefix + '================Client request validated object=======================' + log_suffix);
         mask_json_data(response_validation, log_prefix, log_suffix);

        console.log('testing 2');
        var ean = obj.metadata.ean;

        
       
        currentDate = getFormattedTime();
        var txid = getTimeStamp();


        var x = Math.random() * 1000000;

        var y = x.toString().split('.');

        txid = txid + y[0];
        

        var tidhead = '<TERMINALID>'+ obj.metadata.tid + '</TERMINALID>';

        if((obj.metadata.tid == '') || (obj.metadata.tid == 'undefined') || (obj.metadata.tid == 'notid'))
        {
          let gtid = getDefaultTID(req.hostname,req);
          tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
        }

        let up_cred = await getUPCredentials(req);

        var userIdHost = up_cred.userIdHost;
        var userPaswdHost = up_cred.userPaswdHost;    


        

 
          {
            var amount = (Number(obj.metadata.partialPay) + Number(obj.metadata.discount)).toString();
            let tid_used = obj.metadata.tid ;

            if((obj.metadata.tid == '') || (obj.metadata.tid == 'undefined') || (obj.metadata.tid == 'notid'))
            {
              let gtid = getDefaultTID(req.hostname,req);
              tid_used =  gtid ;
            }
            
            let secret_checkout = '';
            let use_checkout_url = '';
            let bearer = '';
            let cred = await getCheckoutCredentials(req.hostname,req);
            if(cred)
            {
              secret_checkout = cred.CheckoutSecretKey;
              use_checkout_url = cred.url;
              bearer = cred.prefix;
            }
            //////////////////////////////
           // let instore_txn = '0';
           // if(obj.metadata.instore)
           // {
           //   instore_txn = obj.metadata.instore;
           // }


            let instore_txn = '0';
            let reward_txn = '0';  //reward auth
            if(obj.metadata.instore)
            {
                if(obj.metadata.instore == '2' ){
                  instore_txn = '0';
                  obj.metadata.instore = '0';
                 // obj.metadata.discount = obj.metadata.partialPay;
                 // obj.metadata.partialPay = '0';
                  reward_txn = '1';
                } else            
                   instore_txn = obj.metadata.instore;               
            }
            console.log('checking process+++++++++++++_____________');
            console.log(obj);
            if(obj.metadata.partialPay) {
            if((obj.metadata.discount != '0')&&(obj.metadata.promoApplied == '1')&&((instore_txn == '0')||(reward_txn == '1'))) {
                let result = await chargePromoCode(tid_used,obj.metadata.promoCode,obj.metadata.discount,obj.metadata.reference,log_prefix,log_suffix,amount,req.hostname,clientip,req);
                console.log('Result Charge: ' + result);
console.log(obj);
               // let instore_txn = '0';
                
		            if((obj.metadata.discount == amount)&&(obj.metadata.partialPay == '0')&&( result == 'Success')&&(!obj.metadata.product.toLowerCase().includes('renewal'))&&((instore_txn == '0')||(reward_txn == '1'))) {
                 let pin_resp = await getPromoPinCode(req,clientip,tid_used,obj,null);
                 if(!pin_resp.includes('<RESULT>0</RESULT>')) {
                  let promocode = obj.metadata.promoCode;
                    let result_refund_promo = await refundPromoDiscount(tid_used,obj.metadata.reference, promocode,log_prefix,log_suffix,req);
                    console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                 }
                 
                 ///////////////////////////////////////////////////////

                 if((reward_txn == '1')&&(pin_resp.includes('<RESULT>0</RESULT>'))) {
                  let TID = getDefaultTID(req.hostname,req);
                  let resp = await getPromoCardStatus(TID,obj.metadata.reference,obj.metadata.promoCode,log_prefix,log_suffix,clientip,req);
                  console.log(resp);

                  if(resp.includes('<CARD>')) {
                    let a = resp.split('<CARD>');
                    let b = a[1].split('</CARD>');
                    let card_data =  b[0] + '<LOGINTIME>' + getTimeStamp() + '</LOGINTIME>';
                    let enc = encrypt(card_data);
                    let enctag = '<ENCBLOCK>' + enc + '</ENCBLOCK>';
                    resp = resp.replace('</RESPONSE>', enctag + '</RESPONSE>');
                  }

                  pin_resp = pin_resp + '<CARDBLOCK>' + resp + '</CARDBLOCK>';
   
                 }

                 //////////////////////////////////////////////////////


                 console.log('sending status 207');
		             res.statusCode = 207;
                 res.send(pin_resp);
                 return;
               } 

               if(result != 'Success')
               {
                 console.log('Result Charge 2: ' + result);
                 res.statusCode = 207;
                 res.send(result);
                 return;
               }
              
            }

            ///////////////////AKANI/////////////////////////
            if(!obj.metadata.flashVoucher) {
              obj.metadata['flashVoucher'] = 'none';
            }
            let payment_methods = await getPaymentMethods(req.hostname);
            if((obj.metadata.flashVoucher)&&(!obj.metadata.product.toLowerCase().includes('renewal'))) {
              
              if((obj.metadata.flashVoucher)&&(obj.metadata.flashVoucher != 'none')&&(payment_methods.includes('akani'))) {
                  let result_akani_payment = await processAkaniPayment(obj,req,clientip,log_prefix,log_suffix);

                  
                  if(result_akani_payment.responseCode == 0) {

                    let pin_resp = await getPromoPinCode(req,clientip,tid_used,obj,result_akani_payment);
                    if(!pin_resp.includes('<RESULT>0</RESULT>')) {                      

                      let result_akani = await processRefundAkaniVoucher(result_akani_payment,obj,req,clientip,log_prefix,log_suffix);
                      console.log(log_prefix + 'result_refund_akani_voucher: ' + log_suffix);
                      console.log(result_akani);
                    }
                    console.log('sending status 207');
                    res.statusCode = 207;
                   // console.log(log_prefix + pin_resp + log_suffix);
                    res.send(pin_resp);
                    return;

                  } else {
                    
                    console.log('sending status 207');
                    res.statusCode = 207;                 
                    let result_akani = '<RESPONSE>' + '<RESULT>' + result_akani_payment.responseCode + '</RESULT>' + '<RESULTTEXT>' + result_akani_payment.responseMessage + '</RESULTTEXT>' + '</RESPONSE>'
                    console.log(log_prefix + result_akani + log_suffix);
                    res.send(result_akani);
                    return;
                  }
              } else if((obj.metadata.flashVoucher.length > 0)&&(obj.metadata.flashVoucher != 'none')&&(!payment_methods.includes('akani'))) {
                 // block ip
                  let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + obj.metadata.tid + ' Reason: GET_AUTH_SALE Akani Payment method not enabled'
                  console.log(log_prefix + alert + log_suffix);
                  if(BlockedIPs) {
                    BlockedIPs = BlockedIPs + ',' + clientip;
                  }else {
                    BlockedIPs = clientip;
                  }
                  let err = JSON.stringify(
                    {
                        request_id: '46c52f94-49e0-4eb6-856e-b34774bb7be6',
                        error_type: getMessageIDText('MESSAGEID_118',req),
                        error_codes: [' '] 
                    });
                
                    res.send(err);
                    return;
              }
            }
            
            
            /////////////////////////////////////////////////
          
              obj.amount = obj.metadata.partialPay;
              if((instore_txn == '1')||(reward_txn == '1')) { //reward auth
                obj.amount = '0';
              }

              if((obj.metadata.flashVoucher.length > 0)&&(obj.metadata.flashVoucher != 'none')&&(payment_methods.includes('akani'))) {
                obj.amount = '0';
              }
            }
            /////////////////////////////// 
           console.log('obj.metadata========================================================');
           console.log(obj.metadata);
          let add_akani_flash = ((obj.metadata.flashVoucher) ? obj.metadata.flashVoucher:'' );
            let add_akani_african = ((obj.metadata.africanID) ? obj.metadata.africanID : '');
            let add_akani_cashier = ((obj.metadata.cashier) ? obj.metadata.cashier : '');            ////////////////////////////////////////////////////////////////////////
        let more_info = obj.metadata.promoApplied  + ',' + obj.metadata.discount + ',' + 
                        obj.metadata.promoCode + ',' + obj.metadata.ActivationSerial + ',' + 
                        obj.metadata.ProductTypeSale + ',' + obj.metadata.CurrencyCodeProduct + ',' +
                        obj.metadata.instore + ',' + obj.metadata.gpay + ',' + obj.metadata.delivery + ',' +
                        add_akani_flash + ',' + add_akani_african + ',' + add_akani_cashier;

   

        obj.metadata['moreInfo'] = more_info;

        let objBackup = JSON.parse(JSON.stringify(obj));

        delete obj.metadata['promoApplied'];
        delete obj.metadata['discount'];
        delete obj.metadata['promoCode'];
        delete obj.metadata['ActivationSerial'];
        delete obj.metadata['ProductTypeSale'];
        delete obj.metadata['CurrencyCodeProduct'];
        delete obj.metadata['instore'];
        delete obj.metadata['gpay'];
        delete obj.metadata['delivery'];
        delete obj.metadata['flashVoucher'];
        delete obj.metadata['africanID'];
        delete obj.metadata['cashier'];

        delete obj.metadata['enc']; //enc check
/////////////////////////////////////////////////////////////////////////
        let bRetry = true;
        let auth_counter = 0;
        let domain_resp_code_retry = await getDomainCheckoutErrorsRetry(req);
        while (bRetry) {
            if(auth_counter > 0) {
              let ref = obj.reference;
              delete obj['reference'];
              obj['reference'] = ref + '-R' + auth_counter;
            } 
            
            body = JSON.stringify(obj);
            console.log(body);

            body = body.replace(/amp2rep/g, '&');
            body = body.replace(/hash2rep/g, '#');
       
           
            const fetchOptions = {
              method: 'POST',

              body: body,

              headers: {
                'Authorization': bearer + secret_checkout,
                'Content-Type': 'application/json',
              },

            }
            console.log(log_prefix + 'GET AUTH REQUEST: ' + use_checkout_url + log_suffix);
            mask_json_data(fetchOptions.body, log_prefix, log_suffix);


         //   let bRetry = true;
         //   let auth_counter = 0;
         //   let domain_resp_code_retry = await getDomainCheckoutErrorsRetry(req);
         //   while (bRetry) {
                  bRetry = false;
                  auth_counter = auth_counter + 1;
                  console.log('++++++++++++++++++++++retry:' + auth_counter);
            const response = await fetch(use_checkout_url, fetchOptions,proxy_url);
            console.log('========checkout getauth response headers=============');
            console.log(response);
            console.log(log_prefix +  'GET AUTH RESPONSE STATUS: '+ response.status + '::::' + JSON.stringify(response.headers) + log_suffix);
            let jsonResponse = await response.json();
            console.log(jsonResponse);
      
            console.log(log_prefix + 'GET AUTH RESPONSE:' + log_suffix);
            mask_json_data(JSON.stringify(jsonResponse), log_prefix, log_suffix);
          
            if(jsonResponse.status == 'Declined')
            {
                if(domain_resp_code_retry) {                             
                        let a = domain_resp_code_retry.split(',');
                        if((auth_counter < 3)&&(a.includes(jsonResponse.response_code))) {
                          bRetry = true;
                          console.log('retry again: ' + auth_counter + '(' + jsonResponse.response_code + ')');
                          continue;                                
                        }
                      }
                 console.log('retry stopped: ' + auth_counter);

                if((obj.metadata.promoApplied == '1')&&(obj.metadata.discount != '0')) {
                let promocode = obj.metadata.promoCode;                 
                let a1 = tidhead.split('<TERMINALID>');
                let a2 = a1[1].split('</TERMINALID>');
                let tid_used = a2[0];
                  let result_refund_promo = await refundPromoDiscount(tid_used,obj.metadata.reference, promocode,log_prefix,log_suffix,req);
                  console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
               }
                let checkout_error = '';
                let checkout_error_code = '';
                if(jsonResponse.response_summary)
                {
                    checkout_error= jsonResponse.response_summary;
                }
                else
                {
                   checkout_error = 'Transaction Declined';                   
                }

                if(jsonResponse.response_code)
                {
                    checkout_error_code= 'Response Code: ' + jsonResponse.response_code;
                }
                else
                {
                   checkout_error_code = '';
                }
                let errorSharaf = ' '+ getMessageIDText('MESSAGEID_135',req);
                var err = JSON.stringify(
                {
                    request_id: '46c52f94-49e0-4eb6-856e-b4e400ff7be8',
                    error_type: (await getCheckoutErrorResponse(jsonResponse,req)),// checkout_error + errorSharaf,
                    error_codes: [checkout_error_code] 
                });

                console.log(log_prefix + err + log_suffix);

                res.send(err);
            }
            else if((response.status == 201)&&((jsonResponse.approved == true))&&(jsonResponse.status == 'Card Verified')&&(reward_txn == '1')) {
              let sale_response = await getAuth201SaleResponse(jsonResponse,obj.metadata,req,clientip);
              ///////////////////////////////////////////////////////
              
              if(sale_response.includes('<RESULT>0</RESULT>')) {
                let TID = getDefaultTID(req.hostname,req);
                let resp = await getPromoCardStatus(TID,obj.metadata.reference+'-1',obj.metadata.promoCode,log_prefix,log_suffix,clientip,req);
                console.log(resp);

                if(resp.includes('<CARD>')) {
                  let a = resp.split('<CARD>');
                  let b = a[1].split('</CARD>');
                  let card_data =  b[0] + '<LOGINTIME>' + getTimeStamp() + '</LOGINTIME>';
                  let enc = encrypt(card_data);
                  let enctag = '<ENCBLOCK>' + enc + '</ENCBLOCK>';
                  resp = resp.replace('</RESPONSE>', enctag + '</RESPONSE>');
                }

                sale_response = sale_response + '<CARDBLOCK>' + resp + '</CARDBLOCK>';
 
               }

               //////////////////////////////////////////////////////
              res.statusCode = 201;
              res.send(sale_response);
              
           }
            else if((response.status == 201)&&((jsonResponse.approved == true))&&((jsonResponse.status == 'Authorized')||(jsonResponse.status == 'Captured'))) {
               let sale_response = await getAuth201SaleResponse(jsonResponse,obj.metadata,req,clientip);
               res.statusCode = 201;
               res.send(sale_response);
            }
            else if((response.status == 201)&&((jsonResponse.approved == true))&&((jsonResponse.status == 'Card Verified'))) {
              if((await getProxyCodeAllowed(req.hostname)) == 'yes') {
                    let param_str = getFormattedTime() + ',' + objBackup.metadata.promoCode + ','+ objBackup.metadata.ean + ','+ objBackup.amount + ',' + objBackup.metadata.tid + ',' + objBackup.metadata.currency + ',' + '' + ',' + objBackup.metadata.firstname + ',' + objBackup.metadata.surname + ',' + objBackup.metadata.email + ',' + objBackup.metadata.phone + ',' + objBackup.metadata.title + ',' + 'yes';
                    let param_str_b64 = Buffer.from(param_str).toString('base64'); 
                    jsonResponse['metadata'] = JSON.parse(JSON.stringify(obj.metadata));
                    let jsonResp = await getProxyMultiCheckout(param_str_b64,clientip,req,jsonResponse);            
                    console.log(jsonResp);
                    res.statusCode = 201;
                    res.send(jsonResp);
                } else {
                  let resp = '<RESPONSE><RESULT>170</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_137',req)+'</RESULTTEXT></RESPONSE>';
                  console.log(resp);
                  res.send(resp);
                }
              
           }
            else
	  	 res.send(jsonResponse);
            }

          }

       
      } catch (error) {
        console.log('invalid body parameter!:' + error);
        res.statusCode = 431;
        res.send('Invalid Parameter')
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  }
  else
{

  var err = JSON.stringify(
    {
        request_id: '46c52f94-49e0-4eb6-856e-b4e400ff7be6',
        error_type: 'This service is only available in the UAE.',
        error_codes: ['Please make sure you are using UAE IP address.'] 
    });

    res.send(err);
  
  
}

});




app.get('/getAuthRenewal', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getAuthRenewal => clientip: ' + clientip);

  let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
  if(isIpTrusted)
  {
  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
      //  var body = req.query.body;
      var body = Buffer.from(req.query.body,'base64').toString('utf8');  

       var obj = JSON.parse(body);

       if(!obj.reference.includes('EPAY-'))
        {
          obj.reference = 'EPAY-' + obj.reference;
        }

       let session_id = obj.reference;
         let host_log = req.hostname.split('.');
         let method = 'GET_AUTH_SAVE_CARD';
         log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         log_suffix = '\n</LOG></SESSION_LOG>';
         console.log(log_prefix + req.headers.campaign + '>>API_CALL:getAuthRenewal => clientip: ' + clientip + log_suffix);
         console.log(log_prefix + 'Request Body Received from Client App:' + log_suffix);
         
         mask_json_data(body,log_prefix,log_suffix);

        var key = "processing_channel_id";

        if(checkout_protocol == 0)
            delete obj[key];
        else
           obj.processing_channel_id = processingchannelid;
        
        obj.customer.phone.country_code = '+' + obj.customer.phone.country_code;

        obj.amount = 0;
        obj.currency = "AED";

        let currencycode = 'AED';
        let country_code = await getCountryCode(req.hostname);
        if(country_code == 'ZA') {
          obj.currency = 'ZAR';
          currencycode = 'ZAR';
        } else if(country_code == 'TR') {
          obj.currency = 'TRY';
          currencycode = 'TRY';
        } else if(country_code == 'SA') {
          obj.currency = 'SAR';
          currencycode = 'SAR';
        }
        

        let getSymbolFromCurrency = require('currency-symbol-map');
        let symbol = getSymbolFromCurrency(currencycode);
        if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
            symbol = '\u{2800}';
        }

        console.log(log_prefix + '3DS Payment Request:' + log_suffix);
        
        let tid_arr = obj.success_url.split('&gtid=');
        let tid_used = tid_arr[1];
        body = JSON.stringify(obj);
        body = body.replace(/amp2rep/g, '&');
        body = body.replace(/hash2rep/g, '#');
 
        

        let checkout_key = '';
        let use_checkout_url = '';
        let bearer = '';
        let cred = await getCheckoutCredentials(req.hostname,req);
        if(cred)
        {
          checkout_key = cred.CheckoutSecretKey;
          use_checkout_url = cred.url;
          bearer = cred.prefix;
        }


        const fetchOptions = {
          method: 'POST',

          body: body,

          headers: {
            'Authorization': bearer + checkout_key,
            'Content-Type': 'application/json',
          },

        }
        
        console.log(log_prefix + 'Request Body Sent to Checkout: ' + use_checkout_url + log_suffix);
        mask_json_data(body,log_prefix,log_suffix);
        const response = await fetch(use_checkout_url, fetchOptions,proxy_url);
        const jsonResponse = await response.json();
        console.log(log_prefix + 'Server Response: '+ response.status  + log_suffix);

        
        mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix);

        if(jsonResponse.status == 'Declined')
            {
                let checkout_error = '';
                let checkout_error_code = '';
                if(jsonResponse.response_summary)
                {
                    checkout_error= jsonResponse.response_summary;
                }
                else
                {
                   checkout_error = 'Transaction Declined';                   
                }

                if(jsonResponse.response_code)
                {
                    checkout_error_code= 'Response Code: ' + jsonResponse.response_code;
                }
                else
                {
                   checkout_error_code = '';
                }
                let errorSharaf = ' ' + getMessageIDText('MESSAGEID_135',req);
                
                var err = JSON.stringify(
                {
                    request_id: '46c52f94-49e0-4eb6-856e-b4e400ff7be7',
                    error_type: (await getCheckoutErrorResponse(jsonResponse,req)),// checkout_error + errorSharaf,
                    error_codes: [checkout_error_code] 
                });
                console.log(log_prefix + err + log_suffix);
                res.send(err);
            }
            else       
       		     res.send(jsonResponse);


      } catch (error) {
        console.log('invalid body parameter!');
        res.statusCode = 431;
        res.send('Invalid Parameter')
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
}
else
  {
    var err = JSON.stringify(
      {
          request_id: '46c52f94-49e0-4eb6-856e-b4e400ff7be9',
          error_type: 'This service is only available in the UAE.',
          error_codes: ['Please make sure you are using UAE IP address.'] 
      });
  
      res.send(err);
    
  }

});

async function sendCardUpdateSuccessMsg_ib(reference,phone,scheme,last4,product,contract,log_prefix,log_suffix)
{
  let sCardType = scheme + ' x' + last4;
  if(reference.includes('-'))
  {
    let arr = reference.split('-');
    reference = arr[0];
  }
 // let smsBody = 'Hi, You card ' + sCardType + ' is successfully updated to your subscription ' + contract + ' for product ' + product + ' with reference ' + reference + '. Thank you!';
  var infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infobip_msg_sender+ '","text":"' + smsBody + '"}]}';
    
    let ref_sp_a = reference.split('-');
let ref_sp = ref_sp_a[1];
if(ref_sp.length == 20) {
  ref_sp = ref_sp.substring(8,20);
}
let smsBody = 'Hi, your card ' + sCardType + ' was successfully updated for your product ' + product + ' subscription. Ref. ' + ref_sp + '. Thank you!';
      

    mask_json_data(infobip_smsbody,log_prefix,log_suffix);
    const fetchOptions = {
      method: 'POST',

      body: infobip_smsbody,

      headers: {
        'Authorization': 'App ' + infobipAuth,  
        'Content-Type': 'application/json',
      },
      
    }

    let infobipSMSURL = infobipURL;  

    var smsTimeout = setTimeout(() => console.log('SMS send time out'), 30000);
    try {
      console.log(log_prefix + 'Infobip SMS Request:' + infobipSMSURL + log_suffix);
      const response = await fetch(infobipSMSURL, fetchOptions,proxy_url);
      console.log(response.status);
      let jsonResponse = await response.json();

     // console.log(jsonResponse);
      
      clearTimeout(smsTimeout);
      mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix); 
    } catch(error) {
      console.log(error);
    }

}


app.get('/getRenewalStatus', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getRenewalStatus => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
try{
 


  let body_token = Buffer.from(req.query.token,'base64').toString('utf8');
  let token_arr = body_token.split(',');
  let token = token_arr[0];
  let gtid = token_arr[1];
     

  if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
  {
      gtid = getDefaultTID(req.hostname,req);        
  }
 
  let use_checkout_key = '';
  let use_checkout_url = '';
  let bearer = '';
  let cred = await getCheckoutCredentials(req.hostname,req);
  if(cred)
  {
    use_checkout_key = cred.CheckoutSecretKey;
    use_checkout_url = cred.url;
    bearer = cred.prefix;
  }
  
  const fetchOptions1 = {
    method: 'GET',
    headers: {
      'Authorization': bearer + use_checkout_key,
      'Content-Type': 'application/json',
    },
  }
  var tokreq = use_checkout_url + '/' + token;
  const responsetok = await fetch(tokreq, fetchOptions1,proxy_url);

  console.log(responsetok);
  console.log(responsetok.status);

  if (responsetok.status != 404) {

    if (responsetok.status == 200) {

      const jsonResponsetok = await responsetok.json();
     
      console.log(jsonResponsetok.metadata.ean);
      console.log(jsonResponsetok.status);
      //-----------------------------------

      let session_id = jsonResponsetok.reference;
      let host_log = req.hostname.split('.');
      let method = 'SAVE_CARD_STATUS';
      let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
      let log_suffix = '\n</LOG></SESSION_LOG>';

      console.log(log_prefix + req.headers.campaign + '>>API_CALL:getRenewalStatus => clientip: ' + clientip + log_suffix);

      console.log(log_prefix + 'Session Query on Checkout: ' + tokreq + log_suffix);

      console.log(log_prefix + 'RESPONSE To Session Query on Checkout:' + log_suffix);
      

      mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix)

      //---------------------------------

      if ((jsonResponsetok.status == 'Card Verified') && (jsonResponsetok.approved == true)) {
        var txnarr = jsonResponsetok.requested_on.toString().split(".");

        let up_cred = await getUPCredentials(req);

        var userIdHost = up_cred.userIdHost;
        var userPaswdHost = up_cred.userPaswdHost;

        let defaultTID = getDefaultTID(req.hostname,req);

        console.log(txnarr);
        var txnTime = txnarr[0].replace('T', ' ');
        txnTime = txnTime.replace('Z','');
        console.log(txnTime);

        var ref = getTimeStamp();
        var refjsonarr = jsonResponsetok.metadata.reference.split('-');
        var inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + refjsonarr[1];      

   
        let tidhead = '<TERMINALID>'+ jsonResponsetok.metadata.contract.substring(0,8) +'</TERMINALID>';
        if(jsonResponsetok.metadata.contract.substring(0,5) == 'EPAY-')
        {
           tidhead = '<TERMINALID>'+ jsonResponsetok.metadata.contract.substring(5,13) +'</TERMINALID>';
        }

      

        {
          console.log(jsonResponsetok.metadata.reference);
          let emailToSend =  jsonResponsetok.metadata.email;
          let phoneToSend =  jsonResponsetok.metadata.phone;
          let emailTAG= '<EMAIL></EMAIL>';
          let phoneTAG = '<PHONE></PHONE>';
          if(emailToSend)
          {
            if(emailToSend.length > 0)
            {
                emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
            }
          }
          if(phoneToSend)
          {
            if(phoneToSend.length > 0)
            {
                phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
            }
          }
          
          let info = await getTestSubscriptionInfo(req.hostname,null) 
          if(info) {            
                tidhead = '<TERMINALID>'+ info.TestTIDSUBSCRIPTION +'</TERMINALID>';            
          }

         
          console.log(log_prefix + jsonResponsetok._links.actions.href + log_suffix);
          let auth_code = await getAuthCode(jsonResponsetok._links.actions.href,jsonResponsetok.metadata.contract.substring(0,8),req.hostname,log_prefix,log_suffix,req);
          
          console.log(log_prefix + 'auth_code: ' + auth_code + log_suffix);
          if(auth_code != 'none')
          {
            auth_code = '-' + auth_code;
          }
          else
          {
            auth_code = '';
          }
          console.log(auth_code);
          let refarray = jsonResponsetok.metadata.contract.split('-');
          let refstring = refarray[1];

          let reftxntemp2 = '';
          if(refarray[2]){
            if(refarray[2].length >= 9){
              reftxntemp2 = refarray[2].substring(0,9);
            }
          }
          let inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + ((reftxntemp2.length == 9) ? reftxntemp2:refstring.substring(0,8));
          
          const fetchOptionsInfo = {
            method: 'POST',

            body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
              '<USERNAME>' + userIdHost + '</USERNAME>' +
              '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
              tidhead +
              '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
              // '<TXID>' + 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + refstring.substring(0,8) + '-' + jsonResponsetok.source.bin + auth_code + '</TXID>' +  //inforef
              '<TXID>' + (inforef.includes('EPAY-undefined') ? inforef.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): inforef) + '</TXID>' + // refstring.substring(0,8) + '-' + jsonResponsetok.source.bin + auth_code + '</TXID>' +  //inforef
              '<PRODUCTID>' + jsonResponsetok.metadata.ean + '</PRODUCTID>' +
              '<SUBSCRIPTION>' +
              '<TOKENID>' + jsonResponsetok.source.id + '</TOKENID>' +
              '<LASTFOUR>' + jsonResponsetok.source.last4 + '</LASTFOUR>' +
              '<CARDTYPE>' + jsonResponsetok.source.scheme + '</CARDTYPE>' +              
              emailTAG +
              phoneTAG +
              '<BIN>' + jsonResponsetok.source.bin + '</BIN>' +
  	      '<AUTHCODE>' + auth_code.replace('-','') + '</AUTHCODE>' +
              '</SUBSCRIPTION>' +
              '<TRANSACTIONREF>' +
              '<REFTYPE>SERIAL</REFTYPE>' +
              '<REF>' + jsonResponsetok.metadata.contract + '</REF>' +
              '</TRANSACTIONREF>' +
              '<CONSUMER>' +
              '<NAME>' + jsonResponsetok.metadata.firstname + '</NAME>' +
              '<SURNAME>' + jsonResponsetok.metadata.lastname + '</SURNAME>' +
              '<SMS>' + '+' + jsonResponsetok.metadata.phone + '</SMS>' +
              '<EMAIL>' + jsonResponsetok.metadata.email + '</EMAIL>' +
              '<TITLE>' + jsonResponsetok.metadata.title + '</TITLE>' +
             
              '<CUSTOMERID>' + (jsonResponsetok.customer ? jsonResponsetok.customer.id : jsonResponsetok.metadata.email) + '</CUSTOMERID>' +
              '</CONSUMER>' +
              '</REQUEST>',

            headers: {
              'Content-Type': 'application/xml',
            },
   
          }
      
          
          mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix)
          console.log(log_prefix + 'PAYMENT INFO REQUEST SAVE CARD: ' + paymentInfoURL + log_suffix);
          const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
          var jsonResponse = await response.text();

	        let homeTag = '';
       
          {
            homeTag = '<HOME>'+jsonResponsetok.metadata.home+'</HOME>';
          }

          var addedResponse = '<CARDTYPE>' + jsonResponsetok.source.scheme + ' x' + jsonResponsetok.source.last4 + '</CARDTYPE>' +
            '<PRODUCT>' + jsonResponsetok.metadata.product + '</PRODUCT>' +
            '<CONTRACT>' + jsonResponsetok.metadata.contract + '</CONTRACT>'+homeTag+'</RESPONSE>';

        
          console.log(log_prefix + 'Response received from server' + log_suffix);
          let jsonResponse_log = jsonResponse;
          jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
          mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
     
          jsonResponse = jsonResponse.replace('</RESPONSE>', addedResponse);
         
         console.log(log_prefix + 'Response sent to client' + log_suffix);
          jsonResponse_log = jsonResponse;
          jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
          mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

          if((jsonResponse.includes('<RESULT>0</RESULT>'))&&(((await getPaymentMethods(req.hostname)).includes('checkout'))))
          {
              sendCardUpdateSuccessMsg_ib(jsonResponsetok.reference,jsonResponsetok.metadata.phone,jsonResponsetok.source.scheme,jsonResponsetok.source.last4,jsonResponsetok.metadata.product,jsonResponsetok.metadata.contract,log_prefix,log_suffix);
          }

          res.send(jsonResponse);

        }


      }
      else if (jsonResponsetok.approved == false) {
        console.log(log_prefix + 'notapproved' + log_suffix);
        if(jsonResponsetok.actions.length > 0)
            {
              let errorSharaf = '. ' + getMessageIDText('MESSAGEID_135',req);
              
              let errorText = await getCheckoutErrorResponse(jsonResponsetok,req);
              // jsonResponsetok.actions[0].type + getMessageIDText('MESSAGEID_136',req) + jsonResponsetok.actions[0].response_code + '. ' + jsonResponsetok.actions[0].response_summary + errorSharaf ;
              console.log(log_prefix + errorText + log_suffix);
              res.send('<RESPONSE><RESULT>' + jsonResponsetok.actions[0].response_code + '</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT><HOME>'+jsonResponsetok.metadata.home+'</HOME><CONTRACT>' + jsonResponsetok.metadata.contract + '</CONTRACT></RESPONSE>');
            }
            else{
              let err = await getCheckoutErrorResponse(jsonResponsetok,req);
              if(err.length)
                err = Buffer.from(err).toString('base64');
              console.log(log_prefix + 'notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.contract + ',' + err + log_suffix);
              res.statusCode = 400;
              res.send('notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.contract + ',' + err);
            }
        
      }
      else {
        console.log('failed1234');
        res.statusCode = 400;
        console.log(log_prefix + 'failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.contract + log_suffix);
        res.send('failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.contract);
      }


    }
    else {

      console.log('failed2222');
      res.statusCode = 400;
      res.send(responsetok.status);
    }

  }
  else {

    console.log('404 error');
    res.statusCode = 404;
    res.send('404');
  }
}catch(error)
{
  console.log(error);
  
  let customer = await getCustomerName(req.hostname);
  let support_url = await getDomainSupportUrl(req.hostname);
  let str =  getMessageIDText('MESSAGEID_102',req)+ customer +getMessageIDText('MESSAGEID_103',req)+ support_url;

 
  res.send('<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+str+'</RESULTTEXT></RESPONSE>');
}

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

});

app.get('/getContractDetails', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getContractDetails => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
  try {
  //var contract = req.query.contract;
  let contract = Buffer.from(req.query.contract,'base64').toString('utf8');
  let session_id = contract;
  let host_log = req.hostname.split('.');
  let method = 'GET_CONTRACT_DETAILS';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';

  console.log(log_prefix + req.headers.campaign + '>>API_CALL:getContractDetails => clientip: ' + clientip + log_suffix);
  
  currentDate = getFormattedTime();
  var ref = getTimeStamp();

  var x = Math.random() * 1000000;
  var y = x.toString().split('.');

  var contractArr = contract.split('-');
  var phone = y[0];
  if (contractArr.length > 1)
    phone = contractArr[1];

  var reference = (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;

  let up_cred = await getUPCredentials(req);

  var userIdHost = up_cred.userIdHost;
  var userPaswdHost = up_cred.userPaswdHost;
  var tidhead = '';

   

  let TERMINAL_ID = contract.substring(0,8);
  console.log(log_prefix + 'TERMINAL_ID: '+ TERMINAL_ID + log_suffix);
 
  if (contract) {
    const fetchOptions = {
      method: 'POST',
      body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
        '<AUTHORIZATION>' +
        '<USERNAME>' + userIdHost + '</USERNAME>' +
        '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
        '</AUTHORIZATION>' +
        '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
        '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
        '<TXID>' + reference + '</TXID>' +
        '<SUBSCRIPTION>' +
        '<CONTRACT>' + contract + '</CONTRACT>' +
        '<STATUS>ACTIVE</STATUS>' +
        '</SUBSCRIPTION>' +
        '</REQUEST>',

      headers: {
        'Content-Type': 'application/xml',
      },

    }
    
    mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
    var contractFetchTimeout = setTimeout(() => {console.log(log_prefix + 'Contract Fetch Timeout' + log_suffix); res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_123',req) + '</RESULTTEXT></RESPONSE>')}, 30000);

    try {
      const response = await fetch(getContractURL, fetchOptions,proxy_url);
      let jsonResponse = await response.text();
      let jsonResponse_log = jsonResponse ;
      jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
     
      mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
      clearTimeout(contractFetchTimeout);

      let longDescriptionEN = '';
      let shortDescriptionEN = '';
      let amount_tag = '';

      if(jsonResponse.includes('<RESULT>0</RESULT>'))
      {
        if(!jsonResponse.includes('<SUBSCRIPTIONS />'))
        {
        let host = req.hostname.split('.');
        let arr = jsonResponse.split('<PRODUCTID>');
        let arrEAN = arr[1].split('</PRODUCTID>');
        let ean = arrEAN[0];
        arr = jsonResponse.split('<TERMINALID>');
        let arrTID = arr[1].split('</TERMINALID>');
        let tid = arrTID[0];
        let blockToParse = await getCatalog(req.hostname,tid,ean,0,req);
        console.log(blockToParse);
        if(blockToParse != 'no_data')
        {
        let str1 = '';  
        
	      let currencycode = 'AED';
        let country_code = await getCountryCode(req.hostname);
        if(country_code == 'ZA') {
          currencycode = 'ZAR';
        } else if(country_code == 'TR') {
          currencycode = 'TRY';
        } else if(country_code == 'SA') {
          currencycode = 'SAR';
        }

        let getSymbolFromCurrency = require('currency-symbol-map');
        let symbol = getSymbolFromCurrency(currencycode);
        if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
          symbol = '\u{2800}';
        }

        let arr_amt = blockToParse.split('<AMOUNT CURRENCY');
        let arr_amt_1 = arr_amt[1].split('</AMOUNT>');
        let arr_amt_2 = arr_amt_1[0].split('>');
        console.log('++--'+ arr_amt_2[1]);
        let str = arr_amt_2[1];
        
        if (str == 0) {
          str1 = symbol + '0.00';
        }
        else {
          str1 = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
        }

        amount_tag = '<AMOUNT>'+ str1 +'</AMOUNT>';

        var parseString = require('xml2js').parseString;
        parseString(blockToParse, function (err, result) {
          console.dir(result.RESPONSE);
          console.dir(result.RESPONSE.INFOS);
          let xmlINFOLIST = result.RESPONSE.INFOS[0].INFO;
          if (xmlINFOLIST.length) {      
            let enfound = 0;   

            for (let k = 0; k < xmlINFOLIST.length; k++) {       
           
            let bBrandExists = false; 

            let xmlCountry = xmlINFOLIST[k].COUNTRY;
            if(xmlCountry)
            {
              
              console.log(xmlCountry);
              
            }
            
              if((xmlINFOLIST[k].BRAND))
              {
                bBrandExists = true;          
               
              }
                   
            if(!bBrandExists)
            {          
              continue;
            }
            
            ///////////////////////////
              let xmlLanguage = xmlINFOLIST[k].LANGUAGE;
              if(!(xmlLanguage))
              {
                xmlLanguage = xmlINFOLIST[k].language;
              }
              if (xmlLanguage) {
                let language = xmlLanguage;

                if (language.length) {
                  if ((language.includes('en-')) || (language == 'en') || (language == 'eng')) {
                    let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
                    let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG;
                  
                    enfound = 1;                 

                  
                    longDescriptionEN = xmlLongdescr
                    shortDescriptionEN = xmlShortdescr;
                   
                   
                    if ((longDescriptionEN.length > 1) || (shortDescriptionEN.length > 1)) {
                      break;
                    }
                    else
                      continue;
                  }



                }
              }
            
            }
            
            if (enfound == 0) {

            
              for (let k = 0; k < xmlINFOLIST.length; k++) {
                
              
            let bBrandExists = false;  
            if(xmlCountry)
            {
              
              console.log(xmlCountry);
              
            }    
           
           
            if((xmlINFOLIST[k].BRAND?.length > 0))
            {
              bBrandExists = true;   
             
            }
                  
            if(!bBrandExists)
            {          
              continue;
            }

                let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
                let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG;
              
                
                if (xmlShortdescr.length) {
                  
                  if ((xmlShortdescr.length > 1) || (xmlLongdescr.length > 1)) {
                    longDescriptionEN = xmlLongdescr;
                    shortDescriptionEN = xmlShortdescr;                   
                    enfound = 1;
                    break;
                  }
                }
              }

            }

            console.log(result.RESPONSE.MEDIA);
            console.log('result.RESPONSE.MEDIA');
            
            let product_logo = '';
            if(result.RESPONSE.MEDIA[0].ARTICLE_IMAGE.length > 0)
            {
              product_logo = result.RESPONSE.MEDIA[0].ARTICLE_IMAGE[0];
            }
            else if(result.RESPONSE.MEDIA[0].LOGO.length > 0)
            {
              product_logo = result.RESPONSE.MEDIA[0].LOGO[0];
            }
       
             logo_tag = '<PRODUCTLOGO>' + product_logo + '</PRODUCTLOGO>';
          }
        });
      }
      else{
        logo_tag = '<PRODUCTLOGO></PRODUCTLOGO>';
      }
      console.log(shortDescriptionEN);
      console.log(longDescriptionEN);     

     let desc = (shortDescriptionEN[0].length > 1)? shortDescriptionEN : longDescriptionEN;
      jsonResponse = jsonResponse.replace('</RESPONSE>','<DESCRIPTION>'+desc+'</DESCRIPTION>'+logo_tag+amount_tag+'</RESPONSE>');
      let jsonResponse_log_new = jsonResponse ;
              jsonResponse_log_new = jsonResponse_log_new.replace(/\r?\n|\r/g, " ");
    
      mask_xml_data(jsonResponse_log_new,log_prefix,log_suffix);
      res.send(jsonResponse);
    }
    else{
      console.log(log_prefix + 'no active subscriptions linked to phone' + log_suffix);
      
      res.send('<RESPONSE><RESULT>107</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_140',req)+'</RESULTTEXT></RESPONSE>')

    }
    }
    else{
      
      let jsonResponse_log_new = jsonResponse ;
      jsonResponse_log_new = jsonResponse_log_new.replace(/\r?\n|\r/g, " ");   
      mask_xml_data(jsonResponse_log_new,log_prefix,log_suffix);

      res.send(jsonResponse);
    }
    
    }
    catch (err) {
      console.log(err);
      let customer = await getCustomerName(req.hostname);
      let support_url = await getDomainSupportUrl(req.hostname);
      let str = getMessageIDText('MESSAGEID_102',req) + customer +getMessageIDText('MESSAGEID_103',req)+ support_url;


      res.send('<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+str+'</RESULTTEXT></RESPONSE>');
    }

  }
}catch(error)
{
  console.log(error);
  let customer = await getCustomerName(req.hostname);
  let support_url = await getDomainSupportUrl(req.hostname);
  let str = getMessageIDText('MESSAGEID_102',req)+ customer +getMessageIDText('MESSAGEID_103',req)+ support_url;


  res.send('<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+str+'</RESULTTEXT></RESPONSE>');
}
} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }


});

async function isTrustedIP(ip,hostname,req)
{

  const clientip = req.headers['incap-client-ip'] ;
  var txid = getTimeStamp();
  var x = Math.random() * 1000000000;    
  var y = x.toString().split('.');  
  txid =  'EPAY-' + '00000000'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
  

  let session_id = txid;
  let host_log = req.hostname.split('.');
  let method = 'UAE_IP_CHECK';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';

   
 
   {
    if(AllowedIPs)
    {
      if(AllowedIPs.includes(ip))
      {
          return true;
      }
      else 
      {        
        console.log( log_prefix + 'IP Restricted: ' + ip + log_suffix);
        return false;
      }
    }
    else
       return true;
  }
  
}


async function getAuthCode(actions,gtid,hostname,log_prefix,log_suffix,req)
{
try {

  let use_checkout_key = '';
  let use_checkout_url = '';
  let bearer = '';
  let cred = await getCheckoutCredentials(hostname,req);
  if(cred)
  {
    use_checkout_key = cred.CheckoutSecretKey;
    use_checkout_url = cred.url;
    bearer = cred.prefix;
  }
  const fetchOptions = {
    method: 'GET',
    headers: {
      'Authorization': bearer + use_checkout_key,
      'Content-Type': 'application/json',
    },
  }
  let authcode = 'none';
  console.log(log_prefix + 'GET AUTH CODE ACTIONS: ' + actions + log_suffix);
  const responsetok = await fetch(actions, fetchOptions,proxy_url);
  
  if (responsetok.status == 200) {
    

    let jsonResponsetok = await responsetok.json();
 

    for(let j=0; j< jsonResponsetok.length;j++)
    {
      mask_json_data(JSON.stringify(jsonResponsetok[j]),log_prefix,log_suffix);
    }

    for(let i=0; i<jsonResponsetok.length; i++)
    {
      if((jsonResponsetok[i].type == 'Authorization')||(jsonResponsetok[i].type == 'Card Verification'))
      {
        if(jsonResponsetok[i].auth_code)
        {
          authcode = jsonResponsetok[i].auth_code;
          break;
        }
      }
    }

     

  }
  if(authcode.length == 0)
  {
     authcode = 'none';
  }
 console.log('auth_code: ' + authcode);
  return authcode;
} catch(err) {
  console.log(log_prefix + 'Exception while fetch auth code!!' +log_suffix);
  return 'none';
}

}

async function getPromoPinCode (req,clientip,gtid,jsonResp,result_akani_payment) {
 
     
        

        
      if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
      {
         gtid = getDefaultTID(req.hostname,req);        
      }
      
      

         const jsonResponsetok = jsonResp;

         let isFlashVoucher = false;
         let isAkaniProduct = false;

        if(jsonResponsetok.metadata.flashVoucher) {
          if(jsonResponsetok.metadata.flashVoucher  != 'none') {
            isFlashVoucher = true;
          }
        }

        if(jsonResponsetok.metadata.africanID) {
          if(jsonResponsetok.metadata.africanID  != 'none') {
            isAkaniProduct = true;
          }
        }

         let session_id = jsonResponsetok.reference;
         let host_log = req.hostname.split('.');
         let method = (isFlashVoucher ? 'GET_PINCODE_SALE_FLASH' : 'GET_PINCODE_SALE_PROMO');
         let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         let log_suffix = '\n</LOG></SESSION_LOG>';         
        
          
  

          //---------------------------------         
           let shortdesciption = '';
           let longdescriptiontag = '';
           let redeemptiondesciptiontag = '';
           let terms = '';
           let termstag = '';
           let host = req.hostname.split('.');
           let blockToParse = await getCatalog(req.hostname , jsonResponsetok.metadata.tid, jsonResponsetok.metadata.ean,0,req);
           
           if(blockToParse != 'no_data')
           {
            let lang = req.headers.campaign;
            if(lang && (language_list.includes(lang))) {
                  let jsonInfoXML = await getJSONInfoCatalog(blockToParse,req,true);            
                  //console.log('jsonInfoXML: ' + jsonInfoXML);
                  let a = jsonInfoXML.split('<INFOSJSON>');
                  let b = a[1].split('</INFOSJSON>');
                  if(b[0] != '{}') {
                    let jsonInfo = JSON.parse(b[0]);
                    console.log(JSON.stringify(jsonInfo[lang]));
                    desc = jsonInfo[lang].DESCRIPTION_SHORT[0];
                    redeemptiondesciptiontag = '<REDEEMDESC>' + jsonInfo[lang].DESCRIPTION_REDEMPTION[0] + '</REDEEMDESC>';
                    longdescriptiontag = '<LONGDESC>' + jsonInfo[lang].DESCRIPTION_LONG[0] + '</LONGDESC>';
                    termstag = '<TERMS>' + jsonInfo[lang].TERMS_AND_CONDITIONS[0] + '</TERMS>';
                    terms = jsonInfo[lang].TERMS_AND_CONDITIONS[0];
                    shortdesciption = jsonInfo[lang].DESCRIPTION_SHORT[0];
                  }
            } else {
                    var parseString = require('xml2js').parseString;
                    parseString(blockToParse, function (err, result) {
                      console.log(result.RESPONSE);
                      console.log(result.RESPONSE.INFOS);
                      let short_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_SHORT;
                      let long_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_LONG;
                      let redeem_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_REDEMPTION;
                    
                      if(redeem_desc.length)
                        redeemptiondesciptiontag = '<REDEEMDESC>' + redeem_desc + '</REDEEMDESC>';
                      
                      if(long_desc.length)
                        longdescriptiontag = '<LONGDESC>' + long_desc + '</LONGDESC>';

                      let desc = (short_desc.length > 0)? short_desc : long_desc;
                      shortdesciption = desc;
                      terms = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].TERMS_AND_CONDITIONS;

                      if(terms.length)
                        termstag = '<TERMS>'+terms+'</TERMS>';
                      
                      
                    });
            }
           }
            
            
            let metaTID = jsonResponsetok.metadata.tid;
            let up_cred = await getUPCredentials(req);

            var userIdHost = up_cred.userIdHost;
            var userPaswdHost = up_cred.userPaswdHost;            

          
           
            var txnTime = getFormattedTime();
            
            console.log(txnTime);

            var ref = getTimeStamp();
            var refjsonarr = jsonResponsetok.metadata.reference.split('-');
            let reftxntemp = refjsonarr[1];
            var inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + reftxntemp.substring(0,8);

            let tidhead = '<TERMINALID>'+ metaTID +'</TERMINALID>';  
            
            if((metaTID == '') || (metaTID == 'undefined') || (metaTID == 'notid'))
            {
              let gtid = getDefaultTID(req.hostname,req);
              tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
            }

                                 
           
            {
              
              var extrahead = '';
              var eanhead = '<EAN>' + jsonResponsetok.metadata.ean + '</EAN>';
              var eantouse = jsonResponsetok.metadata.ean;
              if (jsonResponsetok.metadata.product.includes('Renewal') || jsonResponsetok.metadata.product.includes('renewal')) {
                extrahead = '<EXTRADATA>' +
                  '<DATA name="CONTRACT">' + jsonResponsetok.metadata.reference + '</DATA>' +
                  '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
                  '</EXTRADATA>';
                
              }

          

            if(jsonResponsetok.metadata.product.toLowerCase().includes('renewal')) {
              let info = await getTestSubscriptionInfo(req.hostname,jsonResponsetok.metadata.ean);
              if(info) {
               tidhead = '<TERMINALID>' + info.TestSubscriptionTID + '</TERMINALID>';
               eanhead = '<EAN>' + info.TestSubscriptionEAN + '</EAN>';
              }
           }

              let cashierhead = '';
              if(jsonResponsetok.metadata.cashier)
              {
                cashierhead = '<CASHIER>' + jsonResponsetok.metadata.cashier + '</CASHIER>';
              }
              let send_sms_tag = '';
              let send_email_tag = '';
              let del_mode = getDeliveryMode(req.hostname,null);
              if(del_mode.includes('SMS'))
              {
                send_sms_tag = '<SMS>' + '+' + jsonResponsetok.metadata.phone + '</SMS>' ;
                
              }

              if(del_mode.includes('EMAIL'))
              {
                send_email_tag = '<EMAIL>' + jsonResponsetok.metadata.email + '</EMAIL>' ;                
              }

              let PAN_TAG = '';
              let CURRENTCY_TAG = '';

              if(jsonResponsetok.metadata.ProductTypeSale == 'POSA')
              {
                PAN_TAG = '<PAN>' + jsonResponsetok.metadata.ActivationSerial + '</PAN>';
                CURRENTCY_TAG = '<CURRENCY>' + jsonResponsetok.metadata.CurrencyCodeProduct + '</CURRENCY>';
              }

              let AK_CUSTOMER_ID = '';

              if(jsonResponsetok.metadata.africanID) {
                if((jsonResponsetok.metadata.africanID != 'none')&&(jsonResponsetok.metadata.africanID.length)) {
                  AK_CUSTOMER_ID = '<AK_CUSTOMER_ID>' + jsonResponsetok.metadata.africanID + '</AK_CUSTOMER_ID>';
                  let gender = ((jsonResponsetok.metadata.title == 'Mr') ? 'm' : 'f' );
                  let areacode = jsonResponsetok.metadata.phone.substring(0,jsonResponsetok.metadata.phone.length-9);
                  let mobile = jsonResponsetok.metadata.phone.substring(jsonResponsetok.metadata.phone.length-9,jsonResponsetok.metadata.phone.length);
                  let AFRICANID_TAG = '<DATA name="AK_CUSTOMER_ID">' + jsonResponsetok.metadata.africanID + '</DATA>' 
                  + '<DATA name="AK_CUSTOMER_FIRST_NAME">' + jsonResponsetok.metadata.firstname + '</DATA>' 
                  + '<DATA name="AK_CUSTOMER_LAST_NAME">' + jsonResponsetok.metadata.lastname + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_EMAIL">' + jsonResponsetok.metadata.email + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_GENDER">' + gender + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_MOBILE_CODE">' + areacode + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_MOBILE_NUMBER">' + mobile + '</DATA>';

                  if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                    extrahead = extrahead.replace('</EXTRADATA>',AFRICANID_TAG+'</EXTRADATA>')
                  }
                  else {
                    extrahead = '<EXTRADATA>'+ AFRICANID_TAG + '</EXTRADATA>';
                  }
                 
                }

              }

              if(result_akani_payment) {
                let acctno = '<DATA name="AK_PAY_ACCN">'+ result_akani_payment.accountNumber +'</DATA>';
                let payref = '<DATA name="AK_PAY_REF">'+ result_akani_payment.reference +'</DATA>';
                let paydate = '<DATA name="AK_PAY_TXDATE">'+ result_akani_payment.transactionDate +'</DATA>';
                let paytxid = '<DATA name="AK_PAY_TXID">'+ result_akani_payment.transactionId +'</DATA>'

              

                let new_pin_expiry = '';
                let new_pin_balance = '';
                let new_pin_currency = '';
                let new_pin = '';
                let new_pin_serial = '';

                if(result_akani_payment.voucher.pin) {            
                  new_pin_expiry = '<DATA name="1V_EXPIRY">'+ result_akani_payment.voucher.expiryDate +'</DATA>';
                  new_pin_balance = '<DATA name="1V_AMOUNT">'+ result_akani_payment.voucher.amount +'</DATA>';
                  new_pin_currency = '<DATA name="1V_CURRENCY">'+ 'ZAR' +'</DATA>';
                  new_pin = '<DATA name="1V_PIN">'+ result_akani_payment.voucher.pin +'</DATA>';
                  new_pin_serial = '<DATA name="1V_SERIAL">'+ result_akani_payment.voucher.serialNumber +'</DATA>';
                }

                let ALL_TAGS = acctno + payref + paydate + paytxid + new_pin_expiry + new_pin_balance + new_pin_currency + new_pin + new_pin_serial;

                if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                  extrahead = extrahead.replace('</EXTRADATA>',ALL_TAGS +'</EXTRADATA>')
                }
                else {
                  extrahead = '<EXTRADATA>'+ ALL_TAGS + '</EXTRADATA>';
                }

              }
              let showBizzResp = ''; //</SHOWBIZZ>
              let refidurl = '';
              //Business in a box
            if(await isBusinesInABoxAkani(gtid,jsonResponsetok.metadata.ean,req)) {
              refidurl = 'https://' + req.hostname + '?REFID=' + jsonResponsetok.metadata.reference;
              let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + jsonResponsetok.metadata.reference + '</DATA>';
              if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                extrahead = extrahead.replace('</EXTRADATA>',REFID_URL_TAG+'</EXTRADATA>')
              }
              else {
                extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
              }

              showBizzResp = '<SHOWBIZZ>' + 'https://' + req.hostname + '?REFID=' + jsonResponsetok.metadata.reference  + '</SHOWBIZZ>';
              
            }


             
            const fetchOptions = {
                method: 'POST',

                body: '<REQUEST type="SALE" STORERECEIPT="1">' +
                  '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
                  '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                  tidhead +
                  cashierhead +
                  '<TXID>' + (jsonResponsetok.metadata.reference.includes('EPAY-undefined') ? jsonResponsetok.metadata.reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): jsonResponsetok.metadata.reference) + '</TXID>' +
                  '<USERNAME>' + userIdHost + '</USERNAME>' +
                  '<CARD>' +
                  PAN_TAG +
                  eanhead +                  
                  '</CARD>' +
                  '<AMOUNT>'+ (Number(jsonResponsetok.metadata.partialPay)+Number(jsonResponsetok.metadata.discount)).toString()  +'</AMOUNT>' +
                  CURRENTCY_TAG +
                  '<CONSUMER>' +
                  '<NAME>' + jsonResponsetok.metadata.firstname + '</NAME>' +
                  '<SURNAME>' + jsonResponsetok.metadata.lastname + '</SURNAME>' +
                 
                  send_sms_tag +
                  send_email_tag +
                  '<TITLE>' + jsonResponsetok.metadata.title + '</TITLE>' +
             
                   AK_CUSTOMER_ID +
                  '</CONSUMER>' +
                  extrahead +
                  '</REQUEST>',

                headers: {
                  'Content-Type': 'application/xml',
                },
      
              }
             
              console.log(log_prefix + 'SALE Request: ' + UPInterfaceURL + log_suffix);


              mask_xml_data(fetchOptions.body,log_prefix,log_suffix);

             const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
             var jsonResponse = await response.text();

             jsonResponse = await updateRedeemptionURL(jsonResponse);

              const UUID = require('pure-uuid');
              const id = new UUID(4).format();
              let encyptBlockTime = getTimeStamp();
     
              let block =  id + '/' + jsonResponsetok.metadata.reference + '.pkpass' + ',' + encyptBlockTime;
              let token = encrypt(block);
              let jsonResponse_log = jsonResponse ;
              jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
              
              console.log(log_prefix + 'SALE Response:' + log_suffix);
		
	            mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

            
              let encyptBlockTimeGMT = new Date();
              let passLink = 'https://' + req.hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();

              if(jsonResponse.includes('<RESULT>0</RESULT>'))
              {
              
                let activation_serial_tag = '<ACTIVATIONSERIAL>' + jsonResp.metadata.ActivationSerial + '</ACTIVATIONSERIAL>';
                let product_type_tag = '<PRODUCTTYPE>' + jsonResp.metadata.ProductTypeSale + '</PRODUCTTYPE>';
                let discount_tag = '<PROMODISCOUNT>0</PROMODISCOUNT>';;
                let promo_tag = '<PROMOCODE>none</PROMOCODE>' ;
                let currency_tag = '<CURRENCYCODEP>'+ jsonResp.metadata.CurrencyCodeProduct +'</CURRENCYCODEP>';
                let partial_tag = '<PARTIALPAY>'+jsonResp.metadata.partialPay+'</PARTIALPAY>' ;
                let apple_pass_tag = '<PASS>none</PASS>';
              
                if((await getApplePassAllowed(req.hostname)) == 'yes')
                {
                  apple_pass_tag = '<PASS>' + passLink + '</PASS>' ;
                } 

                if(jsonResp.metadata.promoApplied == '1')
                {
                  let promo_code = jsonResp.metadata.promoCode;
                  discount_tag = '<PROMODISCOUNT>' + jsonResp.metadata.discount + '</PROMODISCOUNT>';
                  promo_tag = '<PROMOCODE>' + 'xxxx' +promo_code.substring(promo_code.length - 4, promo_code.length) + '</PROMOCODE>';
             
                }

                let discRRP = await getDiscountRRP(jsonResponsetok.metadata.ean,gtid,req);
                let vat = await getItemVAT(req,jsonResponsetok.metadata.ean,gtid);
                let discountrrp_tag = '<PREDISCOUNTRRP>' + discRRP + '</PREDISCOUNTRRP>';
                let vat_tag = '<VAT>' + vat + '</VAT>';
                let flash_voucher_tag =  '<FLASHVOUCHER>none</FLASHVOUCHER>';
                if(jsonResponsetok.metadata.flashVoucher) {
                  if(jsonResponsetok.metadata.flashVoucher != 'none') {

                     flash_voucher_tag =  '<FLASHVOUCHER>' + 'Flash x' + jsonResponsetok.metadata.flashVoucher.substring(jsonResponsetok.metadata.flashVoucher.length - 4, jsonResponsetok.metadata.flashVoucher.length) + '</FLASHVOUCHER>';
                      try {
                      if(result_akani_payment.voucher.pin) {
                            let new_1voucher_pin_tag =  '<VOUCHERPIN>'+ result_akani_payment.voucher.pin + '</VOUCHERPIN>';
                            let new_1voucher_pin_serial_tag =  '<VOUCHERPINSERIAL>'+ result_akani_payment.voucher.serialNumber + '</VOUCHERPINSERIAL>';
                            let new_1voucher_pin_expiry_tag =  '<VOUCHERPINEXPIRY>' + result_akani_payment.voucher.expiryDate + '</VOUCHERPINEXPIRY>';
                            let amount = result_akani_payment.voucher.amount;
                            let str1 = 'R0.00';
                            if(amount > 99)
                                str1 = 'R' + amount.toString().substring(0, (amount.toString().length - 2)) + "." + amount.toString().substring((amount.toString().length - 2), amount.toString().length);
                            else if(amount > 9)
                                str1 = 'R0.' + amount.toString();
                            else if(amount > 0) 
                                str1 = 'R0.0' + amount.toString();


                            let new_1voucher_amount_tag =  '<VOUCHERPINAMOUNT>'+ str1 + '</VOUCHERPINAMOUNT>';

                            flash_voucher_tag = flash_voucher_tag + new_1voucher_pin_tag + new_1voucher_pin_serial_tag + new_1voucher_pin_expiry_tag + new_1voucher_amount_tag;
                      }
                    }catch (err) {
                      console.log('Exception result_akani_payment');
                      console.log(result_akani_payment);
                      console.log(err);
                    }
                  
                  }
                }

               let africanID_tag = ''; 
               if(isAkaniProduct) {
                  africanID_tag  = '<AFRICANID>' + jsonResponsetok.metadata.africanID  + '</AFRICANID>';
                  try {
                      let a = jsonResponse.split('<SERIAL>');
                      let a1 = a[1].split('</SERIAL>');
                      let serial = a1[0];
                      
                      let currencycode = 'AED';
                      let country_code = await getCountryCode(req.hostname);
                      if(country_code == 'ZA') {
                        currencycode = 'ZAR';
                      } else if(country_code == 'TR') {
                        currencycode = 'TRY';
                      } else if(country_code == 'SA') {
                        currencycode = 'SAR';
                      }

                      let getSymbolFromCurrency = require('currency-symbol-map');
                      let symbol = getSymbolFromCurrency(currencycode);
                      if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
                        symbol = '\u{2800}';
                      }
                      
                      let str = jsonResponsetok.metadata.partialPay;  
                      let amount_str = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);              
                      

                      let report = jsonResponsetok.metadata.firstname + ',' + jsonResponsetok.metadata.lastname + ',' +
                      jsonResponsetok.metadata.email + ',' + jsonResponsetok.metadata.phone + ',' +
                      jsonResponsetok.metadata.africanID + ',' + jsonResponsetok.metadata.product.replaceAll(',','') + ',' +
                      amount_str + ',' + serial + ',' + txnTime + ',' + jsonResponsetok.metadata.reference +  ',' + refidurl  ;

                      console.log(log_prefix + '<AKANI_REPORTING_TRANSACTION_DATA>' + report + '</AKANI_REPORTING_TRANSACTION_DATA>' + log_suffix );
                  } catch (err) {
                      console.log(log_prefix + 'Exception in report info log: ' + JSON.stringify(err) + log_suffix); 
                      console.log(err);               
                  }

                }
                jsonResponse = jsonResponse + '<CARDTYPE>' +   'PROMO x' + jsonResponsetok.metadata.promoCode.substring(jsonResponsetok.metadata.promoCode.length-4,jsonResponsetok.metadata.promoCode.length) + '</CARDTYPE>' +
                  '<PAID>' + jsonResponsetok.metadata.amt + '</PAID>' + '<PRODUCT>' + jsonResponsetok.metadata.product + '</PRODUCT>' +
                  '<SHORTDESC>' + shortdesciption + '</SHORTDESC>' + redeemptiondesciptiontag + longdescriptiontag + termstag + '<LOGO>' + jsonResponsetok.metadata.productlogo + '</LOGO>' +
                  '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>' + '<URLREDEEM>' + jsonResponsetok.metadata.redeemURL + '</URLREDEEM>' +
                  apple_pass_tag + discount_tag + promo_tag + currency_tag + partial_tag + activation_serial_tag + product_type_tag
                  + discountrrp_tag + vat_tag + flash_voucher_tag + africanID_tag + showBizzResp;     
           
                jsonResponse_log = jsonResponse ;
                jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

                mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
              }

              
              if (jsonResponse.includes('<RESULT>0</RESULT>')) {
                console.log(jsonResponsetok.metadata.reference);
                var strref = jsonResponsetok.metadata.reference;
                var arrRefSplit = strref.split('-');
                var actlink = jsonResponsetok.metadata.redeemURL;
                var productKey = '';
                var prodSerial = '';
                if (jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
                  var newarr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</DATA>');
                    actlink = arr1[0];
                  }
                }

                if (jsonResponse.includes('<PIN>')) {
                  var newarr = jsonResponse.split('<PIN>');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</PIN>');
                    productKey = arr1[0];
                  }
                }

                if (jsonResponse.includes('<SERIAL>')) {
                  var newarr = jsonResponse.split('<SERIAL>');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</SERIAL>');
                    prodSerial = arr1[0];
                  }
                }
                var prodExpiry = '';
                if (jsonResponse.includes('<VALIDTO>')) {
                  var newarr = jsonResponse.split('<VALIDTO>');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</VALIDTO>');
                    prodExpiry = arr1[0];
                    if (prodExpiry == '3000-01-01 00:00:00') {
                      prodExpiry = 'Never Expires';
                    }
                  }
                }
	           
                

          let emailToSend =  jsonResponsetok.metadata.email;
          let phoneToSend =  jsonResponsetok.metadata.phone;
          let emailTAG='';
          let phoneTAG = '';
          if(emailToSend)
          {
            if(emailToSend.length > 0)
            {
                emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
            }
          }
          if(phoneToSend)
          {
            if(phoneToSend.length > 0)
            {
                phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
            }
          }

          let allowed_google = await getGooglePassAllowed(req.hostname);
          let allowed_apple = await getApplePassAllowed(req.hostname);
              if((allowed_google == 'yes')||(allowed_apple == 'yes'))
              {
                try {
                  const findRemoveSync = require('find-remove');
              
                  if(allowed_google == 'yes') { 
                    let objGoogle = [];
                    objGoogle.push({
                    reference:jsonResponsetok.metadata.reference,
                    productLogo:jsonResponsetok.metadata.productlogo,
                    product:jsonResponsetok.metadata.product,
                    provider:jsonResponsetok.metadata.company,
                    serial:prodSerial,
                    expiry:prodExpiry,
                    amount:jsonResponsetok.metadata.amt,
                    pin:productKey,
                    //description:shortdesciption[0],
                    description:((shortdesciption[0].length > 1) ? shortdesciption[0]:shortdesciption),
                    tx_time:txnTime,
                    refSplit:arrRefSplit[1],
                    phone:jsonResponsetok.metadata.phone,
                    //terms:terms[0],
                    terms:((terms[0].length > 1) ? terms[0]:terms),
                    actlink:actlink,
                    providerLogo:jsonResponsetok.metadata.provLogo,
                    id:id,
                    stripe:''
                  });
                  await generateGooglePass(objGoogle[0]);
                
                  objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
                  let googlePassUrl = await createPassObject(objGoogle);

                  jsonResponse = jsonResponse + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
                  console.log('Response GPass: ' + googlePassUrl);
                  setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
                } else {
                  jsonResponse = jsonResponse + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';                 
                }
                                   
                  if(allowed_apple == 'yes')
                  {
                    await generatePass(jsonResponsetok.metadata.productlogo, jsonResponsetok.metadata.reference, jsonResponsetok.metadata.product, prodSerial, prodExpiry, jsonResponsetok.metadata.amt, productKey, ((shortdesciption[0].length > 1) ? shortdesciption[0]:shortdesciption), txnTime, arrRefSplit[1], jsonResponsetok.metadata.phone, ((terms[0].length > 1) ? terms[0]:terms), actlink, jsonResponsetok.metadata.provLogo, id);
                    setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
                  }
                
                }
                catch (err)
                {
                  console.log(log_prefix + err + log_suffix);
                }
              }
                console.log(jsonResponse);
                return (jsonResponse);
                
              }
              
              else{
                return (jsonResponse + '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>');
              }



            }
         
  
}



async function getCampaignHITCount(token)
{
  return campaignCounter.toString();
}

async function saveCampaignHITCount(count,token)
{ 
  fs.writeFileSync(configdir + 'campaign.txt',count, 'utf8');
}

async function getTokeLog(token)
{
  let strscript = 'sudo journalctl -o short-full  --unit=' + service_name + '| grep "Session token received: ' + token + '"' ;
      console.log('Executing search script token log'); 
      return (shell.exec(strscript));
}

app.get('/getPINCodeProxy', cors(corsOptions), limiter, async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPINCodeProxy => clientip: ' + clientip);
try {
  let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
  if(isIpTrusted)
  {

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {

      let body_token = Buffer.from(req.query.token,'base64').toString('utf8');
      let token_arr = body_token.split(',');
      let token = token_arr[0];
      let gtid = token_arr[1];


      if(await IsTokenAlreadyInCache(token)) {
        res.send('404');
        return;
      }

       
        
      if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
      {
         gtid = getDefaultTID(req.hostname,req);        
      }
      
      let use_checkout_key = '';
      let use_checkout_url = '';
      let bearer = '';
      let cred = await getCheckoutCredentials(req.hostname,req);
      if(cred)
      {
        use_checkout_key = cred.CheckoutSecretKey;
        use_checkout_url = cred.url;
        bearer = cred.prefix;
      }

      const fetchOptions1 = {
        method: 'GET',
        headers: {
          'Authorization': bearer + use_checkout_key,
          'Content-Type': 'application/json',
        },
      }
      var tokreq = use_checkout_url + '/' + token;
      const responsetok = await fetch(tokreq, fetchOptions1,proxy_url);

      console.log(responsetok);
      console.log(responsetok.status);

      if (responsetok.status != 404) {

        if (responsetok.status == 200) {        

          const jsonResponsetok = await responsetok.json();

         let session_id = jsonResponsetok.reference;
         let host_log = req.hostname.split('.');
         let method = 'GET_PINCODE_PROXY_SALE';
         let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         let log_suffix = '\n</LOG></SESSION_LOG>';         
         console.log(log_prefix + 'GET_PINCODE_SALE SESSION QUERY REQUEST: ' + tokreq + log_suffix);
         console.log(log_prefix + 'GET_PINCODE_SALE SESSION QUERY RESPONSE:' + log_suffix);

         console.log(log_prefix + req.headers.campaign + '>>API_CALL:getPINCode => clientip: ' + clientip + log_suffix);
          
          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);
          console.log(jsonResponsetok.metadata.ean);
          console.log(log_prefix + jsonResponsetok.status + log_suffix);

          let temp_data = jsonResponsetok.metadata.moreInfo;
           let temp_arr = temp_data.split(',');
           let promoApplied_add = temp_arr[0] ? temp_arr[0] : "";
           let discount_add = temp_arr[1] ? temp_arr[1] : "";
           let promoCode_add = temp_arr[2] ? temp_arr[2] : "";
           let ActivationSerial_add = temp_arr[3] ? temp_arr[3] : "";
           let ProductTypeSale_add = temp_arr[4] ? temp_arr[4] : "";
           let CurrencyCodeProduct_add = temp_arr[5] ? temp_arr[5] : "";
           let instore_add = temp_arr[6] ? temp_arr[6] : "";
           let gpay_add = temp_arr[7] ? temp_arr[7] : "";
           let delivery_add = temp_arr[8] ? temp_arr[8] : "";
           let flashVoucher_add = temp_arr[9] ? temp_arr[9] : "none";
           let africanID_add = temp_arr[10] ? temp_arr[10] : "none";
           let cashier_add = temp_arr[11] ? temp_arr[11] : "";


           jsonResponsetok.metadata['promoApplied'] = promoApplied_add;
           jsonResponsetok.metadata['discount'] = discount_add;
           jsonResponsetok.metadata['promoCode'] = promoCode_add;
           jsonResponsetok.metadata['ActivationSerial'] = ActivationSerial_add;
           jsonResponsetok.metadata['ProductTypeSale'] = ProductTypeSale_add;
           jsonResponsetok.metadata['CurrencyCodeProduct'] = CurrencyCodeProduct_add;
           jsonResponsetok.metadata['instore'] = instore_add;
           jsonResponsetok.metadata['gpay'] = gpay_add;
           jsonResponsetok.metadata['delivery'] = delivery_add;
           jsonResponsetok.metadata['flashVoucher'] = flashVoucher_add;
           jsonResponsetok.metadata['africanID'] = africanID_add;
           jsonResponsetok.metadata['cashier'] = cashier_add;

           delete jsonResponsetok.metadata['moreInfo'];

           console.log(log_prefix + JSON.stringify(jsonResponsetok) + log_suffix);

          //---------------------------------

          if (((jsonResponsetok.status == 'Captured')||(jsonResponsetok.status == 'Authorized')||(jsonResponsetok.status == 'Card Verified')) && (jsonResponsetok.approved == true) && (jsonResponsetok.metadata.instore == '0')) {

             let param_str = getFormattedTime() + ',' + jsonResponsetok.metadata.promoCode + ','+ jsonResponsetok.metadata.ean + ','+ jsonResponsetok.metadata.amount + ',' + jsonResponsetok.metadata.tid + ',' + jsonResponsetok.metadata.currency + ',' + jsonResponsetok.metadata.cashier + ',' + jsonResponsetok.metadata.firstname + ',' + jsonResponsetok.metadata.surname + ',' + jsonResponsetok.metadata.email + ',' + jsonResponsetok.metadata.phone + ',' + jsonResponsetok.metadata.title + ',' + 'yes';
            let param_str_b64 = Buffer.from(param_str).toString('base64'); 
          
            let jsonResp = await getProxyMultiCheckout(param_str_b64,clientip,req,jsonResponsetok);            
            console.log(jsonResp);
            res.send(jsonResp);         
          }
          else if (jsonResponsetok.approved == false) {
            console.log(log_prefix + 'notapproved' + log_suffix);
            if(jsonResponsetok.actions.length > 0)
            {
              let errorSharaf = '. ' + getMessageIDText('MESSAGEID_135',req);
                
              let errorText = await getCheckoutErrorResponse(jsonResponsetok,req);
              // jsonResponsetok.actions[0].type + getMessageIDText('MESSAGEID_136',req) + jsonResponsetok.actions[0].response_code + '. ' + jsonResponsetok.actions[0].response_summary + errorSharaf ;
              console.log(log_prefix + errorText + log_suffix);
              res.send('<RESPONSE><RESULT>' + jsonResponsetok.actions[0].response_code + '</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT><EAN>'+jsonResponsetok.metadata.ean+'</EAN><HOME>'+jsonResponsetok.metadata.home+'</HOME></RESPONSE>');
            }
            else{
              let err = await getCheckoutErrorResponse(jsonResponsetok,req);
              if(err.length)
                err = Buffer.from(err).toString('base64');
              res.statusCode = 400;
              console.log(log_prefix + 'notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err + log_suffix);
              res.send('notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err);
            }
            
          }
          else {
            console.log('failed1234');
            res.statusCode = 400;
            console.log(log_prefix + 'failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + log_suffix)
            res.send('failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean);
          }


        }
        else {
 
          console.log('failed2222');
          res.statusCode = 400;
          res.send(responsetok.status);
        }

      }
      else {

        console.log('404 error');
        res.statusCode = 404;
        res.send('404');
      }
    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

}
else
{  
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_111',req)+'</RESULTTEXT></RESPONSE>');
}
} catch(err) {
  console.log(err);
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>')
}

});

async function getItemCode(req,ean,tid,log_prefix,log_suffix) {

  let blockToParse = await getCatalog(req.hostname,tid,ean,0,req);       
    console.log('getItemCode==>>' + req.hostname + ',' + tid + ',' + ean);      
    let item_code = '';  
    let VAT = '';        
  if(blockToParse != 'no_data')
  {
    if(blockToParse.includes('<TECHNICAL_INFORMATION>')) {
      let a = blockToParse.split('<TECHNICAL_INFORMATION>');
      for(let i=1; i<a.length; i++) {
        let b = a[i].split('</TECHNICAL_INFORMATION>');
        if(b[0].includes('ITEMCODE=')) {
         let c = b[0].split('ITEMCODE=');
         if(c[1].length) {
           if(c[1].includes(',')) {
             let d = c[1].split(',');
             item_code = d[0];
           }
           else {
            item_code = c[1];
           }
           break;
         }
  
        }
      }
    }
    if(blockToParse.includes('<VAT>')) {
        let a = blockToParse.split('<VAT>');    
        let b = a[1].split('</VAT>');
        let c = b[0];
        if((c == '-1')||(c == '0')){
           VAT = '0';
        }
        else {
          VAT = '5';
        }
    }
  
    console.log(log_prefix + 'CARREFOUR ITEMCODE = ' + item_code + log_suffix);
    console.log(log_prefix + 'CARREFOUR ITEM VAT = ' + VAT + log_suffix);
    return item_code + ',' + VAT;

  }
  else {
    console.log(log_prefix + 'CARREFOUR EAN INFO NOT FOUND !!' + log_suffix);
    let item = ',';
    return item;
  }

}


async function uploadTxnCarrefour(sale_date,reference,serial,email,phone,name,last4,
               amount,ean,tid,product,req,log_prefix,log_suffix) {
try {
  let item_code_vat_str = await getItemCode(req,ean,tid,log_prefix,log_suffix);
  let item_code = '';
  let item_vat = '5';
  let vat_exempted = "false"
  if(item_code_vat_str.includes(',')) {
    let a = item_code_vat_str.split(',');
    if(a[0].length) {
      item_code = a[0];
    }
    if(a[1].length) {
      if((a[1] == '0')||(a[1] == '5')) {
        item_vat = a[1];
        if(item_vat == '0'){
          vat_exempted = "true";
        }
        else {
          vat_exempted = "false";
        }
     }
    }
  }
  let date = sale_date.split(' ');
  let time = date[1].replaceAll(':','');
  let order_reference = reference;
  if(order_reference.includes('-'))
  {
    let a = order_reference.split('-');
    let ref = a[1];  
    if(ref.length == 20)
    {
      order_reference = ref.substring(8,order_reference.length) ;
    }
    else {
      order_reference = ref;
    }
  }
  let amount_without_decimal = amount.substring(0,amount.length - 2);
  let amount_with_decimal = amount.substring(0,amount.length - 2) + '.' + amount.substring(amount.length - 2,amount.length);
  let req_body = 'invoiceJson=' + JSON.stringify({
      "sourceReference":carrefour_source_reference,// "EPAY_UAT",
      "date": date[0],// "2024-05-05", //sale_date
      "time": time,// "0544", //sale_date
      "storeNo": "099",
      "trxBarcode": 'EPAY-' + order_reference,// "EPAY475440", //reference
      "extOrderNo": serial,// "MA00000130", //Serial Numebr
      "invoiceOptions": "5",
      "webDelTime": "",
      "payments": [
          {
              "discountFlag": false,
              "cardNo": last4,//"", //last4
              "paymentType": "Credit Card",
              "cardHolderName": "", 
              "amount":amount_with_decimal
          }
      ],
      "UserAccessCode": carrefour_user_access_code, // "JXiJOgUroyK5ppxhsUy7/w==",
      "OrderBookingSource": carrefour_booking_source,//"EPAY",
      "customerEMail": email,// "jmoufarek@epayworldwide.com", //email
      "customerMobile":phone,// "", //phone
      "customerAddr": "",
      "customerName": name,//"Johnny", //name
      "items": [
          {
              "itemBarcode": ean,
              "itemQtyOrdered": "1",
              "itemQty": "1",
              "itemUnitPrice": amount_with_decimal,// amount_without_decimal,// "37",
              "totalPrice": amount_with_decimal,// amount_without_decimal,// "37", without decimal
              "delivery": "",
              "itemName": product,// "Sony PLaystation 10 USD",
              "itemName_Ar": product,// "",
              "delDate": "",
              "directDiscount": "0",
              "vatPercent":  item_vat,//"0",
              "vatExempted": vat_exempted,// "true",
              "chargeItem": "false",
              "sectionCode": "099",
              "departmentCode": "099",
              "itemCode": item_code,// "5227",
              "discountAmount": "0"
          }
      ],
      "orderDate": sale_date + '.0' //"2024-05-05 00:00:00.0" //sale date
  });
  
  const fetchOptions = {
    method: 'POST',
    body:req_body,
    headers: {
   // 'Content-Type': 'application/json'
    'Content-Type': 'application/x-www-form-urlencoded',
  //  'Cookie': '_abck=9723C6E819A6149C1154AD8A209C421A~-1~YAAQJdgsMYrfD0qIAQAASdI8Vgn8boHl77bgNZh6ufpTrIO4vvNdEVuOnEmyVl98vlD738p6DQbYS/nLhlR95JZk8izlB6Uj4zhQcJkQLmqHJrqBgxhWJPti7AaU9WPvNcVTU5ZoQH6qu5g2Xndwc98b0BZxepYpeUiZac3hGIfOgJ6CPHjY9IMDKtVKi96/iYaTlBjmTuJDC4za2J0dvLGuJb76JPBrHPZWHK8il3wHbWYiJVE95hpNvnhwRnJzNANlY7zZrmk/LG9g0gY41W3Q0PrjMhUTuQZ6B2ZsqjCcCksyq9P+Fzm1MfNgHgryXhYuuSsYgGgb2Tm+cwr5cqIskWybRNz30qjtof/kCEq1wYVrjGKY7XT/x9M=~-1~-1~-1'
    },
  }
  console.log(log_prefix + JSON.stringify(fetchOptions.body) + log_suffix);
  console.log(log_prefix + 'Txn upload request to carrefour url: ' + carrefour_url + log_suffix);
  const responsetok = await fetch(carrefour_url, fetchOptions,proxy_url);
  console.log(log_prefix +  responsetok.status + log_suffix);
  if (responsetok.status == 200) {
    const jsonResponsetok = await responsetok.json();
    console.log(log_prefix + JSON.stringify(jsonResponsetok) + log_suffix);
  }
  else {
    console.log(log_prefix + 'Carrefour request failed with status ' + responsetok.status + log_suffix);
  }

} catch(err) {
  console.log(err);
  console.log(log_prefix + 'Carrefour request failed with exception: ' + err + log_suffix);
}
}



async function isUploadRequired(req) {
  let host = (req.hostname.split('.'))[0];
  if(req.hostname == DOMAIN_0)
  {
     return domain0_upload_txn;
  } else if(req.hostname == DOMAIN_1)
  {
    return domain1_upload_txn;
  } else if(req.hostname == DOMAIN_2)
  {
    return domain2_upload_txn;
  } else
  if(req.hostname == DOMAIN_3)
  {
    return domain3_upload_txn;
  } else if(config[host]) {
    if(config[host].UPLOAD_TXN) {
      return config[host].UPLOAD_TXN;
    }
  } else {
    return 'no';
  }
}

async function checkAmountInRange(amount_fv,tid,ean,log_prefix,log_suffix,hostname,clientip,req) {
  console.log('tid:' + tid + '&& ean:' + ean);
  let blockToParse = await getCatalog(hostname,tid,ean,0,req);
    
  if(blockToParse != 'no_data')
  {  
    
    let arrm = blockToParse.split('MINAMOUNT="');
    let arrm_1 = arrm[1].split('"');
    let minamount = arrm_1[0];
    arrm = blockToParse.split('MAXAMOUNT="');
    arrm_1 = arrm[1].split('"');
    let maxamount = arrm_1[0];
    console.log(log_prefix + 'Max & Min amount for EAN: ' + minamount + '::' + maxamount + log_suffix);

    if((Number(maxamount) > 0)&&(Number(amount_fv) >= Number(minamount))&&(Number(amount_fv) <= Number(maxamount))) {
      return true;
    } else {
      return false;
    }      
  }
  else {
    console.log(log_prefix + 'Max & Min amount for EAN: none' + log_suffix);
    return false;
  }

}

let sid_checkout = [];
async function IsTokenAlreadyInCache(token) {
  let index = sid_checkout.map(function (sid) {return sid.token;}).indexOf(token);
  console.log('Token log index: ' + index);
  if(index >= 0) {
     return true;
  } else {
    sid_checkout.push({
        token:token,
        date: (new Date()).toString()
    })    
    return false;
  }
}

async function deleteTokenOlderThan15Minutes() {
  let date_current = new Date();
  for(let i=0; i<sid_checkout.length; i++) {
    let date = new Date(sid_checkout[i].date);    
    let dateDifference = Math.abs(date_current - date)/1000;
    if(dateDifference > 900){
      sid_checkout.splice(i,1);
    }
  }
}

async function getTestTID(hostname,product) {

  let host = (hostname.split('.'))[0];
  let result = '93889311'; //default test tid

  if(product.toLowerCase().includes('renewal')) {
    return '93889311';//'93880288';
  }
  if(hostname == DOMAIN_1)
    {
      if(config['domain_1']) {
      if(config['domain_1'].TestTID) {
        result = config['domain_1'].TestTID;
      }
     }
    }
    else if(hostname == DOMAIN_2)
    {
      if(config['domain_2']) {
        if(config['domain_2'].TestTID) {
          result = config['domain_2'].TestTID;
        }
      }
    }
    else if(hostname == DOMAIN_3)
    {
      if(config['domain_3']) {
        if(config['domain_3'].TestTID) {
          result = config['domain_3'].TestTID;
        }
      }
    }
    else if(hostname == DOMAIN_0)
    {
      if(config['domain_0']) {
        if(config['domain_0'].TestTID) {
          result = config['domain_0'].TestTID;
        }
      }
    } 
    else if(config[host]) {
      if(config[host].TestTID) {
        result = config[host].TestTID;
      }
    }

    return result;

}

app.get('/getPINCode', cors(corsOptions), limiter, async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPINCode => clientip: ' + clientip);
  console.log('req.headers.referer: '+req.headers.referer);


  try {

  let isIpBlocked = await isIPBlocked(clientip,req.hostname,req);
    if(isIpBlocked) {
       res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT></RESPONSE>');
       return;
    }


  let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
  if(isIpTrusted)
  {

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
   
      let body_token = Buffer.from(req.query.token,'base64').toString('utf8');
      let token_arr = body_token.split(',');
      let token = token_arr[0];
      let gtid = token_arr[1];


      if(await IsTokenAlreadyInCache(token)) {
        res.send('404');
        return;
      }
      
        
      if((gtid == '') || (gtid == 'undefined') || (gtid == 'notid'))
      {
         gtid = getDefaultTID(req.hostname,req);        
      }

       let pay_methods =  await getPaymentMethods(req.hostname);
      if(!pay_methods.includes('checkout')) {

        let session_id = 'SECURITY-ERROR';
         let host_log = req.hostname.split('.');
         let method = 'GET_PINCODE_SALE';
         let log_prefix_block = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         let log_suffix_block = '\n</LOG></SESSION_LOG>'; 
    
        let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid + ' Reason: GET_PIN_CODE_SALE Payment method not enabled'
        console.log(log_prefix_block + alert + log_suffix_block);
        if(BlockedIPs) {
          BlockedIPs = BlockedIPs + ',' + clientip;
        }else {
          BlockedIPs = clientip;
        }
        res.send('<RESPONSE><RESULT>151</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT><HOME>'+jsonResponsetok.metadata.home+'</HOME><EAN>'+jsonResponsetok.metadata.ean+'</EAN></RESPONSE>');
        return;
    
      }
      
      let use_checkout_key = '';
      let use_checkout_url = '';
      let bearer = '';
      let cred = await getCheckoutCredentials(req.hostname,req);
      if(cred)
      {
        use_checkout_key = cred.CheckoutSecretKey;
        use_checkout_url = cred.url;
        bearer = cred.prefix;
      }

      const fetchOptions1 = {
        method: 'GET',
        headers: {
          'Authorization': bearer + use_checkout_key,
          'Content-Type': 'application/json',
        },
      }
      var tokreq = use_checkout_url + '/' + token;
      const responsetok = await fetch(tokreq, fetchOptions1,proxy_url);

      console.log(responsetok);
      console.log(responsetok.status);

      if (responsetok.status != 404) {

        if (responsetok.status == 200) {        

          const jsonResponsetok = await responsetok.json();

         let session_id = jsonResponsetok.reference;
         let host_log = req.hostname.split('.');
         let method = 'GET_PINCODE_SALE';
         let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
         let log_suffix = '\n</LOG></SESSION_LOG>';         
         console.log(log_prefix + 'GET_PINCODE_SALE SESSION QUERY REQUEST: ' + tokreq + log_suffix);
         console.log(log_prefix + 'GET_PINCODE_SALE SESSION QUERY RESPONSE:' + log_suffix);

         console.log(log_prefix + req.headers.campaign + '>>API_CALL:getPINCode => clientip: ' + clientip + log_suffix);
          
          mask_json_data(JSON.stringify(jsonResponsetok),log_prefix,log_suffix);
          console.log(jsonResponsetok.metadata.ean);
          console.log(log_prefix + jsonResponsetok.status + log_suffix);

          

           let temp_data = jsonResponsetok.metadata.moreInfo;
           let temp_arr = temp_data.split(',');
           let promoApplied_add = temp_arr[0] ? temp_arr[0] : "";
           let discount_add = temp_arr[1] ? temp_arr[1] : "";
           let promoCode_add = temp_arr[2] ? temp_arr[2] : "";
           let ActivationSerial_add = temp_arr[3] ? temp_arr[3] : "";
           let ProductTypeSale_add = temp_arr[4] ? temp_arr[4] : "";
           let CurrencyCodeProduct_add = temp_arr[5] ? temp_arr[5] : "";
           let instore_add = temp_arr[6] ? temp_arr[6] : "";
           let gpay_add = temp_arr[7] ? temp_arr[7] : "";
           let delivery_add = temp_arr[8] ? temp_arr[8] : "";
           let flashVoucher_add = temp_arr[9] ? temp_arr[9] : "none";
           let africanID_add = temp_arr[10] ? temp_arr[10] : "none";
           let cashier_add = temp_arr[11] ? temp_arr[11] : "";

           jsonResponsetok.metadata['promoApplied'] = promoApplied_add;
           jsonResponsetok.metadata['discount'] = discount_add;
           jsonResponsetok.metadata['promoCode'] = promoCode_add;
           jsonResponsetok.metadata['ActivationSerial'] = ActivationSerial_add;
           jsonResponsetok.metadata['ProductTypeSale'] = ProductTypeSale_add;
           jsonResponsetok.metadata['CurrencyCodeProduct'] = CurrencyCodeProduct_add;
           jsonResponsetok.metadata['instore'] = instore_add;
           jsonResponsetok.metadata['gpay'] = gpay_add;
           jsonResponsetok.metadata['delivery'] = delivery_add;
           jsonResponsetok.metadata['flashVoucher'] = flashVoucher_add;
           jsonResponsetok.metadata['africanID'] = africanID_add;
           jsonResponsetok.metadata['cashier'] = cashier_add;

           delete jsonResponsetok.metadata['moreInfo'];

           //////////////////////////////////////////////
          let instore_txn = '0';
          if(jsonResponsetok.metadata.instore)
          {
	     instore_txn = '1';

          }

          //---------------------------------

          // ADD SECURITY BLOCK ALERT FOR [AMOUNT PAID + DISCOUNT != FV]
          let product_fv = '0';
          if (((jsonResponsetok.status == 'Captured')||(jsonResponsetok.status == 'Authorized')) 
             && (jsonResponsetok.approved == true)) {

              
              if((jsonResponsetok.metadata.product_type != '1')) {
                product_fv = await getAmountEAN(jsonResponsetok.metadata.tid,jsonResponsetok.metadata.ean,log_prefix,log_suffix,req.hostname,clientip,req);
              
                console.log(log_prefix + 'EAN (' + jsonResponsetok.metadata.ean + '): SECURITY CHECK:Product Amount: ' + product_fv + log_suffix);
              
                if(Number(product_fv) != (Number(jsonResponsetok.metadata.discount) +jsonResponsetok.amount)) {
                  // send security error
                  // SECURITY ALERT: Blocked Access: 182.62.151.162 TID: 93889311 Reason: Amount paid and discount not matched with FV
                  let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + jsonResponsetok.metadata.tid + ' Reason: Amount paid and discount not matched with FV'
                  console.log(log_prefix + alert + log_suffix);
                  if(BlockedIPs) {
                    BlockedIPs = BlockedIPs + ',' + clientip;
                  }else {
                    BlockedIPs = clientip;
                  }
                  res.send('<RESPONSE><RESULT>151</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT><HOME>'+jsonResponsetok.metadata.home+'</HOME><EAN>'+jsonResponsetok.metadata.ean+'</EAN></RESPONSE>');
                  return;
                }
              
            } else {
              //range check of paid amount + discount:: security error if not matched
               product_fv = (Number(jsonResponsetok.metadata.discount) +jsonResponsetok.amount).toString();
               let result = await checkAmountInRange(product_fv,jsonResponsetok.metadata.tid,jsonResponsetok.metadata.ean,log_prefix,log_suffix,req.hostname,clientip,req);
               if(!result) {
                // send security error
                let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + jsonResponsetok.metadata.tid + ' Reason: Amount paid and discount not matched with range value'
                console.log(log_prefix + alert + log_suffix);
                if(BlockedIPs) {
                  BlockedIPs = BlockedIPs + ',' + clientip;
                }
                else {
                  BlockedIPs = clientip;
                }
                res.send('<RESPONSE><RESULT>152</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT><HOME>'+jsonResponsetok.metadata.home+'</HOME><EAN>'+jsonResponsetok.metadata.ean+'</EAN></RESPONSE>');
                return;
               }
            }
                        

          }

          //---------------------------------

         

          if (((jsonResponsetok.status == 'Captured')||(jsonResponsetok.status == 'Authorized')||(jsonResponsetok.status == 'Card Verified')) && (jsonResponsetok.approved == true) && (jsonResponsetok.metadata.instore == '0')) {

           
            
           let shortdesciption = '';
           let longdescriptiontag = '';
           let redeemptiondesciptiontag = '';
           let terms = '';
           let termstag = '';
           let discountRRP_tag = '<PREDISCOUNTRRP>none</PREDISCOUNTRRP>';
           let host = req.hostname.split('.');
           let blockToParse = await getCatalog(req.hostname , jsonResponsetok.metadata.tid, jsonResponsetok.metadata.ean,0,req);
           
           if(blockToParse != 'no_data')
           {
            let lang = req.headers.campaign;
            if(lang && (language_list.includes(lang))) {
                  let jsonInfoXML = await getJSONInfoCatalog(blockToParse,req,true);            
                  //console.log('jsonInfoXML: ' + jsonInfoXML);
                  let a = jsonInfoXML.split('<INFOSJSON>');
                  let b = a[1].split('</INFOSJSON>');
                  if(b[0] != '{}') {
                    let jsonInfo = JSON.parse(b[0]);
                    console.log(JSON.stringify(jsonInfo[lang]));
                    desc = jsonInfo[lang].DESCRIPTION_SHORT[0];
                    redeemptiondesciptiontag = '<REDEEMDESC>' + jsonInfo[lang].DESCRIPTION_REDEMPTION[0] + '</REDEEMDESC>';
                    longdescriptiontag = '<LONGDESC>' + jsonInfo[lang].DESCRIPTION_LONG[0] + '</LONGDESC>';
                    termstag = '<TERMS>' + jsonInfo[lang].TERMS_AND_CONDITIONS[0] + '</TERMS>';
                    terms = jsonInfo[lang].TERMS_AND_CONDITIONS[0];
                    shortdesciption = jsonInfo[lang].DESCRIPTION_SHORT[0];
                  }
            } else {
                    var parseString = require('xml2js').parseString;
                    parseString(blockToParse, function (err, result) {
                      console.log(result.RESPONSE);
                      console.log(result.RESPONSE.INFOS);
                      let short_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_SHORT;
                      let long_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_LONG;
                      let redeem_desc = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].DESCRIPTION_REDEMPTION;
                    
                      if(redeem_desc.length)
                        redeemptiondesciptiontag = '<REDEEMDESC>' + redeem_desc + '</REDEEMDESC>';
                      
                      if(long_desc.length)
                        longdescriptiontag = '<LONGDESC>' + long_desc + '</LONGDESC>';

                      let desc = (short_desc.length > 0)? short_desc : long_desc;
                      shortdesciption = desc;
                      terms = result.RESPONSE.INFOS[0].INFO[Number(jsonResponsetok.metadata.info)].TERMS_AND_CONDITIONS;

                      if(terms.length)
                        termstag = '<TERMS>'+terms+'</TERMS>';
                      
                      
                    });
            }

              
              if((blockToParse.includes('<PREDISCOUNTRRP>'))&&(blockToParse.includes('</PREDISCOUNTRRP>')))
              {
                  let rrp_arr = blockToParse.split('<PREDISCOUNTRRP>');
                  if(rrp_arr.length)
                  {
                      let rrp_arr_1 = rrp_arr[1].split('</PREDISCOUNTRRP>');            
                      rrp =  rrp_arr_1[0];
                      discountRRP_tag = '<PREDISCOUNTRRP>' + rrp + '</PREDISCOUNTRRP>';
                  }
              }
           }
            
            var txnarr = jsonResponsetok.requested_on.toString().split(".");
            let metaTID = jsonResponsetok.metadata.tid;
            let up_cred = await getUPCredentials(req);

            var userIdHost = up_cred.userIdHost;
            var userPaswdHost = up_cred.userPaswdHost;

            let customer = up_cred.customer;
            

            console.log(txnarr);
            var txnTime = txnarr[0].replace('T', ' ');
            txnTime = txnTime.replace('Z','');
            console.log(txnTime);

            var ref = getTimeStamp();
            var refjsonarr = jsonResponsetok.metadata.reference.split('-');
            let reftxntemp = refjsonarr[1];
            //var inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + reftxntemp.substring(0,8);

            let reftxntemp2 = '';
            if(refjsonarr[2]){
              if(refjsonarr[2].length >= 9){
                reftxntemp2 = refjsonarr[2].substring(0,9);
              }
            }
            var inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + ((reftxntemp2.length == 9) ? reftxntemp2:reftxntemp.substring(0,8));


            let tidhead = '<TERMINALID>'+ metaTID +'</TERMINALID>';  
            
            if((metaTID == '') || (metaTID == 'undefined') || (metaTID == 'notid'))
            {
              let gtid = getDefaultTID(req.hostname,req);
              tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
            }

                                 
           
            {
              
              var extrahead = '';
              var eanhead = '<EAN>' + jsonResponsetok.metadata.ean + '</EAN>';
              var eantouse = jsonResponsetok.metadata.ean;
              if (jsonResponsetok.metadata.product.includes('Renewal') || jsonResponsetok.metadata.product.includes('renewal')) {
                extrahead = '<EXTRADATA>' +
                  '<DATA name="CONTRACT">' + jsonResponsetok.metadata.reference + '</DATA>' +
                  '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
                  '</EXTRADATA>';
                
              }

           

            if(jsonResponsetok.metadata.product.toLowerCase().includes('renewal')) {
              let info = await getTestSubscriptionInfo(req.hostname,jsonResponsetok.metadata.ean);
              if(info) {
               tidhead = '<TERMINALID>' + info.TestSubscriptionTID + '</TERMINALID>';
               eanhead = '<EAN>' + info.TestSubscriptionEAN + '</EAN>';
              }
           }

              let cashierhead = '';
              if(jsonResponsetok.metadata.cashier)
              {
                cashierhead = '<CASHIER>' + jsonResponsetok.metadata.cashier + '</CASHIER>';
              }
              let send_sms_tag = '';
              let send_email_tag = '';
          
              let delivery_m = null;
             
              let del_mode = getDeliveryMode(req.hostname,delivery_m);

              if(del_mode.includes('SMS'))
              {
                send_sms_tag = '<SMS>' + '+' + jsonResponsetok.metadata.phone + '</SMS>' ;
                
              }

              if(del_mode.includes('EMAIL'))
              {
                send_email_tag = '<EMAIL>' + jsonResponsetok.metadata.email + '</EMAIL>' ;                
              }
              let PAN_TAG = '';
              let CURRENTCY_TAG = '';

              if(jsonResponsetok.metadata.ProductTypeSale == 'POSA')
              {
                PAN_TAG = '<PAN>' + jsonResponsetok.metadata.ActivationSerial + '</PAN>';
                CURRENTCY_TAG = '<CURRENCY>' + jsonResponsetok.metadata.CurrencyCodeProduct + '</CURRENCY>';
              }
              
              let product_fv_sale = (jsonResponsetok.amount + Number(jsonResponsetok.metadata.discount)).toString();
              
            /*  if((jsonResponsetok._links.actions.href.includes('api.sandbox.checkout'))) {
                  let test_tid = await getTestTID(req.hostname,jsonResponsetok.metadata.product);
                  tidhead = '<TERMINALID>' + test_tid + '</TERMINALID>';
                  console.log(log_prefix + 'Checkout sandbox payment confirmation received. Test TID will be used for SALE.' + log_suffix);
              }*/
              
             

              if(jsonResponsetok.metadata.africanID) {
                if((jsonResponsetok.metadata.africanID != 'none')&&(jsonResponsetok.metadata.africanID.length)) {
                  let gender = ((jsonResponsetok.metadata.title == 'Mr') ? 'm' : 'f' );
                  let areacode = jsonResponsetok.metadata.phone.substring(0,jsonResponsetok.metadata.phone.length-9);
                  let mobile = jsonResponsetok.metadata.phone.substring(jsonResponsetok.metadata.phone.length-9,jsonResponsetok.metadata.phone.length);
                  let AFRICANID_TAG = '<DATA name="AK_CUSTOMER_ID">' + jsonResponsetok.metadata.africanID + '</DATA>' 
                  + '<DATA name="AK_CUSTOMER_FIRST_NAME">' + jsonResponsetok.metadata.firstname + '</DATA>' 
                  + '<DATA name="AK_CUSTOMER_LAST_NAME">' + jsonResponsetok.metadata.lastname + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_EMAIL">' + jsonResponsetok.metadata.email + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_GENDER">' + gender + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_MOBILE_CODE">' + areacode + '</DATA>'
                  + '<DATA name="AK_CUSTOMER_MOBILE_NUMBER">' + mobile + '</DATA>';

                  if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                    extrahead = extrahead.replace('</EXTRADATA>',AFRICANID_TAG+'</EXTRADATA>')
                  }
                  else {
                    extrahead = '<EXTRADATA>'+ AFRICANID_TAG + '</EXTRADATA>';
                  }
                 
                }

              }

               //Business in a box
              if(await isBusinesInABoxAkani(gtid,jsonResponsetok.metadata.ean,req)) {
                let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + jsonResponsetok.reference + '</DATA>';
                if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                  extrahead = extrahead.replace('</EXTRADATA>',REFID_URL_TAG+'</EXTRADATA>')
                }
                else {
                  extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
                }
                
              }

              const fetchOptions = {
                method: 'POST',

                body: '<REQUEST type="SALE" STORERECEIPT="1">' +
                  '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
                  '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                  tidhead +
                  cashierhead +
                  '<TXID>' + (jsonResponsetok.reference.includes('EPAY-undefined') ? jsonResponsetok.reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): jsonResponsetok.reference)
                   + '</TXID>' +
                  '<USERNAME>' + userIdHost + '</USERNAME>' +
                  '<CARD>' +
                  PAN_TAG +
                  eanhead +                  
                  '</CARD>' +
                  '<AMOUNT>'+ product_fv_sale +'</AMOUNT>' + //jsonResponsetok.amount 
                  '<Comment>' + 'PaymentMethod=card|</Comment>' +
                  CURRENTCY_TAG +
                  '<CONSUMER>' +
                  '<NAME>' + jsonResponsetok.metadata.firstname + '</NAME>' +
                  '<SURNAME>' + jsonResponsetok.metadata.lastname + '</SURNAME>' +
                 
                  send_sms_tag +
                  send_email_tag +
                  '<TITLE>' + jsonResponsetok.metadata.title + '</TITLE>' +
              
                  '<CUSTOMERID>' + (jsonResponsetok.customer ? jsonResponsetok.customer.id : jsonResponsetok.metadata.email) + '</CUSTOMERID>' +
                  '</CONSUMER>' +
                  extrahead +
                  '</REQUEST>',

                headers: {
                  'Content-Type': 'application/xml',
                },
      
              }
             
              console.log(log_prefix + 'SALE Request: ' + UPInterfaceURL + log_suffix);


              mask_xml_data(fetchOptions.body,log_prefix,log_suffix);

             const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
             var jsonResponse = await response.text();

             jsonResponse = await updateRedeemptionURL(jsonResponse);

              const UUID = require('pure-uuid');
              const id = new UUID(4).format();
              let encyptBlockTime = getTimeStamp();
     
              let block =  id + '/' + jsonResponsetok.metadata.reference + '.pkpass' + ',' + encyptBlockTime;
              let token = encrypt(block);
              let jsonResponse_log = jsonResponse ;
              jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
              
              console.log(log_prefix + 'SALE Response:' + log_suffix);
		
	            mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

         
               let encyptBlockTimeGMT = new Date();
               let passLink = 'https://' + req.hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();

              if(jsonResponse.includes('<RESULT>0</RESULT>'))
              {

                let serial_upload = '';
            
                if (jsonResponse.includes('<SERIAL>')) {
                  let newarr = jsonResponse.split('<SERIAL>');
                  if (newarr.length > 1) {
                    let arr1 = newarr[1].split('</SERIAL>');
                    serial_upload = arr1[0];
                  }
                }
                let uploadTxn = await isUploadRequired(req);
                if(uploadTxn == 'yes')
                {
                await uploadTxnCarrefour(txnTime,jsonResponsetok.metadata.reference,serial_upload,
                  jsonResponsetok.metadata.email,jsonResponsetok.metadata.phone,
                  jsonResponsetok.metadata.firstname + ' ' + jsonResponsetok.metadata.lastname,
                  jsonResponsetok.source.last4,jsonResponsetok.amount.toString(),jsonResponsetok.metadata.ean,
                  jsonResponsetok.metadata.tid,jsonResponsetok.metadata.product,req,log_prefix,log_suffix);
	              }

                 let product_vat = '0';
                let item_code_vat_str = await getItemCode(req,jsonResponsetok.metadata.ean,jsonResponsetok.metadata.tid,log_prefix,log_suffix);
                if(item_code_vat_str.includes(',')) {
                   let a = item_code_vat_str.split(',');
                   if(a[1].length) {
                    product_vat = a[1];
                   }
                }
           


                let activation_serial_tag = '<ACTIVATIONSERIAL>' + jsonResponsetok.metadata.ActivationSerial + '</ACTIVATIONSERIAL>';
                let product_type_tag = '<PRODUCTTYPE>' + jsonResponsetok.metadata.ProductTypeSale + '</PRODUCTTYPE>';
                let discount_tag = '<PROMODISCOUNT>0</PROMODISCOUNT>';;
                let promo_tag = '<PROMOCODE>none</PROMOCODE>' ;
                let currency_tag = '<CURRENCYCODEP>'+ jsonResponsetok.metadata.CurrencyCodeProduct +'</CURRENCYCODEP>';
                let amount_part = (jsonResponsetok.status == 'Card Verified') ? '000' : jsonResponsetok.amount;
                let partial_tag = '<PARTIALPAY>'+ amount_part +'</PARTIALPAY>' ;

                if(jsonResponsetok.metadata.promoApplied == '1')
                {
                  let promo_code = jsonResponsetok.metadata.promoCode;
                  discount_tag = '<PROMODISCOUNT>' + jsonResponsetok.metadata.discount + '</PROMODISCOUNT>';
                  promo_tag = '<PROMOCODE>' + 'xxxx' +promo_code.substring(promo_code.length - 4, promo_code.length) + '</PROMOCODE>';
              
                }
                jsonResponse = jsonResponse + '<CARDTYPE>' + jsonResponsetok.source.scheme + ' x' + jsonResponsetok.source.last4 + '</CARDTYPE>' +
                  '<PAID>' + jsonResponsetok.metadata.amt + '</PAID>' + '<PRODUCT>' + jsonResponsetok.metadata.product + '</PRODUCT>' +
                  '<SHORTDESC>' + shortdesciption + '</SHORTDESC>' + redeemptiondesciptiontag + longdescriptiontag + termstag + '<LOGO>' + jsonResponsetok.metadata.productlogo + '</LOGO>' +
                  '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>' + '<URLREDEEM>' + jsonResponsetok.metadata.redeemURL + '</URLREDEEM>' +
                  '<PASS>' + passLink + '</PASS>' + discount_tag + promo_tag + currency_tag + partial_tag + activation_serial_tag + product_type_tag +
                    '<VAT>' + product_vat + '</VAT>' + discountRRP_tag;     
           
                jsonResponse_log = jsonResponse ;
                jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

                mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
              }

              
              if (jsonResponse.includes('<RESULT>0</RESULT>')) {
                console.log(jsonResponsetok.metadata.reference);
                var strref = jsonResponsetok.metadata.reference;
                var arrRefSplit = strref.split('-');
                var actlink = jsonResponsetok.metadata.redeemURL;
                var productKey = '';
                var prodSerial = '';
                if (jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
                  var newarr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</DATA>');
                    actlink = arr1[0];
                  }
                }

                if (jsonResponse.includes('<PIN>')) {
                  var newarr = jsonResponse.split('<PIN>');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</PIN>');
                    productKey = arr1[0];
                  }
                }

                if (jsonResponse.includes('<SERIAL>')) {
                  var newarr = jsonResponse.split('<SERIAL>');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</SERIAL>');
                    prodSerial = arr1[0];
                  }
                }
                var prodExpiry = '';
                if (jsonResponse.includes('<VALIDTO>')) {
                  var newarr = jsonResponse.split('<VALIDTO>');
                  if (newarr.length > 1) {
                    var arr1 = newarr[1].split('</VALIDTO>');
                    prodExpiry = arr1[0];
                    if (prodExpiry == '3000-01-01 00:00:00') {
                      prodExpiry = 'Never Expires';
                    }
                  }
                }
	           
                

          let emailToSend =  jsonResponsetok.metadata.email;
          let phoneToSend =  jsonResponsetok.metadata.phone;
          let emailTAG= '<EMAIL></EMAIL>';
          let phoneTAG = '<PHONE></PHONE>';
          if(emailToSend)
          {
            if(emailToSend.length > 0)
            {
                emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
            }
          }
          if(phoneToSend)
          {
            if(phoneToSend.length > 0)
            {
                phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
            }
          }

         
                if (((jsonResponsetok.metadata.product.includes('Renewal')) || jsonResponsetok.metadata.product.includes('renewal'))) {

                
		              console.log(jsonResponsetok._links.actions.href);
                  let auth_code = await getAuthCode(jsonResponsetok._links.actions.href,gtid,req.hostname,log_prefix,log_suffix,req);
                  console.log(log_prefix + 'auth_code: ' + auth_code + log_suffix);
                  if(auth_code != 'none')
                  {
                    auth_code = '-' + auth_code;
                  }
                  else
                  {
                    auth_code = '';
                  }
                  console.log(auth_code);

                  const fetchOptionsInfo = {
                    method: 'POST',
  
                    body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
                      '<USERNAME>' + userIdHost + '</USERNAME>' +
                      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                      tidhead +
                      '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
                      '<TXID>' + (inforef.includes('EPAY-undefined') ? inforef.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): inforef) + '</TXID>' + //'-' + jsonResponsetok.source.bin + auth_code 
                      '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
                      '<SUBSCRIPTION>' +
                      '<TOKENID>' + jsonResponsetok.source.id + '</TOKENID>' +
                      '<LASTFOUR>' + jsonResponsetok.source.last4 + '</LASTFOUR>' +
                      '<CARDTYPE>' + jsonResponsetok.source.scheme + '</CARDTYPE>' +
                      '<PAYMENTID>' + jsonResponsetok.id + '</PAYMENTID>' +
                      emailTAG +
                      phoneTAG +
                      '<BIN>' + jsonResponsetok.source.bin + '</BIN>' +
  	     	            '<AUTHCODE>' + auth_code.replace('-','') + '</AUTHCODE>' +
                      '</SUBSCRIPTION>' +
                      '<TRANSACTIONREF>' +
                      '<REFTYPE>SERIAL</REFTYPE>' +
                      '<REF>' + jsonResponsetok.metadata.reference + '</REF>' +
                      '</TRANSACTIONREF>' +
                      '</REQUEST>',
  
                    headers: {
                      'Content-Type': 'application/xml',
                    },
              
                  }

               
                console.log(log_prefix + 'PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
                mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
                console.log(log_prefix + paymentInfoURL + log_suffix);
               const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
               var jsonResponseInfo = await response.text();
             
              console.log(log_prefix + 'PAYMENTINFO Response:' + log_suffix);
              let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
                mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);

                }

                try {
                  const findRemoveSync = require('find-remove');
                  let allowed_google = await getGooglePassAllowed(req.hostname);
                  let allowed_apple = await getApplePassAllowed(req.hostname);
                  if(allowed_google == 'yes') { 
                    let objGoogle = [];
                    objGoogle.push({
                    reference:jsonResponsetok.metadata.reference,
                    productLogo:jsonResponsetok.metadata.productlogo,
                    product:jsonResponsetok.metadata.product,
                    provider:jsonResponsetok.metadata.company,
                    serial:prodSerial,
                    expiry:prodExpiry,
                    amount:jsonResponsetok.metadata.amt,
                    pin:productKey,
                    //description:shortdesciption[0],
                    description:((shortdesciption[0].length > 1) ? shortdesciption[0]:shortdesciption),
                    tx_time:txnTime,
                    refSplit:arrRefSplit[1],
                    phone:jsonResponsetok.metadata.phone,
                    terms: ((terms[0].length > 1) ? terms[0]:terms ),
                    actlink:actlink,
                    providerLogo:jsonResponsetok.metadata.provLogo,
                    id:id,
                    stripe:''
                  });
                  await generateGooglePass(objGoogle[0]);
               
                 objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
                 let googlePassUrl = await createPassObject(objGoogle);

                  jsonResponse = jsonResponse + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
                  console.log('Response GPass: ' + googlePassUrl);
                  setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
                } else {
                  jsonResponse = jsonResponse + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';
                }

              
                  if(allowed_apple == 'yes')
                  {
                    await generatePass(jsonResponsetok.metadata.productlogo, jsonResponsetok.metadata.reference, jsonResponsetok.metadata.product, prodSerial, prodExpiry, jsonResponsetok.metadata.amt, productKey, ((shortdesciption[0].length > 1) ? shortdesciption[0]:shortdesciption), txnTime, arrRefSplit[1], jsonResponsetok.metadata.phone, ((terms[0].length > 1) ? terms[0]:terms), actlink, jsonResponsetok.metadata.provLogo, id);
                    setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
                  }                 
                   
                   
                }
                catch (err)
                {
                  console.log(log_prefix + err + log_suffix);
                }
                await sendOrderSuccessMessage_ib(jsonResponse,jsonResponsetok.metadata.phone,req,log_prefix,log_suffix);

                res.send(jsonResponse);
                
              }
              else if(jsonResponse.includes('<RESULT>34</RESULT>')) {

                let session_id = 'SECURITY-ERROR';
                let host_log = req.hostname.split('.');
                let method = 'GET_PINCODE_SALE';
                let log_prefix_block = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
                let log_suffix_block = '\n</LOG></SESSION_LOG>'; 
            
                let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid + ' Reason: GET_PIN_CODE_SALE Transaction Duplicated.'
                console.log(log_prefix_block + alert + log_suffix_block);
                if(BlockedIPs) {
                  BlockedIPs = BlockedIPs + ',' + clientip;
                }else {
                  BlockedIPs = clientip;
                }
                let resp = '<RESPONSE><RESULT>151</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT><HOME>'+jsonResponsetok.metadata.home+'</HOME><EAN>'+jsonResponsetok.metadata.ean+'</EAN></RESPONSE>';
                res.send(resp);
                return;

              }
              else{
                let refund_status_card_txn = false;
                let refund_status_promo_txn = false;
                let refund_status = getMessageIDText('MESSAGEID_180',req) + await getCustomerName(req.hostname) + getMessageIDText('MESSAGEID_133',req);
                if(jsonResponsetok.metadata.partialPay != '0')
                {
                  let act_id = await getActionIdCaptureCheckout(jsonResponsetok.id,log_prefix,log_suffix,jsonResponsetok.metadata.tid,req.hostname,req);
                  if((act_id != 'none')&&(act_id.includes('act_')))
                  {            
                    let response = await processRefundCheckout(jsonResponsetok.amount,jsonResponsetok.reference + '_r',act_id,jsonResponsetok.id,jsonResponsetok.metadata.ean,jsonResponsetok.metadata.tid,jsonResponsetok.reference,customer,log_prefix,log_suffix,req.hostname,req);
                    response = response.replace('</RESPONSE>','<CUSTOMER>' + customer + '</CUSTOMER></RESPONSE>');
                    console.log(log_prefix +  response + log_suffix);
                    if(response.includes('<RESULT>0</RESULT>'))
                    {
                      refund_status_card_txn = true;
                    }                 
                  }
                }
                else {
                  refund_status_card_txn = true;
                }
                if((jsonResponsetok.metadata.promoApplied == '1')&&(jsonResponsetok.metadata.discount != '0')) {
                  let promocode = jsonResponsetok.metadata.promoCode;                 
                  let a1 = tidhead.split('<TERMINALID>');
                  let a2 = a1[1].split('</TERMINALID>');
                  let tid_used = a2[0];
                    let result_refund_promo = await refundPromoDiscount(tid_used,jsonResponsetok.metadata.reference, promocode,log_prefix,log_suffix,req);
                    console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                    if(result_refund_promo.includes('<RESULT>0</RESULT>'))
                    {
                      refund_status_promo_txn = true;                                       
                    }  
                    
                 } else {
                  refund_status_promo_txn = true;
                 }

                 if((refund_status_card_txn == true) && (refund_status_promo_txn == true))
                 {
                  //refund_status = 'Your refund for this transaction is processed successfully.';
                  refund_status = getMessageIDText('MESSAGEID_179',req);
                 } 
                 else {
                  refund_status = getMessageIDText('MESSAGEID_180',req) + await getCustomerName(req.hostname) + getMessageIDText('MESSAGEID_133',req);
                 }          
                 

                jsonResponse = jsonResponse.replace('</RESULTTEXT>', '\n' + refund_status + '</RESULTTEXT>');
                res.send(jsonResponse + '<HOME>' + jsonResponsetok.metadata.home + '</HOME>' + '<EAN>' + jsonResponsetok.metadata.ean +'</EAN>');
              }

            }
         
          }
          else if (jsonResponsetok.approved == false) {
            console.log(log_prefix + 'notapproved' + log_suffix);
            if(jsonResponsetok.actions.length > 0)
            {
              let errorSharaf = '. '+ getMessageIDText('MESSAGEID_135',req);
                
              let errorText = await getCheckoutErrorResponse(jsonResponsetok,req);
              //jsonResponsetok.actions[0].type + getMessageIDText('MESSAGEID_136',req) + jsonResponsetok.actions[0].response_code + '. ' + jsonResponsetok.actions[0].response_summary + errorSharaf ;
              console.log(log_prefix + errorText + log_suffix);
              res.send('<RESPONSE><RESULT>' + jsonResponsetok.actions[0].response_code + '</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT><EAN>'+jsonResponsetok.metadata.ean+'</EAN><HOME>'+jsonResponsetok.metadata.home+'</HOME></RESPONSE>');
            }
            else
            {
              let err = await getCheckoutErrorResponse(jsonResponsetok,req);
              if(err.length)
                err = Buffer.from(err).toString('base64');
              res.statusCode = 400;
              console.log(log_prefix + 'notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err + log_suffix);
              res.send('notapproved,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + ',' + err);
            }
                        
          }
          else {
            console.log('failed1234');
            res.statusCode = 400;
            console.log(log_prefix + 'failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean + log_suffix)
            res.send('failed,' + jsonResponsetok.metadata.home + ',' + jsonResponsetok.metadata.ean);
          }


        }
        else {
 
          console.log('failed2222');
          res.statusCode = 400;
          res.send(responsetok.status);
        }

      }
      else {

        console.log('404 error');
        res.statusCode = 404;
        res.send('404');
      }
    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

}
else
{
  
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_111',req)+'</RESULTTEXT></RESPONSE>');
}

} catch(err) {
  console.log(err);
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_165',req)+'</RESULTTEXT></RESPONSE>');
}

});


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


app.get('/redeemNow', cors(corsOptions), async (req, res) => {

  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:redeemNow => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {

  try {
    
  //let body = req.query.body;
  let body = Buffer.from(req.query.body,'base64').toString('utf8');
  console.log(body);
  let arr = body.split(',');
  let contract =  arr[1]; 
  let ean = arr[2]; 
  let localdate = arr[0];

  let session_id = contract;
  let host_log = req.hostname.split('.');
  let method = 'REDEEM_NOW';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';
  
  console.log(log_prefix + req.headers.campaign + '>>API_CALL:redeemNow => clientip: ' + clientip + log_suffix);

  var timeCurr = getTimeStamp();
  var decryptedString = decrypt(arr[5]);
  var tmA = decryptedString.split(',');
  if (tmA.length > 0) {

      console.log(timeCurr + '::' + tmA[1]);
      if (Number(await date_difference(timeCurr,tmA[1])) > 300) {
        console.log(log_prefix + 'Session Expired' + log_suffix);
        let customer = await getCustomerName(req.hostname);
        let support_url = await getDomainSupportUrl(req.hostname);
        let str = 'Sorry, Session Expired. Please login again or contact '+ customer +getMessageIDText('MESSAGEID_103',req)+ support_url;


        let response_to_send = '<RESPONSE><RESULT>108</RESULT><RESULTTEXT>' + str + '</RESULTTEXT></RESPONSE>';;
        res.send(response_to_send);
      }
      else {
        const hashValue = crypto.createHash('sha256', secret).update(arr[3]).digest('hex');
        //if(hashValue == arr[4]) { 
        if((hashValue == arr[4]) ||(otpTest && (arr[3] == otpTest)))  {       
  
          let arr_cont = contract.split('-');
          let phone = arr_cont[2];
         
          let ref =  getTimeStamp() + '0';
          let reference = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;
          if(!((await checkIfVodacomFlow(req.hostname)) == 'yes') )
          {
            //add epay prefix
       
            if(contract.substring(0,5) == 'EPAY-')
            {
              reference = 'EPAY-' + contract.substring(5,13) + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;
            }
            else
              reference = 'EPAY-' + contract.substring(0,8) + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;
          }

          let TERMINAL_ID = defaultTID_domain_2;
          
          let up_cred = await getUPCredentials(req);
          let userIdHost = up_cred.userIdHost;
          let userPaswdHost = up_cred.userPaswdHost;

          if(contract.includes('-')) {
            let arr = contract.split('-');
            if(arr[0] == 'EPAY') {
              if(arr[1].length == 20) {
                TERMINAL_ID = arr[1].substring(0,8);
              } else {
                TERMINAL_ID = getDefaultTID(req.hostname,req);
              }
            } else {
              if(arr[0].length == 20) {
                TERMINAL_ID = arr[0].substring(0,8);
              } else {
                TERMINAL_ID = getDefaultTID(req.hostname,req);
              }
            }

          }
          else {
            if(contract.length == 20) {
              TERMINAL_ID = contract.substring(0,8);
            } else {
              TERMINAL_ID = getDefaultTID(req.hostname,req);
            }
          }         
          
        
          
          let info = await getTestSubscriptionInfo(req.hostname,ean) 
          if(info) {           
                TERMINAL_ID = info.TestTIDSUBSCRIPTION ;            
          }



        
         const fetchOptions = {
            method: 'POST',

            body: '<REQUEST type="SALE" mode="REPRINT,NOSMS" version="3" STORERECEIPT="1" >' +
              '<USERNAME>' + userIdHost + '</USERNAME>' +
              '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
              '<TERMINALID>' + TERMINAL_ID + '</TERMINALID>' +
              '<LOCALDATETIME>' + localdate + '</LOCALDATETIME>' +
              '<TXID>' + reference + '</TXID>' +
              '<TXREF>'+ contract +'</TXREF>' +      
              '<PRODUCTID>'+ ean +'</PRODUCTID>' +  
              '</REQUEST>',

            headers: {
              'Content-Type': 'application/xml',
            },

          }
          
          console.log(log_prefix + 'REPRINT REQUEST FOR REDEEM NOW:' + UPInterfaceURL + log_suffix);
          mask_xml_data(log_prefix + fetchOptions.body + log_suffix);
          const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
          var jsonResponse = await response.text();
          jsonResponse = await updateRedeemptionURL(jsonResponse);      
          let jsonResponse_log = jsonResponse;
          jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
          mask_xml_data(log_prefix + jsonResponse_log + log_suffix);
          //console.log(jsonResponse);
          if(jsonResponse.includes('<RESULT>0</RESULT>'))
          {
            let response_to_send = '';
            if(jsonResponse.includes('<REDEMPTIONURL>'))
            {
              let data_arr = jsonResponse.split('<REDEMPTIONURL>');
              let data_arr_2 = data_arr[1].split('</REDEMPTIONURL>');
              let redeemLink = data_arr_2[0];
              response_to_send = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT><REEDEMPTIONURL>' +
                                redeemLink +'</REEDEMPTIONURL></RESPONSE>';
              console.log(log_prefix + 'Redeem Link Send Successful.' + log_suffix);
              res.send(response_to_send);
            }
	          else if(jsonResponse.includes('<DATA name="REDEMPTIONURL">'))
            {
              let data_arr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
              let data_arr_2 = data_arr[1].split('</DATA>');
              let redeemLink = data_arr_2[0];
              response_to_send = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT><REEDEMPTIONURL>' +
                                redeemLink +'</REEDEMPTIONURL></RESPONSE>';
              console.log(log_prefix + 'Redeem Link Send Successful.' + log_suffix);
              res.send(response_to_send);
            }
            else
            {
              let customer = await getCustomerName(req.hostname);
              let support_url = await getDomainSupportUrl(req.hostname);
              let str = getMessageIDText('MESSAGEID_141',req) + customer +getMessageIDText('MESSAGEID_103',req)+ support_url;
              let response_to_send = '<RESPONSE><RESULT>109</RESULT><RESULTTEXT>' + str + '</RESULTTEXT></RESPONSE>';
              console.log(log_prefix + 'No Redeem Link Avaialble.' + log_suffix);
              res.send(response_to_send);
            }

          }
          else
          {
            res.send(jsonResponse);
          }

        }
        else {
          console.log(log_prefix + getMessageIDText('MESSAGEID_142',req) + log_suffix);
          response_to_send = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_142',req) + '</RESULTTEXT></RESPONSE>';
          res.send(response_to_send);
        }
    }

  }
  else {
    response_to_send = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_142',req)+'</RESULTTEXT></RESPONSE>';
    res.send(response_to_send);
    }
  } catch (error) {
    console.log(error);
    let customer = await getCustomerName(req.hostname);
    let support_url = await getDomainSupportUrl(req.hostname);
    let str = getMessageIDText('MESSAGEID_102',req) + customer +getMessageIDText('MESSAGEID_103',req)+ support_url;
              
    
    res.send('<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+str+'</RESULTTEXT></RESPONSE>');
  }

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

});

async function checkIfVodacomFlow(hostname) {

    let result = 'no';

    let pay_methods = await getPaymentMethods(hostname);
    let country_code = await getCountryCode(hostname);
    
    if((pay_methods.includes('vodacom_xml'))&&(country_code == 'ZA')) {
      result = 'yes';
    }
  
    return result;
  

}



async function updateDescription(jsonResponseContracts,hostname,req)
{
  let country_code = await getCountryCode(req.hostname);
  let bVodacom = false; 
  if((await checkIfVodacomFlow(req.hostname)) == 'yes'){
    bVodacom = true;
  }
  let longDescriptionEN = '';
  let shortDescriptionEN = '';
  let jsonResponse = jsonResponseContracts;

  let tid = getDefaultTID(req.hostname,req);
  

  let host = hostname.split('.');

  let catalogData = await getCatalog(hostname,tid,'',1,req);

  let add_info_inactive = '';
  if(jsonResponse.includes('<RESULT>0</RESULT>')&& !jsonResponse.includes('<CATALOG />'))
  {
      var parseString_resp = require('xml2js').parseString;
      parseString_resp(jsonResponse, async function (err, result) {
 
      let subscriptions = result.RESPONSE.SUBSCRIPTIONS[0].SUBSCRIPTION;
      if(subscriptions)
      {
        for(let k=0; k<subscriptions.length; k++)
        {
          let cancel_date_tag = '';
          let contract = subscriptions[k].CONTRACT;
          let ean = subscriptions[k].PRODUCTID; 
	        let amount_tag = '';
          let productdisplayName = '';
          if(catalogData.includes('<EAN>'+ean+'</EAN>'))
          {

            let arr = catalogData.split('<EAN>'+ean+'</EAN>');
            let arr_1 = arr[1].split('</MEDIA>');
            let blockToParse = '<RESPONSE>'+ '<EAN>'+ean+'</EAN>' +arr_1[0] + '</MEDIA>' +'</RESPONSE>';
            
            var parseString = require('xml2js').parseString;
            parseString(blockToParse, function (err, result) {
           
	          let symbol = '';

            if(bVodacom)
            {              
              symbol = 'R';
            }
            else
            {
              let currencycode = 'AED';
              
              if(country_code == 'ZA') {
                currencycode = 'ZAR';
              } else if(country_code == 'TR') {
                currencycode = 'TRY';
              } else if(country_code == 'SA') {
                currencycode = 'SAR';
              }
              var getSymbolFromCurrency = require('currency-symbol-map');
              symbol = getSymbolFromCurrency(currencycode); 
              if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
                symbol = '\u{2800}';
              }              
            }
	          // Process CANCELABLE////////////////////
            let cancelable  = '0';  

            let arr_cancel = blockToParse.split('<CANCELABLE>');
            if(arr_cancel.length)
	          {
            	let arr_cancel_1 = arr_cancel[1].split('</CANCELABLE>');            
            	cancelable =  arr_cancel_1[0];
	          }



            /////////////////////////////////////////
                           
            let str1 = '';  

            let arr_curr = blockToParse.split('<AMOUNT CURRENCY="');
            let arr_curr_1 = arr_curr[1].split('"');            
            let currency =  arr_curr_1[0];

            let arr_amt = blockToParse.split('<AMOUNT CURRENCY');
            let arr_amt_1 = arr_amt[1].split('</AMOUNT>');
            let arr_amt_2 = arr_amt_1[0].split('>');
            let str =  arr_amt_2[1];
            
            console.log('++'+ str);
            if (str == 0) {
              str1 = symbol + '0.00';
            }
            else {
              str1 = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
            }
	          productdisplayName = result.RESPONSE.NAME[0];	
      
                 
            let xmlINFOLIST = result.RESPONSE.INFOS[0].INFO;
            if (xmlINFOLIST.length) {  
              let enfound = 0;        
              for (let k = 0; k < xmlINFOLIST.length; k++) {         
                let bBrandExists = false;
                
                if((xmlINFOLIST[k].BRAND))
                {
                  bBrandExists = true;        
                }                    
                if(!bBrandExists)
                {          
                  continue;
                }               
          
                let xmlLanguage = xmlINFOLIST[k].LANGUAGE;
                if(!(xmlLanguage))
                {
                  xmlLanguage = xmlINFOLIST[k].language;
                }
                if (xmlLanguage) {
                  let language = xmlLanguage;
                  if (language.length) {
                    if ((language.includes('en-')) || (language == 'en') || (language == 'eng')) {
                      let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
                      let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG;                    
                      enfound = 1;                
                      longDescriptionEN = xmlLongdescr
                      shortDescriptionEN = xmlShortdescr;
                      let xmlDisplayName = xmlINFOLIST[k].DISPLAY_NAME;
                    if (xmlDisplayName.length) {                      
                        productdisplayName = xmlDisplayName;                      
                    }
                    
                     if ((longDescriptionEN.length > 1) || (shortDescriptionEN.length > 1)) {
                        break;
                      }
                      else
                        continue;
                    }
                  }
                }              
              }
              
              if (enfound == 0) {

              
                for (let k = 0; k < xmlINFOLIST.length; k++) {                 
                
                    let bBrandExists = false;                                  
                    if((xmlINFOLIST[k].BRAND?.length > 0))
                    {
                      bBrandExists = true;
                    }
                    if(!bBrandExists)
                    {          
                      continue;
                    }
                    let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
                    let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG;
                    let xmlDisplayName = xmlINFOLIST[k].DISPLAY_NAME;
                    if (xmlDisplayName.length) {                      
                        productdisplayName = xmlDisplayName;                      
                    }
                    if (xmlShortdescr.length) {
                     if ((xmlShortdescr.length > 1) || (xmlLongdescr.length > 1)) {
                        longDescriptionEN = xmlLongdescr;
                        shortDescriptionEN = xmlShortdescr;
                        enfound = 1;
                        break;
                      }
                    }

                }

              }
            }
     
           
            let product_logo = '';
            if(result.RESPONSE.MEDIA[0].ARTICLE_IMAGE.length > 0)
            {
              product_logo = result.RESPONSE.MEDIA[0].ARTICLE_IMAGE[0];
            }
            else if(result.RESPONSE.MEDIA[0].LOGO.length > 0)
            {
              product_logo = result.RESPONSE.MEDIA[0].LOGO[0];
            }

            let logo_tag = '<PRODUCTLOGO>' + product_logo + '</PRODUCTLOGO>';
    
            
            if (productdisplayName.toString().includes('1 Month Renewal')) {
  
              str1 = str1 + ' per month';
            }
            else
              if (productdisplayName.toString().includes('12 Months Renewal') || productdisplayName.toString().includes('1 Year Renewal')) {
                str1 = str1 + ' per year';
              }
          
              amount_tag = '<AMOUNT>'+str1+'</AMOUNT>';
              let currency_tag = '<CURRENCY>'+currency+'</CURRENCY>';
              let cancelable_tag = '<CANCELABLE>'+cancelable +'</CANCELABLE>';

 

            let desc = shortDescriptionEN.length > 0 ? shortDescriptionEN:longDescriptionEN;
		
            {
                let jsonResponse_reconstruct = '';
                let split_json = jsonResponse.split('<SUBSCRIPTIONS>');
                let split_json_1 = split_json[1].split('</SUBSCRIPTIONS>');
                let json_process = split_json_1[0];
                let json_array = json_process.split('</SUBSCRIPTION>');

                let sale_date = 'NA';
                
                if(json_array[k].length)
                {
                      let current = json_array[k];
                      console.log( 'Contract::::::::'+ contract);
                      console.log( 'current::::::::'+ current);
                      console.log( 'current::::::::'+ 'vvvvvvvvvvvvvvvvvvvv');
                      let c_arr = contract[0].split('-');
                      let sale_d = '';
                      if(c_arr.length > 0)
                      {
                        let temp = c_arr[1];
                        console.log('temp::' + temp);
                        sale_d = temp.substring(temp.length-12,temp.length);
                        console.log('sale_d::' + sale_d);
                        sale_d = (Number('0x'+ sale_d)).toString();
                        console.log('sale_d1::' + sale_d);
                        let seconds = sale_d.substring(12,14);
                        if(Number(seconds) > 59)
                        {
                          let secs = (Number(seconds)/100)*60;
                          if(secs.toString().includes('.'))
                          {
                            let secs_arr = secs.toString().split('.');
                            seconds = secs_arr[0];
                          }

                        }
                        sale_date = sale_d.substring(0,4) + '-' + sale_d.substring(4,6) + '-' + sale_d.substring(6,8) + ' ' + sale_d.substring(8,10) + ':' + sale_d.substring(10,12) + ':' + seconds;
                        sale_d = sale_d.substring(0,4) + '-' + sale_d.substring(4,6) + '-' + sale_d.substring(6,8) + ' 00:00:00';
                        console.log('sale_d2::' + sale_d);
                         
                      }
                      console.log( 'sale_d::::::::'+ sale_d);
                }
                let renewal_tag = '<RENEWALDATE>' + 'NA' + '</RENEWALDATE>';
                let sale_date_tag = '<SALEDATE>' + sale_date + '</SALEDATE>';
                let current = json_array[k];

                if((current.length)&&(current.includes('<STATUS>INACTIVE</STATUS>')))
                {
                  if(add_info_inactive.length)
                    add_info_inactive = add_info_inactive + ',';

                 
                  add_info_inactive = add_info_inactive + contract;
                  console.log('contract inactive: ' + contract);

                }

                if((current.length)&&(current.includes('<STATUS>ACTIVE</STATUS>')||(current.includes('<STATUS>UNSUBSCRIBED</STATUS>'))))
                {
                    cancel_date_tag = '<CANCELDATE>NA</CANCELDATE>' 
                }

         
                if((current.length)&&(current.includes('<STATUS>ACTIVE</STATUS>')))
                {
                  let arr_p = current.split('<PRODUCTNAME>');
                  let arr_p_1 = arr_p[1].split('</PRODUCTNAME>');
                  let product = arr_p_1[0];

                  arr_p = current.split('<PRODUCTID>');
                  arr_p_1 = arr_p[1].split('</PRODUCTID>');
                  let ean_p = arr_p_1[0];

                  console.log('sale_date: ' + sale_date);
                  console.log('ean_p: ' + ean_p);
                  console.log('product: ' + product);
                  let renew_date = '';
                  let no_of_months = 0;
                  //let d = new Date("2024-12-31");
                  let dt = sale_date.split(' ');
                  let d = new Date(dt[0]);
                  let p = productdisplayName.toString().toLowerCase();
                  if((ean_p == '4251972939829')||(ean_p == '4251972939843')) 
                  {
                    no_of_months = 15;    
                  }
                  else
                  if((p.includes('1month'))||(p.includes('1 month')))
                  {     
                    no_of_months = 1;      
                  }
                  else if((p.includes('6 month'))||(p.includes('6month'))) 
                  {
                    no_of_months = 6;   
                  }
                  else if((p.includes('12 month'))||(p.includes('12month'))) 
                  {
                    no_of_months = 12;   
                  }
                  else if((p.includes('15 month'))||(p.includes('15month'))) 
                  {
                    no_of_months = 15 ; 
                  }
                  else if((p.includes('1 year'))||(p.includes('1year'))) 
                  {
                    no_of_months = 12;   
                  }
		  else {
                    no_of_months = 0;
                    renew_date = 'NA';
                  }
                  
                  d.setMonth(d.getMonth() + no_of_months);
                  console.log(d.toLocaleDateString());
                  let d1 = d.toLocaleDateString();
                  if(d1.includes('/'))
                  {
                    let arr_d = d1.split('/');
                    if(renew_date != 'NA')
                    {
                      renew_date = arr_d[2] + '-' + ((arr_d[0].length)>1 ? arr_d[0] : ('0' + arr_d[0]))  + '-' + ((arr_d[1].length)>1 ? arr_d[1] : ('0' + arr_d[1]));
                    }
                  }

                  console.log('product: ' + product);
                  console.log('sale_date: ' + sale_date);
                  console.log('renew_date: ' + renew_date);

                  renewal_tag = '<RENEWALDATE>' + renew_date + '</RENEWALDATE>';
                }

                let product_catalog_tag = '<PRODUCTCATALOG></PRODUCTCATALOG>';
                if(productdisplayName.length)
                {
                    product_catalog_tag = '<PRODUCTCATALOG>' + productdisplayName + '</PRODUCTCATALOG>';
                }

/////////////////////////////////////////////////////////////////////////////////
                if(json_array.length)
                {
                  json_array[k] = json_array[k].replace('<CONTRACT>'+contract+'</CONTRACT>','<CONTRACT>'+contract+'</CONTRACT>\n\t<DESCRIPTION>' + desc + '</DESCRIPTION>\n\t'+logo_tag+ '\n\t' + amount_tag + product_catalog_tag + currency_tag + cancelable_tag + sale_date_tag + renewal_tag + cancel_date_tag);
                }

                for(let m=0; m<subscriptions.length;m++)
                {
                    jsonResponse_reconstruct = jsonResponse_reconstruct + json_array[m] + '</SUBSCRIPTION>';
                }

                jsonResponse_reconstruct = split_json[0] + '<SUBSCRIPTIONS>' + jsonResponse_reconstruct +  '</SUBSCRIPTIONS>' + '</RESPONSE>';
                console.log('jsonResponse_reconstruct::'+jsonResponse_reconstruct);
		jsonResponse = jsonResponse_reconstruct;

            }

          });
      
          }

        }
      }

    });
  }

  if(add_info_inactive.length)
  {
    jsonResponse = jsonResponse + '<INACTIVELIST>' + add_info_inactive + '</INACTIVELIST>';
  }
   console.log('contract inactive list: ' + add_info_inactive);


  return jsonResponse;
}


app.get('/getHASHUnsubscribe', cors(corsOptions), async (req, res) => {

  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getHASHUnsubscribe => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        console.log('getHashUnsubscribe function started');
        //var str = req.query.otp;
        let str = Buffer.from(req.query.otp,'base64').toString('utf8');
        var arr = str.split(',');
        var otp = arr[0];
        var genHash = arr[1];
        var genHashTime = arr[2];
        console.log(str);
        
        


        var currentTimeStamp = getTimeStamp();
        var otpGenTime = decrypt(genHashTime);

        var values = otpGenTime.split(',');
        let phoneref = values[2].substring(values[2].length-9,values[2].length);
       
        let refsession =  getTimeStamp();
        let session_id = 'EPAY-' + (parseInt(refsession)).toString(16).toUpperCase() + '-' + phoneref;
        let host_log = req.hostname.split('.');
        let api = 'VALIDATE_OTP_MANAGEACCOUNT';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ api +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';
        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getHASHUnsubscribe => clientip: ' + clientip + log_suffix);

        if (otpGenTime.length > 0) {
          var tmArr = otpGenTime.split(',');
          if (tmArr.length > 0) {
            console.log(currentTimeStamp + '::' + tmArr[1]);
            if (Number(await date_difference(currentTimeStamp,tmArr[1])) > 300) {
              var response = 'KO' + ',' + 'OTPTimedOut';
              res.send(response);
     
            }
            else {
              console.log(otp);
              const hashValue = crypto.createHash('sha256', secret).update(otp).digest('hex');
            
              if ((genHash == hashValue) ||(otpTest && (otp == otpTest))) {
                var toencrypt = tmArr[0] + ',' + currentTimeStamp;
                 
      
                let phone = tmArr[2].substring(tmArr[2].length-9,tmArr[2].length);
              

                let currentDate = getFormattedTime();
                let ref =  getTimeStamp();
                let reference = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;
                
                let up_cred = await getUPCredentials(req);

                let userIdHost = up_cred.userIdHost;
                let userPaswdHost = up_cred.userPaswdHost;
                
                let TERMINAL_ID =  getDefaultTID(req.hostname,req);
             

                let bVodacom = false; 
                if((await checkIfVodacomFlow(req.hostname)) == 'yes'){
                  bVodacom = true;
                }
                if(!bVodacom)
                {
                  if((arr[3].length) && (arr[3] != 'undefined'))
                  {
                    TERMINAL_ID = arr[3];
                    reference = 'EPAY-' + TERMINAL_ID + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;

                  }
                 

               
                }		                          
                

                
                if((req.headers.referer.includes('/mcafee')) && (TEST_IP_AZURE == clientip)) {
                  let info = await getTestSubscriptionInfo(req.hostname,null) 
                  if(info) {          
                        TERMINAL_ID = info.TestSubscriptionTID ;      
                        reference = 'EPAY-' + TERMINAL_ID + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;      
                  }
                }


                

                const fetchOptions = {
                  method: 'POST',
                  body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
                    '<AUTHORIZATION>' +
                    '<USERNAME>' + userIdHost + '</USERNAME>' +
                    '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                    '</AUTHORIZATION>' +
                    '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
                    '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
                    '<TXID>' + reference + '</TXID>' +
                    '<SUBSCRIPTION>' +
                    '<PHONE>' + phone + '</PHONE>' +
                    '<STATUS>ACTIVE</STATUS>' +
                    '</SUBSCRIPTION>' +
                    '</REQUEST>',

                  headers: {
                    'Content-Type': 'application/xml',
                  },

                }
                console.log(log_prefix + 'CHECK API CALL: ' + getContractURL + log_suffix);
                mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
                var contractFetchTimeout = setTimeout(() => res.send('KO' + ',' + 'timestamp'), 30000);

                try {
                  
		const response = await fetch(getContractURL , fetchOptions,proxy_url);

                  let jsonResponse = await response.text();
                  let jsonResponse_log = jsonResponse;
          	      jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
                  mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
                
                  clearTimeout(contractFetchTimeout);
		  if(jsonResponse.includes('<RESULT>0</RESULT>'))
                  {
                    const fetchOptions_unsubs = {
                      method: 'POST',
                      body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
                        '<AUTHORIZATION>' +
                        '<USERNAME>' + userIdHost + '</USERNAME>' +
                        '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                        '</AUTHORIZATION>' +
                        '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
                        '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
                        '<TXID>' + 'UNSUBS' +  reference  + '</TXID>' +
                        '<SUBSCRIPTION>' +
                        '<PHONE>' + phone + '</PHONE>' +
                        '<STATUS>UNSUBSCRIBED</STATUS>' +
                      
                        '</SUBSCRIPTION>' +
                        '</REQUEST>',
    
                      headers: {
                        'Content-Type': 'application/xml',
                      },
    
                    }

                    mask_xml_data(fetchOptions_unsubs.body,log_prefix,log_suffix);
                    //const response_unsubs = await fetch(getContractURL, fetchOptions_unsubs,proxy_url);
                    const response_unsubs = await fetch(getContractURL, fetchOptions_unsubs,proxy_url);
                    let jsonResponse_unsubs = await response_unsubs.text();
                    let jsonResponse_log = jsonResponse_unsubs;
                    jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
                    mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
                   

		    ///////////////ADD CANCELLED BLOCK/////////////////////////////

                   const fetchOptions_cancel = {
                    method: 'POST',
                    body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
                      '<AUTHORIZATION>' +
                      '<USERNAME>' + userIdHost + '</USERNAME>' +
                      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                      '</AUTHORIZATION>' +
                      '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
                      '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
                      '<TXID>' + 'CANC' +  reference  + '</TXID>' +
                      '<SUBSCRIPTION>' +
                      '<PHONE>' + phone + '</PHONE>' +                    
                      '<STATUS>INACTIVE</STATUS>' +
                      '</SUBSCRIPTION>' +
                      '</REQUEST>',
  
                    headers: {
                      'Content-Type': 'application/xml',
                    },
  
                  }
                 
                  mask_xml_data(fetchOptions_cancel.body,log_prefix,log_suffix);
                
                  const response_cancel = await fetch(getContractURL, fetchOptions_cancel,proxy_url);
                  let jsonResponse_cancel = await response_cancel.text();
                  let jsonResponse_log_c = jsonResponse_cancel;
                  jsonResponse_log_c = jsonResponse_log_c.replace(/\r?\n|\r/g, " ");
                  mask_xml_data(jsonResponse_log_c,log_prefix,log_suffix);

                    if((jsonResponse_unsubs.includes('<RESULT>0</RESULT>'))&&(jsonResponse_unsubs.includes('</SUBSCRIPTION>')))
                    {
                     
                      let subs_block_arr = jsonResponse_unsubs.split('<SUBSCRIPTIONS>');
                      let subs_block_arr_1 = subs_block_arr[1].split('</SUBSCRIPTIONS>');
                      let subscriptions_block_to_add = subs_block_arr_1[0];
                      if(jsonResponse.includes('<SUBSCRIPTIONS />'))
                      {
                        jsonResponse = jsonResponse.replace('<SUBSCRIPTIONS />','<SUBSCRIPTIONS>'+ subscriptions_block_to_add + '</SUBSCRIPTIONS>')
                      }
                      else if(jsonResponse.includes('</SUBSCRIPTIONS>'))
                      {
                        jsonResponse = jsonResponse.replace('</SUBSCRIPTIONS>',subscriptions_block_to_add + '</SUBSCRIPTIONS>' );
                      }
                    }

		                //////////////////////////////////////////////////////////////////////
                    if((jsonResponse_cancel.includes('<RESULT>0</RESULT>'))&&(jsonResponse_cancel.includes('</SUBSCRIPTION>')))
                    {
                   
                      let subs_block_arr = jsonResponse_cancel.split('<SUBSCRIPTIONS>');
                      let subs_block_arr_1 = subs_block_arr[1].split('</SUBSCRIPTIONS>');
                      let subscriptions_block_to_add = subs_block_arr_1[0];
                      if(jsonResponse.includes('<SUBSCRIPTIONS />'))
                      {
                        jsonResponse = jsonResponse.replace('<SUBSCRIPTIONS />','<SUBSCRIPTIONS>'+ subscriptions_block_to_add + '</SUBSCRIPTIONS>')
                      }
                      else if(jsonResponse.includes('</SUBSCRIPTIONS>'))
                      {
                        jsonResponse = jsonResponse.replace('</SUBSCRIPTIONS>',subscriptions_block_to_add + '</SUBSCRIPTIONS>' );
                      }
                    }
                    
                  }
	  


                  let updatedResponse = await updateDescription(jsonResponse,req.hostname,req);
                  if(updatedResponse.includes('<INACTIVELIST>'))
                  {
                    let arr_c = updatedResponse.split('<INACTIVELIST>');
                    let arr_c_1 = arr_c[1].split('</INACTIVELIST>');
                    let inactive_list = arr_c_1[0];
                    updatedResponse = arr_c[0];
                    let c_list = inactive_list.split(',');
                    if(c_list.length)
                    {
                      for(let m=0;m<c_list.length;m++)
                      {
                        let cancel_date_tag = '<CANCELDATE>NA</CANCELDATE>' ;
                        let c_arr = c_list[m].split('-');
                        let sale_d = '';
                        if(c_arr.length > 0)
                        {
                          let temp = c_arr[1];
                          console.log('temp::' + temp);
                          sale_d = temp.substring(temp.length-12,temp.length);
                          console.log('sale_d::' + sale_d);
                          sale_d = (Number('0x'+ sale_d)).toString();
                          console.log('sale_d1::' + sale_d);
                          sale_d = sale_d.substring(0,4) + '-' + sale_d.substring(4,6) + '-' + sale_d.substring(6,8) + ' 00:00:00';
                          console.log('sale_d2::' + sale_d);

                          let tid = TERMINAL_ID;                          
                          let arr_td = c_list[m].split('-');
                          if(arr_td[1].length > 19)
                          {
                            tid = arr_td[1].substring(0,8);
                          }

                          let body = '<REQUEST TYPE="TXLIST">' +
                            '<USERNAME>'+userIdHost+'</USERNAME>' +
                            '<PASSWORD>'+userPaswdHost+'</PASSWORD>' +
                            '<TERMINALID>'+tid+'</TERMINALID>' +
                            '<LOCALDATETIME>'+getFormattedTime()+'</LOCALDATETIME>' +
                            '<TXID>'+reference+'-cd'+ m +'</TXID>' +
                            '<LISTOPTIONS>' +
                            '<FROM>'+sale_d+'</FROM>' +
                            '<UNTIL>'+getFormattedTime()+'</UNTIL>' +
                            '<TXID>'+c_list[m] + 'C'+'</TXID>' +
                            '</LISTOPTIONS>' +
                            '</REQUEST>';
                          
                          console.log(body);
                          

                          const fetchOptions = {
                            method: 'POST',
                        
                            body: body,
                        
                            headers: {
                              'Content-Type': 'application/xml',
                            },
                        
                          }

                          const response = await fetch(UPInterfaceURL, fetchOptions, proxy_url);
                          let jsonResponse = await response.text();
                          console.log(jsonResponse);
                          if(jsonResponse.includes('<RESULT>0</RESULT>'))
                          {
                    
                            let arr = jsonResponse.split('<RESULT>0</RESULT>');
                            if(arr[1].includes('<LOCALDATETIME>') &&  arr[1].includes('<TX>') && arr[1].includes('<TXLIST>'))
                            {
                              let c_arr = arr[1].split('<LOCALDATETIME>');
                              let c_arr_1 = c_arr[1].split('</LOCALDATETIME>');
                              cancel_date_tag = '<CANCELDATE>'+c_arr_1[0]+'</CANCELDATE>';
                              console.log('cancel_date_tag found: ' + cancel_date_tag);
                              updatedResponse = updatedResponse.replace('<CONTRACT>' + c_list[m] + '</CONTRACT>','<CONTRACT>' + c_list[m] + '</CONTRACT>' + cancel_date_tag);
                            }

                          }
                          else {
                            console.log('<CONTRACT>' + c_list[m] + '</CONTRACT>');
                            console.log(cancel_date_tag);
                            updatedResponse = updatedResponse.replace('<CONTRACT>' + c_list[m] + '</CONTRACT>','<CONTRACT>' + c_list[m] + '</CONTRACT>' + cancel_date_tag);
                          }

                        }

                      }
                    }
                  }
                  
                   jsonResponse_log = updatedResponse;
                    jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
                    mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
                  
                  res.send('OK' + ',' + encrypt(toencrypt) +',' + cancelAllowedPerDomain(req.hostname) + ',' +updatedResponse);
                 
                }
                catch(err)
                {
                  console.log(err);
                }

                
              }
              else {
                var response = 'KO' + ',' + 'timestamp';
                res.send(response);
              }

            }


          }
          else {
            var response = 'KO' + ',' + 'timestamp';
            res.send(response);
          }
        }
        else {
          var response = 'KO' + ',' + 'timestamp';
          res.send(response);
        }

      } catch (error) {
        console.log(error);
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});

const { GoogleAuth } = require('google-auth-library');
const jwt = require('jsonwebtoken');

const issuerId = '3388000000022274537';
const classId =    '3388000000022274537.c5fc2f43-f1de-48db-9ac0-21f5400b1a55';
const baseUrl = 'https://walletobjects.googleapis.com/walletobjects/v1';

const credentials = require('C:/Work/Web/WebServer/master/keys/copper-gear-298710-acc90807e19f.json');
const httpClient = new GoogleAuth({
  credentials: credentials,
  scopes: 'https://www.googleapis.com/auth/wallet_object.issuer'
});





async function generatePassStripGoogle(pin, passdir,guid) {

  const { createCanvas, loadImage } = require('canvas')

  const width = 1200 + 48
  const height = 490

  const canvas = createCanvas(width, height)
  const context = canvas.getContext('2d')

  context.fillStyle = '#ffffff'
  context.fillRect(0, 0, width, height)

  loadImage(passdir + '/'+  guid + '_striplogo.png').then(image => {
    context.drawImage(image, 499, 20, 250, 250)
    const buffer = canvas.toBuffer('image/png')
    fs.writeFileSync(passdir + '/' + guid + '_strip.png', buffer)
    fs.writeFileSync(passdir + '/' + guid + '_strip@2x.png', buffer)
  })


  context.textAlign = 'center'
  context.textBaseline = 'top'
  context.font = '40pt Menlo'
  context.fillStyle = '#0066cc'
  context.fillText(pin, 624, 310)

  loadImage(templatedir + 'pbe.png').then(image => {
    context.drawImage(image, 920, 425, 318, 56)
    const buffer = canvas.toBuffer('image/png')
    fs.writeFileSync(passdir + '/' + guid + '_strip.png', buffer)
    fs.writeFileSync(passdir + '/' + guid + '_strip@2x.png', buffer)
  })
}

async function generateGooglePass(obj) {
  folderName = basepath + 'static/media/Google/passes';// + obj.id;
  console.log(folderName);
 // fs.mkdirSync(folderName,{recursive: true});
  console.log(obj);

  const response = await fetch(obj.productLogo,{},proxy_url);
    const blob = await response.blob();
    const arrayBuffer = await blob.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    fs.writeFileSync(folderName + '/' + obj.id + '_striplogo.png', buffer, 'binary', (err) => {
      if (err) {
        //throw err
        console.log(err);
      }
      console.log('Product Logo saved.');
    })
  
  await generatePassStripGoogle(obj.pin, folderName,obj.id);  

}

async function createPassObject(obj) {
  // TODO: Create a new Generic pass for the user
  let objectSuffix = obj[0].reference;

  console.log(obj);
  
  let objectId = `${issuerId}.${objectSuffix}`;
  console.log(objectId);

  let genericObject = {
    'id':  `${objectId}`,
    'classId': classId,
    'genericType': 'GENERIC_TYPE_UNSPECIFIED',
    'hexBackgroundColor': '#FFFFFF',
    'logo': {
      'sourceUri': {
        'uri': obj[0].providerLogo
      }
    },
    'cardTitle': {
      'defaultValue': {
        'language': 'en',
        'value': obj[0].provider
      }
    }, 

    
   'imageModulesData': [
      {
        'mainImage': {
          'sourceUri': {
            'uri':obj[0].stripe
          },
          
        },
        'id': 'event_banner'
      }
    ], 
    
   
    'header': {
      'defaultValue': {
        'language': 'en',
        'value': obj[0].amount
      }
    },
    'subheader': {
      'defaultValue': {
        'language': 'en',
        'value': obj[0].product
      }
    },
    'textModulesData': [
      
      {
        'header': 'Description',
        'body': obj[0].description,
        'id': 'description'
      },
      {
        'header': 'Terms & Conditions',
        'body': obj[0].terms, 
        'id': 'TNC'
      },      
      {
        'header': 'PIN',
        'body': obj[0].pin,
        'id': 'pin'
      },
      {
        'header': 'Serial',
        'body': obj[0].serial,
        'id': 'points'
      },
      {
        'header': 'Purchased On',
        'body': obj[0].tx_time, 
        'id': 'txtime'
      },
      {
        'header': 'Expiry',
        'body': obj[0].expiry,
        'id': 'contacts'
      }
    ],
    'barcode': {
      'type': 'QR_CODE',
      'value': obj[0].pin 
    },
    'heroImage': {
      'sourceUri': {
        'uri':obj[0].stripe
      }
    },

    'linksModuleData': {
      'uris': [
        {
          'uri': obj[0].actlink,
          'description': 'Redeem Your Code',
          'id': 'official_site'
        }
      ]
    }
    
    

    
 
  };
  // TODO: Create the signed JWT and link
  const claims = {
    iss: credentials.client_email,
    aud: 'google',
    origins: [],
    typ: 'savetowallet',
    payload: {
      genericObjects: [
        genericObject
      ]
    }
  };

 console.log(claims);
  const token = jwt.sign(claims, credentials.private_key, { algorithm: 'RS256' });
  const saveUrl = `https://pay.google.com/gp/v/save/${token}`;
  console.log(saveUrl);
  return saveUrl;
  //res.send(`<a href='${saveUrl}'><img src='wallet-button.png'></a>`);
}


app.get('/getActivation', cors(corsOptions), async (req, res) => {

const clientip = req.headers['incap-client-ip'] ;  
console.log(req.headers.campaign + '>>API_CALL:getActivation => clientip: ' + clientip);
 
  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {

  let params = Buffer.from(req.query.params,'base64').toString('utf8');// req.query.params;
  console.log(params);
  let arr = params.split(',');
  let txnTime = arr[0];
  let serial = arr[1];
  let ean = arr[2];
  let tid = arr[3];
  let amount = arr[4];
  let currency = arr[5];

  let consumer_tag = '';

 if(arr.length > 6)
 {
  let title = arr[6];
  let name = arr[7];
  let surname = arr[8];
  let phone = arr[9];
  let email = arr[10];

  let title_tag = title.length ? ('<TITLE>' + title + '</TITLE>') : '';
  let name_tag = name.length ? ('<NAME>' + name + '</NAME>') : '';
  let surname_tag = surname.length ? ('<SURNAME>' + surname + '</SURNAME>') : '';
  let sms_tag = phone.length ? ('<SMS>+' +  phone + '</SMS>') : '';
  let email_tag = email.length ? ('<EMAIL>' + email + '</EMAIL>') : '';

  let consumer_tag_pre = title_tag + name_tag + surname_tag + sms_tag + email_tag;
  consumer_tag = consumer_tag_pre.length ? ('<CONSUMER>' + consumer_tag_pre + '</CONSUMER>') : '';
  }

  if((tid == 'undefined')||(tid == 'notid')||(tid == ''))
  {
    tid = getDefaultTID(req.hostname,req);    
  }

  var ref = getTimeStamp();
  var x = Math.floor(100000 + Math.random() * 900000000);
  var y = x.toString().split('.');
  var number = y[0];

  var inforef = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' +number;

  let session_id = inforef;
  let host_log = req.hostname.split('.');
  let method = 'ACTIVATION_CODE';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';

  console.log(log_prefix + req.headers.campaign + '>>API_CALL:getActivation => clientip: ' + clientip + log_suffix);

  let up_cred = await getUPCredentials(req);

  let userIdHost = up_cred.userIdHost;
  let userPaswdHost = up_cred.userPaswdHost;
 

  const fetchOptions = {
    method: 'POST',

    body: '<REQUEST type="SALE" STORERECEIPT="1">' +
      '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
      '<USERNAME>' + userIdHost + '</USERNAME>' +
      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
      '<TERMINALID>'+ tid +'</TERMINALID>' +      
      '<TXID>' + (inforef.includes('EPAY-undefined') ? inforef.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): inforef)
       + '</TXID>' +      
      '<CARD>' +
      '<PAN>'+serial + '</PAN>' +      
      '<EAN>'+ean + '</EAN>' +            
      '</CARD>' +
      '<AMOUNT>'+ amount +'</AMOUNT>' +
      '<CURRENCY>'+ currency +'</CURRENCY>' +
      consumer_tag +
      '</REQUEST>',

    headers: {
      'Content-Type': 'application/xml',
    },

  }

  mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
  console.log(log_prefix + 'POSA Activation Request: ' + UPInterfaceURL + log_suffix);

  var upActivationTimeout = setTimeout(() => {console.log(log_prefix + 'Activation Request Timedout ' + log_suffix);res.send('timeout')}, 30000);
  try {
 const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
 var jsonResponse = await response.text();
 jsonResponse = await updateRedeemptionURL(jsonResponse);
 clearTimeout(upActivationTimeout);
 mask_xml_data(jsonResponse,log_prefix,log_suffix);
 res.send(jsonResponse);
  }catch(error)
  {

    console.log(error);
    console.log(log_prefix + 'POSA Activation Response Exception' + log_suffix);
    res.send('exception');
  }



 } catch (error) {
        console.log(error);        
        res.send('exception');      
     
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }



});

async function getActionIdCaptureCheckout(payment_id,log_prefix,log_suffix,gtid,hostname,req)
{
  
  let use_checkout_key = '';
  let use_checkout_url = '';
  let bearer = '';
  let cred = await getCheckoutCredentials(hostname,req);
  if(cred)
  {
    use_checkout_key = cred.CheckoutSecretKey;
    use_checkout_url = cred.url;
    bearer = cred.prefix;
  }
  const fetchOptions = {
    method: 'GET',
    headers: {
      'Authorization': bearer + use_checkout_key,
      'Content-Type': 'application/json',
    },
  }
  let actionIdCapture = 'none';
  let act_url = use_checkout_url + '/' + payment_id + '/actions' ;
  console.log(log_prefix + 'GET CAPTURE ACTION ID: ' + act_url + log_suffix);
  const responsetok = await fetch(act_url, fetchOptions,proxy_url);
  
  if (responsetok.status == 200) {
    

    const jsonResponsetok = await responsetok.json();

    for(let j=0; j< jsonResponsetok.length;j++)
    {
      mask_json_data(JSON.stringify(jsonResponsetok[j]),log_prefix,log_suffix);
    }

    for(let i=0; i<jsonResponsetok.length; i++)
    {
      if(jsonResponsetok[i].type == 'Capture')
      {
        if(jsonResponsetok[i].id.length)
        {
          actionIdCapture = jsonResponsetok[i].id;
          break;
        }
      }
    }

     

  }
 console.log('action id capture: ' + actionIdCapture);
  return actionIdCapture;

}

async function processRefundCheckout(amount,reference,action_id,payment_id,ean,tid,contract,customer,log_prefix,log_suffix,hostname,req){
  
  let use_checkout_key = '';
  let use_checkout_url = '';
  let bearer = '';
  let cred = await getCheckoutCredentials(hostname,req);
  if(cred)
  {
    use_checkout_key = cred.CheckoutSecretKey;
    use_checkout_url = cred.url;
    bearer = cred.prefix;
  }

  let body= {
    "amount": amount,
    "reference": reference,
    "processing": {
      "capture_payment_id": action_id
    },
    "metadata": {    
      "ean": ean,
      "tid": tid
    }
  }
console.log(body);
  const fetchOptions = {
    method: 'POST',
    body:JSON.stringify(body),
    headers: {
      'Authorization': bearer + use_checkout_key,
      'Content-Type': 'application/json',
    },
  }
 let refunds = use_checkout_url + '/' + payment_id + '/refunds'
  console.log(log_prefix + 'GET REFUND URL: ' + refunds + log_suffix);
  const responsetok = await fetch(refunds, fetchOptions,proxy_url);
  console.log(responsetok.status);
  let domain1_str = '';
  customer = await getCustomerName(req.hostname);
  let support_url = await getDomainSupportUrl(req.hostname);
  domain1_str = getMessageIDText('MESSAGEID_132',req)+ customer +getMessageIDText('MESSAGEID_103',req)+ support_url;
     
  
  if (responsetok.status == 202) { 
    const jsonResponsetok = await responsetok.json();
    console.log(jsonResponsetok);
    return ('<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
  else if(responsetok.status == 401)
  {
    return ('<RESPONSE><RESULT>401</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_143',req)+domain1_str+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
  else if(responsetok.status == 403)
  {
    return ('<RESPONSE><RESULT>403</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_144',req)+domain1_str+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
  else if(responsetok.status == 404)
  {
    return ('<RESPONSE><RESULT>404</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_145',req)+domain1_str+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
  else if(responsetok.status == 422)
  {
    const jsonResponsetok = await responsetok.json();
    console.log(jsonResponsetok);
    return ('<RESPONSE><RESULT>422</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_146',req)+domain1_str+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
  else if(responsetok.status == 502)
  {
    return ('<RESPONSE><RESULT>502</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_147',req)+domain1_str+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
  else
  {
    let customer = await getCustomerName(req.hostname);
    let support_url = await getDomainSupportUrl(req.hostname);
    domain1_str = getMessageIDText('MESSAGEID_148',req) + customer +getMessageIDText('MESSAGEID_103',req)+ support_url;
    
    return ('<RESPONSE><RESULT>106</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_149',req) +domain1_str+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
  }
}

async function processRefundVodacomXML(amount,reference,action_id,payment_id,ean,tid,contract,customer,log_prefix,log_suffix,req){

try { 

       let con_arr = contract.split('-');      

          let bodyRefund = '<COMMAND>'+
        '<FUNKTION>1</FUNKTION>' +
        '<TERMINAL-ID>'+tid+'</TERMINAL-ID>' +
        '<IDENT>'+ payment_id +'</IDENT>' +
        '<USERLOGIN>'+user_xml+'</USERLOGIN>' +
        '<PASSWORD>'+password_xml+'</PASSWORD>' +
        '<PAN>'+'27'+con_arr[2]+'</PAN>' + 
        '<CARDTYPE>2643</CARDTYPE>' +
        '<EXTRADATA>' +
              'REASON=Customer cancelled subscription|' +  
        '</EXTRADATA>' +
        '<REASON>Customer cancelled subscription</REASON>' +
      '</COMMAND>';

      console.log(log_prefix + bodyRefund + log_suffix);

      const fetchOptionsRefund = {
        method: 'POST',

        body: bodyRefund,

        headers: {

          'Destination': 'cwxmlgate',
        },

      }

      console.log(log_prefix + 'XML Refund Request: ' + XMLInterfaceURL + log_suffix);
      var RefundResponseSent = 0;
      var refundTimeout = setTimeout(() => { console.log(log_prefix + 'refund time out' + log_suffix); RefundResponseSent = 1; res.send('apiTimeout') }, 30000);
      try {
      const responseRefund = await fetch(XMLInterfaceURL, fetchOptionsRefund,proxy_url);
      console.log(log_prefix + 'XML Refund response status code:  '+ responseRefund.statusCode + log_suffix);
      const xmlResponseRefund = await responseRefund.text();
      
        clearTimeout(refundTimeout);

        if(xmlResponseRefund.length)
        {
          console.log(log_prefix + xmlResponseRefund + log_suffix);
        }
        else {
          console.log(log_prefix + 'Empty response body received.' + log_suffix);
        }
        if (xmlResponseRefund.includes('<FEHLERCODE>0000</FEHLERCODE>')) {
          let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_150',req) +'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
          console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
          return resp;

        }
        else
        {
          var parseString = require('xml2js').parseString;
          parseString(xmlResponseRefund, function (err, result) {
            console.log(result.ANSWER);
            console.log(log_prefix + 'XML Response Code: ' + result.ANSWER.FEHLERCODE + log_suffix);          
            let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_151',req)+'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
            console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
            return resp;
          });
        }
      
    }
    catch(error)
    {
      console.log(log_prefix + error + log_suffix);
      let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_151',req) +'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
      console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
      return resp;
    }
  


  }catch(error)
  {
    console.log(log_prefix + error + log_suffix);
    let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_151',req) +'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
    console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
    return resp;
  }


  
}


async function processRefundVodacomAPI(amount,reference,action_id,payment_id,ean,tid,contract,customer,log_prefix,log_suffix,auto,req){
  let str = amount.substring(0,amount.length-2) + '.' + amount.substring(amount.length-2,2);
  let cont_arr = contract.split('-');
  let currency_name = 'ZAR';
  let currency_code = '710';
  let msg = 'Customer requested a refund';
  if(auto == true)
  {
    msg = 'Transaction failed. Automatic refund';
  }
  
  var bodyRefund = '<er-request id="100034" client-application-id="'+ client_application_id_voda_service +'" purchase_locale="en_ZA" language_locale="en_ZA">' + 
  '<payload>' +
    '<refund-monetary-request>' +
      '<msisdn>27'+ cont_arr[2] +'</msisdn>' +
      '<transaction-id>'+payment_id+'</transaction-id>' +
      '<amount>'+str+'</amount>' +
      '<chargingResource>' +
        '<name>'+currency_name+'</name>' +
        '<code>'+currency_code+'</code>' +
      '</chargingResource>' +
      '<refund-attributes>' +
        '<csr-id>2</csr-id>' +
        '<reason>'+msg+'</reason>' +
        '<partner-id>'+partner_id_voda_service+'</partner-id>' +
      '</refund-attributes>' +
    '</refund-monetary-request>' +
  '</payload>' +
'</er-request>';


console.log(log_prefix + 'Vodacom Refund API Request Body:  ' + bodyRefund + log_suffix);
console.log(log_prefix + 'Vodacom Refund API Refund Url :  ' + vodacomChargeURL + log_suffix);


const fetchOptionsRefund = {
                        method: 'POST',

                        body: bodyRefund,

                        headers: {
                          'Authorization': 'Basic ' + Auth_vodacom,
                          'Content-Type': 'application/xml',
                        },
                        
                      }

var RefundResponseSent = 0;
var refundTimeout = setTimeout(() => { console.log(log_prefix + 'refund time out' + log_suffix); RefundResponseSent = 1; res.send('apiTimeout') }, 30000);
try {

      const response = await fetch(vodacomChargeURL, fetchOptionsRefund,proxy_url);
      const jsonResponseRefund = await response.text();
      clearTimeout(refundTimeout);

      console.log(log_prefix + 'Response Refund:  ' + jsonResponseRefund + log_suffix);
      let responseOKToBeDone = false;
      if(responseOKToBeDone)
      {
        return ('<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT><TXID>'+ reference +'</TXID></RESPONSE>');
      }
      else{
        return ('<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_152',req)+ reference +'. '+ getMessageIDText('MESSAGEID_153',req) + customer + getMessageIDText('MESSAGEID_154',req)+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
      }
    }catch(error)
    {
      console.log(log_prefix + 'Exception!' + log_suffix);
      console.log(error);
      return ('<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_152',req)+ reference +'. '+ getMessageIDText('MESSAGEID_153',req) + customer +  getMessageIDText('MESSAGEID_154',req)+'</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
    }
      
   
  
}

function refundAllowedPerDomain(hostname)
{
  let host = (hostname.split('.'))[0];
   if(hostname == DOMAIN_0)
   {
     return refund_allowed_domain0;
   }
   else if(hostname == DOMAIN_1)
   {
     return refund_allowed_domain1;
   }
   else if(hostname == DOMAIN_2)
   {
     return refund_allowed_domain2;
   }
   else if(hostname == DOMAIN_3)
   {
     return refund_allowed_domain3;
   } else if(config[host]) {
    if(config[host].REFUND) {
      return config[host].REFUND;
    }
  }
   else{
     return '0';
   }
}

function cancelAllowedPerDomain(hostname)
{
  let host = (hostname.split('.'))[0];
   if(hostname == DOMAIN_0)
   {
     return cancel_allowed_domain0;
   }
   else if(hostname == DOMAIN_1)
   {
     return cancel_allowed_domain1;
   }
   else if(hostname == DOMAIN_2)
   {
     return cancel_allowed_domain2;
   }
   else if(hostname == DOMAIN_3)
   {
     return cancel_allowed_domain3;
   } else if(config[host]) {
    if(config[host].CANCEL) {
      return config[host].CANCEL;
    }
   }
   else{
     return '0';
   }
}

async function processRefundVodacomALTPAY(amount,reference,action_id,payment_id,ean,tid,contract,customer,log_prefix,log_suffix,req){

  try { 
  
         let con_arr = contract.split('-');      
         let up_cred = await getUPCredentials(req);
        //altrefund
        
        let bodyRefund = '<REQUEST TYPE="ALTCANCEL">' +       
        '<AUTHORIZATION>' +
        '<USERNAME>'+up_cred.userIdHost+'</USERNAME>' +
        '<PASSWORD>'+up_cred.userPaswdHost+'</PASSWORD>' +
        '</AUTHORIZATION>' +
        '<TERMINALID>'+tid+'</TERMINALID>' +
        '<TXID>'+ reference + '-REFUND' +'</TXID>' +
        '<TXREF>'+ contract + '_CHARGE' +'</TXREF>' +
        '<AMOUNT>' + amount + '</AMOUNT>' +
        '<CURRENCY>710</CURRENCY>' + 
        '<CARD>'  +
        '<PAN>' + '27'+con_arr[2] + '</PAN>' +
        '</CARD>'  +
        '<EXTRADATA>'  +
        '<DATA name="APP">epayPOSAndroid</DATA>' +
        '<DATA name="CUSTOMER_SCAN">1</DATA>' +        
        '<DATA name="CARDTYPE">2643</DATA>' +   
        '<DATA name="REASON">Customer cancelled</DATA>' +           
        '</EXTRADATA>'  +           
        '</REQUEST>';
  
        console.log(log_prefix + bodyRefund + log_suffix);
  
        const fetchOptionsRefund = {
          method: 'POST',
  
          body: bodyRefund
  
        }
        let ALTPayInterfaceURL = UPInterfaceURL;
        console.log(log_prefix + 'UP ALTPAY Refund Request: ' + ALTPayInterfaceURL + log_suffix);
        var RefundResponseSent = 0;
        var refundTimeout = setTimeout(() => { console.log(log_prefix + 'refund time out' + log_suffix); RefundResponseSent = 1; res.send('apiTimeout') }, 30000);
        try {
        const responseRefund = await fetch(ALTPayInterfaceURL, fetchOptionsRefund,proxy_url);
        console.log(log_prefix + 'UP ALTPAY Refund response status code:  '+ responseRefund.statusCode + log_suffix);
        const xmlResponseRefund = await responseRefund.text();
        
          clearTimeout(refundTimeout);
     
          if(xmlResponseRefund.length)
          {
            console.log(log_prefix + xmlResponseRefund + log_suffix);
          }
          else {
            console.log(log_prefix + 'Empty response body received.' + log_suffix);
          }
          if (xmlResponseRefund.includes('<RESULT>0</RESULT>')) {
            let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_150',req) +'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
            console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
            return resp;
  
          }
          else
          {
            var parseString = require('xml2js').parseString;
            parseString(xmlResponseRefund, function (err, result) {
              console.log(result.RESPONSE);
              console.log(log_prefix + 'UP ALTPay Response Code: ' + result.RESPONSE.RESULT + log_suffix);          
              let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_151',req)+'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
              console.log(log_prefix + 'UP ALTPay Refund response sent: ' + resp + log_suffix);
              return resp;
            });
          }
        
      }
      catch(error)
      {
        console.log(log_prefix + error + log_suffix);
        let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_151',req)+'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
        console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
        return resp;
      }
    
  
  
    }catch(error)
    {
      console.log(log_prefix + error + log_suffix);
      let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_151',req)+'(xml_refund)</RESULTTEXT><TXID>'+ reference +'</TXID><CONTRACT>'+contract+'</CONTRACT><CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>';
      console.log(log_prefix + 'XML Refund response sent: ' + resp + log_suffix);
      return resp;
    }
  
  
    
  }

app.get('/getCancel', cors(corsOptions), async (req, res) => {
 
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getCancel => clientip: ' + clientip);

   if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
   if(cancelAllowedPerDomain(req.hostname) == '1'){
   let params = Buffer.from(req.query.params,'base64').toString('utf8');// req.query.params;
   let arr = params.split(',');
   let local_date = arr[0];
   let paymentId = arr[1];
   let tid = arr[2];
   if((tid == '')||(tid == 'undefined'))
   {
      tid = getDefaultTID(req.hostname,req);
   }
   let ean = arr[3];
   let contract = arr[4];
   let amount = arr[5];
   let currency_code = arr[6];


  let txid = getTimeStamp();
  let x = Math.random() * 1000000;
   console.log(x);
   let y = x.toString().split('.');
   console.log(y[0]);
   txid = txid + y[0];
   console.log(txid);

  let tid_prefix = '';
  if(contract.includes('-'))
  {
     let con_a = contract.split('-');
     let sub_con = con_a[1] ? con_a[1] : '';
     if(sub_con.length == 20)
     {
         tid = sub_con.substring(0,8);
         tid_prefix = tid;
     }
     let sub_ph = con_a[2] ? con_a[2] : '';
     if(sub_ph.length > 0)
     {
         txid = sub_ph;
     }
  }

 
    let ref =  getTimeStamp() + '0';
   let reference = 'EPAY-' + tid_prefix + (parseInt(ref)).toString(16).toUpperCase() + '-' + txid;

    let session_id = reference;
      let host_log = req.hostname.split('.');
      let method = 'CANCEL_CODE';
      let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
      let log_suffix = '\n</LOG></SESSION_LOG>';

      console.log(log_prefix + req.headers.campaign + '>>API_CALL:getCancel => clientip: ' + clientip + log_suffix);

      let up_cred = await getUPCredentials(req);

      let userIdHost = up_cred.userIdHost;
      let userPaswdHost = up_cred.userPaswdHost;
      let customer = up_cred.customer;   

    

   const fetchOptions = {
    method: 'POST',

    body: '<REQUEST type="CANCEL">' +        
      '<USERNAME>' + userIdHost + '</USERNAME>' +
      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
       '<TERMINALID>' +  tid +  '</TERMINALID>' + 
      '<LOCALDATETIME>' + local_date + '</LOCALDATETIME>' + 
      '<TXID>' + reference + '</TXID>' + 
      '<TXREF>' + contract + '</TXREF>' +  
      '<AMOUNT>'+ amount +'</AMOUNT>' +  
      '<CURRENCY>'+ currency_code +'</CURRENCY>' +    
      '<CARD>' +        
        '<EAN>'+ ean +'</EAN>' +
      '</CARD>' +   
      
      '</REQUEST>',

    headers: {
      'Content-Type': 'application/xml',
    },

  }
  console.log(log_prefix + 'Cancel Request: ' + UPInterfaceURL + log_suffix);
  mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
  var upCancelTimeout = setTimeout(() => {console.log(log_prefix + 'Cancel Request Timedout ' + log_suffix);res.send('timeout')}, 30000);
  try {
    const response = await fetch(UPInterfaceURL , fetchOptions,proxy_url);
    let  jsonResponse = await response.text();
    clearTimeout(upCancelTimeout);

    console.log(log_prefix + 'Cancel Response received from server' + log_suffix);
        let jsonResponse_log = jsonResponse;
        jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
        mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
////
////    
        if((refundAllowedPerDomain(req.hostname) == '1')&&(jsonResponse.includes('<RESULT>0</RESULT>'))&&((await getPaymentMethods(req.hostname)).includes('checkout')))
        {
        
          let act_id = await getActionIdCaptureCheckout(paymentId,log_prefix,log_suffix,tid,req.hostname,req);
          if((act_id != 'none')&&(act_id.includes('act_')))
          {            
             let response = await processRefundCheckout(amount,reference,act_id,paymentId,ean,tid,contract,customer,log_prefix,log_suffix,req.hostname,req);
             response = response.replace('</RESPONSE>','<CUSTOMER>' + customer + '</CUSTOMER></RESPONSE>');
	           console.log(log_prefix +  response + log_suffix);
             res.send(response);
          }

        }
        else if((refundAllowedPerDomain(req.hostname) == '1')&&(jsonResponse.includes('<RESULT>0</RESULT>'))&&((await checkIfVodacomFlow(req.hostname)) == 'yes'))
        {
            if(getXMLFlag(req.hostname) == '1')
            {
              let response = await processRefundVodacomXML(amount,reference,'',paymentId,ean,tid,contract,customer,log_prefix,log_suffix,req);
              console.log(log_prefix +  response + log_suffix);             
             
            
               res.send(response);
            }
            else if(getXMLFlag(req.hostname) == '0') {

              let response = await processRefundVodacomAPI(amount,reference,'',paymentId,ean,tid,contract,customer,log_prefix,log_suffix,false,req);
             console.log(log_prefix +  response + log_suffix);
             res.send(response);

            }
            else if(getXMLFlag(req.hostname) == '2') {
              let response = await processRefundVodacomALTPAY(amount,reference,'',paymentId,ean,tid,contract,customer,log_prefix,log_suffix,req);
              console.log(log_prefix +  response + log_suffix);
              res.send(response);

            }
          
        }
        else {
        jsonResponse = jsonResponse.replace('</RESPONSE>', '<CUSTOMER>'+customer+'</CUSTOMER></RESPONSE>');
        console.log(log_prefix +  jsonResponse + log_suffix);
        res.send(jsonResponse);
        }       

   
  } catch (err) {
    console.log(err);
    res.send('failed');  
  }
 }
else{
  res.send('<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_155',req)+'</RESULTTEXT></RESPONSE>')
} 

}catch (err)
{
  console.log(err);
  res.send('failed');
}

} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
} else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }


});



/////////////////////Test redeem code///////////////////////////////


async function getProductInfoEAN(ean,userIdHost, userPaswdHost,tidhead, local_date,reference,log_prefix,log_suffix,req) {

  if((ean == 'undefined')||(ean == ''))
  {
     return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_156',req) +'</RESULTTEXT></RESPONSE>';
  }

  let body = '<REQUEST type="CATALOGPRODUCT">' +
  '<USERNAME>' + userIdHost + '</USERNAME>' +
  '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
   tidhead +      
  '<LOCALDATETIME>' + local_date + '</LOCALDATETIME>' + 
  '<TXID>' + reference + '_PINFO' + '</TXID>' +   
  '<EAN>' + ean +'</EAN>' +
  '<LANGUAGE>en-en</LANGUAGE>' +
  '</REQUEST>';

  const fetchOptions = {
    method: 'POST',
    body: body,
    headers: {
      'Content-Type': 'application/xml',
    },
  }

  console.log(log_prefix + 'EAN Info Request: ' + UPInterfaceURL  + log_suffix);
  mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
  var upEanInfoTimeout = setTimeout(() => {return 'timeout';} , 30000);
  try {
    const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
    var  jsonResponse = await response.text();

    console.log(log_prefix + 'EAN Info Response received from server' + log_suffix);
        let jsonResponse_log = jsonResponse;
        jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
        mask_xml_data(jsonResponse_log,log_prefix,log_suffix);   
        clearTimeout(upEanInfoTimeout);
        return jsonResponse;
  } catch (err) {
    console.log(err);
    return 'failed';
  }
}

async function getChargePromoCard(tidhead,reference,amount,code,log_prefix,log_suffix,use_amount,hostname,clientip,req)
{ 

  if((clientip == TEST_IP_AZURE )&&(hostname == 'endlessaisle.epayworldwide.com')) {
    let resp = fs.readFileSync('/var/www/html/ca/redeem.txt', 'utf8');   
    console.log(resp);
    return resp;
    }
    
    let  localdate = getFormattedTime();
    let amount_tag = '<Amount>' + amount + '</Amount>';
    if(!use_amount)
    {
      amount_tag = '';
    }    
    console.log('amount_tag: ' + amount_tag);

    let cred_precision = await getDomainPromoCredentials(req);
 
   let promo_tid = await getDomainPaymentPROMOTID(hostname);
    const fetchOptions = {
      method: 'POST',  
      body: '<REQUEST TYPE="Redeem">' +
      '<USERNAME>'+cred_precision.precisionUser+'</USERNAME>' +
      '<PASSWORD>'+cred_precision.precisionPassword+'</PASSWORD>' +
      '<CARD>' +
      '<PAN>'+code+'</PAN>' +
      '</CARD>' +
     // tidhead +
      '<TERMINALID>' + promo_tid + '</TERMINALID>' +
      '<LOCALDATETIME>'+localdate+'</LOCALDATETIME>' +
      '<TXID>'+reference + '_rd' + '</TXID>' +
      amount_tag + 
      '</REQUEST>',  
      headers: {
        'Content-Type': 'application/xml',
      },
  
    }

   
    console.log(log_prefix + 'CARD REDEEM Request: ' + cred_precision.precisionURL  + log_suffix);
    mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
    var cardRedeemTimeout = setTimeout(() => {return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_123',req) + '</RESULTTEXT></RESPONSE>';} , 30000);
    try {
      let  jsonResponse = '';
             const response = await fetch(cred_precision.precisionURL, fetchOptions,proxy_url);
          jsonResponse = await response.text();
      
          if(jsonResponse.includes('<RESULTTEXT>card unknown</RESULTTEXT>')) {
            jsonResponse = jsonResponse.replace('<RESULTTEXT>card unknown</RESULTTEXT>','<RESULTTEXT>'+ getMessageIDText('MESSAGEID_124',req)+'</RESULTTEXT>');
          }

        clearTimeout(cardRedeemTimeout);

        console.log(log_prefix + 'CARD REDEEM Response received from server' + log_suffix);
        let jsonResponse_log = jsonResponse;
        jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
        mask_xml_data(jsonResponse_log,log_prefix,log_suffix);   
       // clearTimeout(upPreAuthTimeout);
        if(!jsonResponse.includes('<RESULT>'))
        {
         
          let resp = '<RESPONSE><RESULT>1022</RESULT><RESULTTEXT>' + jsonResponse + '</RESULTTEXT></RESPONSE>';
          console.log(log_prefix + resp + log_suffix);
          return  resp;
        }
        else
        {
          return jsonResponse ;
        }
    } catch (err) {
      console.log(err);
      let customer = await getCustomerName(req.hostname);
    let support_url = await getDomainSupportUrl(req.hostname);

      let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_102',req) + customer + getMessageIDText('MESSAGEID_103',req)+ support_url + '</RESULTTEXT></RESPONSE>';;
     
      return str;
    }

}

async function refundPromoDiscount(tid,reference, promocode,log_prefix,log_suffix,req)
{
  let cred_precision = await getDomainPromoCredentials(req);
  let promo_tid = await getDomainPaymentPROMOTID(req.hostname);
  let tidhead = '<TERMINALID>' + promo_tid + '</TERMINALID>';
  let local_date = getFormattedTime();
  let body = '<REQUEST type="cancel">' +
   '<USERNAME>' + cred_precision.precisionUser + '</USERNAME>' +
   '<PASSWORD>' + cred_precision.precisionPassword + '</PASSWORD>' +
  tidhead +  
  '<LOCALDATETIME>' + local_date + '</LOCALDATETIME>'+
  '<TXID>' + reference + '_' + 'rf'  + '</TXID>' +
  '<CARD>' +
          '<PAN>'+ promocode + '</PAN>'+
  '</CARD>' +
  '<TXref>' + reference + '_rd' + '</TXref>' +
  '</REQUEST>';

    const fetchOptions = {
      method: 'POST',
      body: body,
      headers: {
        'Content-Type': 'application/xml',
      },
    }

    console.log(log_prefix + 'PROMO Cancel Request: ' + cred_precision.precisionURL  + log_suffix);
    mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
    var upPreAuthTimeout = setTimeout(() => {return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + getMessageIDText('MESSAGEID_123',req) + '</RESULTTEXT></RESPONSE>';} , 30000);
    try {
       const response = await fetch(cred_precision.precisionURL, fetchOptions,proxy_url);
       let  jsonResponse = await response.text();

      clearTimeout(upPreAuthTimeout);

      console.log(log_prefix + 'PROMO Cancel Response received from server' + log_suffix);
          let jsonResponse_log = jsonResponse;
          jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
          mask_xml_data(jsonResponse_log,log_prefix,log_suffix);   
          //clearTimeout(upPreAuthTimeout);
          if(!jsonResponse.includes('<RESULT>'))
          {
            return  ('<RESPONSE><RESULT>99</RESULT><RESULTTEXT>' + jsonResponse + '</RESULTTEXT></RESPONSE>');
          }else
          {
     
            return jsonResponse ;
          }
    } catch (err) {
      console.log(err);
      return 'failed';
    }

}



function extractUrls(str) {

  const regexp = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?!&//=]*)/gi;
  const regexp1 = /[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?!&//=]*)/gi;

  if (str) {
    console.log(str);
    let urls = str.match(regexp);
    let urls1 = str.match(regexp1);
    console.log('---------------');
    console.log(urls);
    console.log(urls1);
    console.log('---------------');
    if (urls) {
      for (let i = 0; i < urls1.length; i++) {

        console.log('-----++++++++555');

        {
          for (let x = 0; x < urls.length; x++) {
            if (urls[x].includes(urls1[i])) {
              urls1[i] = urls[x];
            }
            console.log('-----++++++++----');
          }
        }
      }
    }

    console.log(urls1);
    console.log('-----++++++++');
    return urls1;
  }
}

async function getDescriptionInfoOLD(catalogData,hostname,ean,req) {

  let country_code = await getCountryCode(hostname);

  let longDescriptionEN = '';
  let shortDescriptionEN = '';
  let redeemptionDesciptionEN = '';
  let redeemptionLink = '';
  let terms = '';
  let brand = '';
  let ret_resp = '';

  let bVodacom = false; 
  if((await checkIfVodacomFlow(hostname)) == 'yes'){
    bVodacom = true;
  }

  let arr = catalogData.split('<EAN>'+ean+'</EAN>');
  let pin_type_str = arr[0].substring(arr[0].length-50,arr[0].length);
  console.log('pin_type_str:  '+ pin_type_str);
  let pin_type = '';
  if((pin_type_str.includes('<TYPE>'))&&(pin_type_str.includes('</TYPE>')))
  {
      let arr = pin_type_str.split('<TYPE>');
      let arr1 = arr[1].split('</TYPE>');
      pin_type = arr1[0];
      console.log('pin_type:  '+ pin_type);

  }
  let arr_1 = arr[1].split('</MEDIA>');
  let blockToParse = '<RESPONSE>'+ '<TYPE>' + pin_type + '</TYPE>' + '<EAN>'+ean+'</EAN>' + arr_1[0] + '</MEDIA>' +'</RESPONSE>';
  
  var parseString = require('xml2js').parseString;
  parseString(blockToParse, function (err, result) {
 
  let symbol = '';

  if(bVodacom)
  {              
    symbol = 'R';
  }
  else
  {
    let currencycode = 'AED';
    
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    }
    var getSymbolFromCurrency = require('currency-symbol-map');
    symbol = getSymbolFromCurrency(currencycode); 
    if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
      symbol = '\u{2800}';
    }              
  }
// Process CANCELABLE////////////////////
  let cancelable  = '0';  

  let arr_cancel = blockToParse.split('<CANCELABLE>');
  if(arr_cancel.length)
  {
      let arr_cancel_1 = arr_cancel[1].split('</CANCELABLE>');            
      cancelable =  arr_cancel_1[0];
  }

  let type  = 'PIN';  

  if((blockToParse.includes('<TYPE>'))&&(blockToParse.includes('</TYPE>')))
  {
      let type_arr = blockToParse.split('<TYPE>');
      if(type_arr.length)
      {
          let type_arr_1 = type_arr[1].split('</TYPE>');            
          type =  type_arr_1[0];
      }
  }
  let discountRRP_tag = '<PREDISCOUNTRRP>none</PREDISCOUNTRRP>';
  if((blockToParse.includes('<PREDISCOUNTRRP>'))&&(blockToParse.includes('</PREDISCOUNTRRP>')))
  {
      let rrp_arr = blockToParse.split('<PREDISCOUNTRRP>');
      if(rrp_arr.length)
      {
          let rrp_arr_1 = rrp_arr[1].split('</PREDISCOUNTRRP>');            
          let rrp =  rrp_arr_1[0];
          discountRRP_tag = '<PREDISCOUNTRRP>' + rrp + '</PREDISCOUNTRRP>';
      }
  }

  let serviceid_tag = '<PRODUCT_CLASSIFICATION>none</PRODUCT_CLASSIFICATION>';
  if((blockToParse.includes('<PRODUCT_CLASSIFICATION>'))&&(blockToParse.includes('</PRODUCT_CLASSIFICATION>')))
  {
      let service_arr = blockToParse.split('<PRODUCT_CLASSIFICATION>');
      if(service_arr.length)
      {
          let service_arr_1 = service_arr[1].split('</PRODUCT_CLASSIFICATION>');            
          let serviceid =  service_arr_1[0];
          serviceid_tag = '<PRODUCT_CLASSIFICATION>' + serviceid + '</PRODUCT_CLASSIFICATION>';
      }
  }


  /////////////////////////////////////////
                 
  let str1 = '';  

  let arr_curr = blockToParse.split('<AMOUNT CURRENCY="');
  let arr_curr_1 = arr_curr[1].split('"');            
  let currency =  arr_curr_1[0];

  ////////////ADD MIN & MAX AMOUNT/////////////////////////////////
  let arrm = arr_curr[1].split('MINAMOUNT="');
  let arrm_1 = arrm[1].split('"');
  let minamount = arrm_1[0];
  arrm = arr_curr[1].split('MAXAMOUNT="');
  arrm_1 = arrm[1].split('"');
  let maxamount = arrm_1[0];

  let min_tag = '<MINAMOUNT>' + minamount + '</MINAMOUNT>';
  let max_tag = '<MAXAMOUNT>' + maxamount + '</MAXAMOUNT>';

  let arr_prov = blockToParse.split('<PROVIDER ID="');
  let arr_prov_1 = arr_prov[1].split('>');            
  let arr_prov_2 = arr_prov_1[1].split('</PROVIDER');
  let provider_ean = arr_prov_2[0];

  let provider_ean_tag = '<PROVIDEREAN>' + provider_ean + '</PROVIDEREAN>';
  /////////////////////////////////////////////////////////////////

  let arr_amt = blockToParse.split('<AMOUNT CURRENCY');
  let arr_amt_1 = arr_amt[1].split('</AMOUNT>');
  let arr_amt_2 = arr_amt_1[0].split('>');
  let str =  arr_amt_2[1];
  let amount_long = str;
  
  console.log('++'+ str);
  if (str == 0) {
    str1 = symbol + '0.00';
  }
  else {
    str1 = symbol + str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
  }
  productdisplayName = result.RESPONSE.NAME[0];	

       
  let xmlINFOLIST = result.RESPONSE.INFOS[0].INFO;
  if (xmlINFOLIST.length) {  
    let enfound = 0;        
    for (let k = 0; k < xmlINFOLIST.length; k++) {         
      let bBrandExists = false;
      
      if((xmlINFOLIST[k].BRAND))
      {
        bBrandExists = true;        
      }                    
      if(!bBrandExists)
      {          
        continue;
      }               

      let xmlLanguage = xmlINFOLIST[k].LANGUAGE;
      if(!(xmlLanguage))
      {
        xmlLanguage = xmlINFOLIST[k].language;
      }
      if (xmlLanguage) {
        let language = xmlLanguage;
        if (language.length) {
          if ((language.includes('en-')) || (language == 'en') || (language == 'eng')) {
            let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
            let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG; 
            terms =  xmlINFOLIST[k].TERMS_AND_CONDITIONS;  
            redeemptionDesciptionEN = xmlINFOLIST[k].DESCRIPTION_REDEMPTION;
            redeemptionLink = xmlINFOLIST[k].REDEMPTION_LINK ? xmlINFOLIST[k].REDEMPTION_LINK : '' ;      
            brand = xmlINFOLIST[k].BRAND ?  xmlINFOLIST[k].BRAND : '';    
            enfound = 1;                
            longDescriptionEN = xmlLongdescr;
            shortDescriptionEN = xmlShortdescr[0];
            let xmlDisplayName = xmlINFOLIST[k].DISPLAY_NAME;
          if (xmlDisplayName.length) {                      
              productdisplayName = xmlDisplayName;                      
          }
          
           if ((longDescriptionEN.length > 1) || (shortDescriptionEN.length > 1)) {
              break;
            }
            else
              continue;
          }
        }
      }              
    }
    
    if (enfound == 0) {

    
      for (let k = 0; k < xmlINFOLIST.length; k++) {                 
      
          let bBrandExists = false;                                  
          if((xmlINFOLIST[k].BRAND?.length > 0))
          {
            bBrandExists = true;
          }
          if(!bBrandExists)
          {          
            continue;
          }
          let xmlShortdescr = xmlINFOLIST[k].DESCRIPTION_SHORT;
          let xmlLongdescr = xmlINFOLIST[k].DESCRIPTION_LONG;
          let xmlDisplayName = xmlINFOLIST[k].DISPLAY_NAME;
          terms =  xmlINFOLIST[k].TERMS_AND_CONDITIONS; 
          redeemptionDesciptionEN = xmlINFOLIST[k].DESCRIPTION_REDEMPTION;
          redeemptionLink = xmlINFOLIST[k].REDEMPTION_LINK ? xmlINFOLIST[k].REDEMPTION_LINK : '' ;  
          brand = xmlINFOLIST[k].BRAND ?  xmlINFOLIST[k].BRAND : '';    
          if (xmlDisplayName.length > 1) {                      
              productdisplayName = xmlDisplayName;                      
          }
          if (xmlShortdescr[0].length) {
           if ((xmlShortdescr[0].length > 1) || (xmlLongdescr.length > 1)) {
              longDescriptionEN = xmlLongdescr;
              shortDescriptionEN = xmlShortdescr[0];
              enfound = 1;
              break;
            }
          }

      }

    }
  }
//  console.log(result.RESPONSE.MEDIA);
 
  let product_logo = '';
  if(result.RESPONSE.MEDIA[0].ARTICLE_IMAGE.length > 0)
  {
    product_logo = result.RESPONSE.MEDIA[0].ARTICLE_IMAGE[0];
  }
  else if(result.RESPONSE.MEDIA[0].LOGO.length > 0)
  {
    product_logo = result.RESPONSE.MEDIA[0].LOGO[0];
  }

  let provider_logo = '';
  if(result.RESPONSE.MEDIA[0].PROVIDER_LOGO.length > 0)
  {
    provider_logo = result.RESPONSE.MEDIA[0].PROVIDER_LOGO[0];
  }


  
  if (productdisplayName.toString().includes('1 Month Renewal')) {

    str1 = str1 + ' per month';
  }
  else
    if (productdisplayName.toString().toLowerCase().includes('12 months renewal') || productdisplayName.toString().toLowerCase().includes('12 month renewal') || productdisplayName.toString().toLowerCase().includes('1 year renewal')) {
      str1 = str1 + ' per year';
    }

    amount_tag = '<AMOUNT>'+str1+'</AMOUNT>';
    let currency_tag = '<CURRENCY>'+currency+'</CURRENCY>';

   let type_tag = '<TYPE>'+type+'</TYPE>'
    let redeemptiondesciptiontag = '';
    let longdescriptiontag = '';
let termstag = '';
    
    if(redeemptionDesciptionEN.length)
       redeemptiondesciptiontag = '<REDEEMDESC>' + redeemptionDesciptionEN + '</REDEEMDESC>';
                
    if(longDescriptionEN.length)
       longdescriptiontag = '<LONGDESC>' + longDescriptionEN + '</LONGDESC>';
    else
        longdescriptiontag = '<LONGDESC>' + shortDescriptionEN + '</LONGDESC>';


    if(terms.length)
       termstag = '<TERMS>' + terms + '</TERMS>';
    

  let desc = shortDescriptionEN.length > 0 ? shortDescriptionEN:longDescriptionEN;

  ret_resp = '<ADD_INFO>' + '<SHORTDESC>' + desc + '</SHORTDESC>' + redeemptiondesciptiontag + longdescriptiontag + termstag + '<LOGO>' + product_logo + '</LOGO>' + '<URLREDEEM>' + redeemptionLink + '</URLREDEEM>' + '<AMOUNT_INFO>' + amount_long + '</AMOUNT_INFO>' + '<AMT_INFO>' + str1 + '</AMT_INFO>' + '<COMPANY>' + brand + '</COMPANY>' +  '<PROVLOGO>' + provider_logo + '</PROVLOGO>' + '<PRODUCT_INFO>' + productdisplayName + '</PRODUCT_INFO>' + '<EAN>'+ean+'</EAN>' + type_tag + currency_tag + min_tag + max_tag + provider_ean_tag + discountRRP_tag + serviceid_tag + '</ADD_INFO>' ;
  console.log(ret_resp);
  

});
console.log(ret_resp);
return ret_resp;

}

async function getProxyPinSaleMulti(ean,tid,product,reference,hostname,userIdHost,userPaswdHost,cashier,txnTime,
  amount,amt,productlogo,provLogo,terms,shortdesciption,company,
  firstname,lastname,email,phone,title,type,posa_serial,currency,code_redeem,
  srcToken,last4,cardtype,cardbin,actionLink,payid,log_prefix,log_suffix,req,PreAuthAddInfoResponse,currencyCodeP)
{
  try {
   
  let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';
  var extrahead = '';
 
  var eanhead = '<EAN>' + ean + '</EAN>';
  var eantouse = ean;
  if (product.includes('Renewal') || product.includes('renewal')) {
    if(!((await checkIfVodacomFlow(req.hostname)) == 'yes'))
    {
      extrahead = '<EXTRADATA>' +
        '<DATA name="CONTRACT">' + reference + '</DATA>' +
        '<DATA name="RedirectionDivisionID">' + (req.hostname.split('.'))[0] + '</DATA>' +
       // '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
        '</EXTRADATA>';
    }
    else {
      extrahead = '<EXTRADATA>' +
        '<DATA name="CONTRACT">' + reference + '</DATA>' +
        '<DATA name="RedirectionDivisionID">vodacom</DATA>' +
        '</EXTRADATA>';
    }
    
  }


if(product.toLowerCase().includes('renewal')) {
  let info = await getTestSubscriptionInfo(req.hostname,ean);
  if(info) {
   tidhead = '<TERMINALID>' + info.TestSubscriptionTID + '</TERMINALID>';
   eanhead = '<EAN>' + info.TestSubscriptionEAN + '</EAN>';
  }
}



  let cashierhead = '';
  if(cashier)
  {
    cashierhead = '<CASHIER>' + cashier + '</CASHIER>';
  }

  let send_sms_tag = '';
  let send_email_tag = '';
  let del_mode = getDeliveryMode(hostname,null);
  if(del_mode.includes('SMS'))
  {
    send_sms_tag = '<SMS>' + '+' + phone + '</SMS>' ;
    
  }

  if(del_mode.includes('EMAIL'))
  {
    if(email.length)
    send_email_tag = '<EMAIL>' + email + '</EMAIL>' ;                
  }

  let PAN_TAG = '';
  let CURRENTCY_TAG = '';

  if(type == 'POSA')
  {
    PAN_TAG = '<PAN>' + posa_serial + '</PAN>';
    CURRENTCY_TAG = '<CURRENCY>' + currency + '</CURRENCY>';
  }

   let firstname_tag = '';
  if(firstname.length)
  {
    firstname_tag = '<NAME>' + firstname + '</NAME>'
  }

  let lastname_tag = '';
  if(lastname.length)
  {
    lastname_tag = '<SURNAME>' + lastname + '</SURNAME>'
  }

  let title_tag = '';
  if(title.length)
  {
    title_tag = '<TITLE>' + title + '</TITLE>'
  }

   //Business in a box
   if(await isBusinesInABoxAkani(tid,ean,req)) {
    let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + reference + '</DATA>';
    if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
      extrahead = extrahead.replace('</EXTRADATA>', REFID_URL_TAG+'</EXTRADATA>')
    }
    else {
      extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
    }
    
  }

  let serial_proxy_tag = '<Comment>' + 'PaymentMethod=proxy|SERIAL=' + '</Comment>';
  if(PreAuthAddInfoResponse.includes('<SERIAL>')) {

    let a =  PreAuthAddInfoResponse.split('<SERIAL>');
    let b = a[1].split('</SERIAL>');
    serial_proxy_tag =  '<Comment>' + 'PaymentMethod=proxy|SERIAL=' +  b[0] + '</Comment>';
  }

  let fetchOptions = {
    method: 'POST',

    body: '<REQUEST type="SALE" STORERECEIPT="1">' +
      '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
      tidhead +
      cashierhead +
      '<TXID>' + (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference) + '</TXID>' +
      '<USERNAME>' + userIdHost + '</USERNAME>' +
      '<CARD>' +
      PAN_TAG +
      eanhead +                  
      '</CARD>' +
      '<AMOUNT>'+ amount +'</AMOUNT>' +
      CURRENTCY_TAG +
      '<CONSUMER>' +
      firstname_tag +
      lastname_tag  +
    //  '<EMAIL>' + email + '</EMAIL>' +
      send_sms_tag +
      send_email_tag +
       title_tag +       
      '</CONSUMER>' +
      serial_proxy_tag +
      extrahead +
      '</REQUEST>',

    headers: {
      'Content-Type': 'application/xml',
    },

  }

 
 
  console.log(log_prefix + 'PROXY SALE Request: ' + UPInterfaceURL + log_suffix);

  console.log(fetchOptions.body);
  //mask_xml_data(fetchOptions.body,log_prefix,log_suffix);

 const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
 var jsonResponse = await response.text();

 jsonResponse = await updateRedeemptionURL(jsonResponse);

  const UUID = require('pure-uuid');
  const id = new UUID(4).format();
  let encyptBlockTime = getTimeStamp();

  let block =  id + '/' + reference + '.pkpass' + ',' + encyptBlockTime;
  let token = encrypt(block);
  let jsonResponse_log = jsonResponse ;
  jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
  
  console.log(log_prefix + 'PROXY SALE Response:' + log_suffix);

  mask_xml_data(jsonResponse_log,log_prefix,log_suffix);


   let encyptBlockTimeGMT = new Date();
  let passLink = 'https://' + hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();

  if(jsonResponse.includes('<RESULT>0</RESULT>'))
  {

    let activation_serial_tag = '<ACTIVATIONSERIAL>' + posa_serial + '</ACTIVATIONSERIAL>';
    let product_type_tag = '<PRODUCTTYPE>' + type + '</PRODUCTTYPE>';
    let currency_tag = '<CURRENCYCODEP>'+currencyCodeP+'</CURRENCYCODEP>';      
    let discount_tag = '<PROMODISCOUNT>' + amount + '</PROMODISCOUNT>';
    let promo_tag = '<PROMOCODE>' + 'xxxx' +code_redeem.substring(code_redeem.length - 4, code_redeem.length) + '</PROMOCODE>';
    let partial_tag = '<PARTIALPAY>' + '0'+ '</PARTIALPAY>';
    let apple_pass_tag = '<PASS></PASS>';
    if(await getApplePassAllowed(req.hostname) == 'yes')
    {
      apple_pass_tag = '<PASS>' + passLink + '</PASS>';
    }
    jsonResponse = jsonResponse + 
      '<PAID>' + amt + '</PAID>' + 
      '<PRODUCT>' + product + '</PRODUCT>' +
      '<HOME>https://' + hostname + '</HOME>' + '<EAN>' + ean +'</EAN>' + '<TYPE>' + type + '</TYPE>' +
      apple_pass_tag + discount_tag + promo_tag + currency_tag + partial_tag + activation_serial_tag + product_type_tag;     

    jsonResponse_log = jsonResponse ;
    jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

    mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

    
  }

  
  if (jsonResponse.includes('<RESULT>0</RESULT>')) {
    console.log(reference); 
    var strref = reference;
    var arrRefSplit = strref.split('-');
    var actlink = '';// redeemURL;
    var productKey = '';
    var prodSerial = '';
    if (jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
      var newarr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</DATA>');
        actlink = arr1[0];
      }
    }

    if (jsonResponse.includes('<PIN>')) {
      var newarr = jsonResponse.split('<PIN>');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</PIN>');
        productKey = arr1[0];
      }
    }

    if (jsonResponse.includes('<SERIAL>')) {
      var newarr = jsonResponse.split('<SERIAL>');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</SERIAL>');
        prodSerial = arr1[0];
      }
    }
    var prodExpiry = '';
    if (jsonResponse.includes('<VALIDTO>')) {
      var newarr = jsonResponse.split('<VALIDTO>');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</VALIDTO>');
        prodExpiry = arr1[0];
        if (prodExpiry == '3000-01-01 00:00:00') {
          prodExpiry = 'Never Expires';
        }
      }
    }
 
    

let emailToSend =  email;
let phoneToSend =  phone;
let emailTAG= '<EMAIL></EMAIL>';
let phoneTAG = '<PHONE></PHONE>';
if(emailToSend)
{
  if(emailToSend.length > 0)
  {
      emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
  }
}
if(phoneToSend)
{
  if(phoneToSend.length > 0)
  {
      phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
  }
}


if ((product.includes('Renewal')) || product.includes('renewal')) {
  let auth_tag = '';
  let auth_code = '';
 console.log('actionLink::::'+actionLink);
 if(actionLink)
 {
   auth_code = await getAuthCode(actionLink,tid,hostname,log_prefix,log_suffix,req);
   console.log(log_prefix + 'auth_code: ' + auth_code + log_suffix);
   if(auth_code != 'none')
   {
     auth_code = '-' + auth_code;
   }
   else
   {
     auth_code = '';
   }
   auth_tag = '<AUTHCODE>' + auth_code.replace('-','') + '</AUTHCODE>';
   console.log(auth_tag);
}



 let payid_tag = '';
 if(payid)
 {
   payid_tag = '<PAYMENTID>' + payid + '</PAYMENTID>' ;
 }

 let cardbin_tag = '';
 if(cardbin)
 {
   cardbin_tag = '<BIN>' + cardbin + '</BIN>';
 }
 let reftype_tag = '';
 if(email)
 {
   reftype_tag = '<REFTYPE>SERIAL</REFTYPE>';
 }
 else {
   reftype_tag =  '<REFTYPE>CONTRACTID</REFTYPE>';
 }

let ref_pay =  'EPAY-'+(parseInt(getTimeStamp())).toString(16).toUpperCase() + '-' + phoneToSend.substring(phoneToSend.length -9,phoneToSend.length);


 const fetchOptionsInfo = {
 method: 'POST',

 body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
 '<USERNAME>' + userIdHost + '</USERNAME>' +
 '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
 tidhead +
 '<LOCALDATETIME>' + getFormattedTime() + '</LOCALDATETIME>' +    
 '<TXID>' + (ref_pay.includes('EPAY-undefined') ? ref_pay.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): ref_pay)
   + '</TXID>' + //reference  + '_PI'
 '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
 '<SUBSCRIPTION>' +
 '<TOKENID>' + srcToken + '</TOKENID>' +
 '<LASTFOUR>' + last4 + '</LASTFOUR>' +
 '<CARDTYPE>' + cardtype + '</CARDTYPE>' +
 payid_tag +
 emailTAG +
 phoneTAG +
 cardbin_tag +
 auth_tag +
 '</SUBSCRIPTION>' +
 '<TRANSACTIONREF>' +
 reftype_tag +
 '<REF>' + reference + '</REF>' +
 '</TRANSACTIONREF>' +
 '</REQUEST>',

 headers: {
 'Content-Type': 'application/xml',
 },

 }


   console.log(log_prefix + 'PROXY PIN PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
   mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
   console.log(log_prefix + paymentInfoURL + log_suffix);
   const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
   var jsonResponseInfo = await response.text();

 console.log(log_prefix + 'PROXY PIN PAYMENTINFO Response:' + log_suffix);
 let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
   mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);

}
let allowed_google = await getGooglePassAllowed(req.hostname);
let allowed_apple = await getApplePassAllowed(req.hostname);

    if((allowed_google == 'yes')||(allowed_apple == 'yes')) {
    try {
      const findRemoveSync = require('find-remove');
      
      if(allowed_google == 'yes') { 
        let objGoogle = [];
        objGoogle.push({
        reference:reference,
        productLogo:productlogo,
        product:product,
        provider:company,
        serial:prodSerial,
        expiry:prodExpiry,
        amount:amt,
        pin:productKey,
        description:shortdesciption,
        tx_time:txnTime,
        refSplit:arrRefSplit[1],
        phone:phone,
        terms:terms,
        actlink:actlink,
        providerLogo:provLogo,
        id:id,
        stripe:''
      });
      await generateGooglePass(objGoogle[0]);
   
      objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
      let googlePassUrl = await createPassObject(objGoogle);

      jsonResponse = jsonResponse + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
      console.log('Response GPass: ' + googlePassUrl);
      setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
    } else {
      jsonResponse = jsonResponse + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';
    }

     
      if(allowed_apple == 'yes')
      {
        await generatePass(productlogo, reference, product, prodSerial, prodExpiry, amt, productKey, shortdesciption[0], txnTime, arrRefSplit[1], phone, terms[0], actlink,provLogo, id);
        setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
      }                
      
      
    }
    catch (err)
    {
      console.log(log_prefix + err + log_suffix);
    }
  }
    return jsonResponse;
    
  }
  else{
    return (jsonResponse + '<HOME>https://' + hostname + '</HOME>' + '<EAN>' + ean +'</EAN>');
  }

}
catch(err)
{
  console.log(err);
  return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_107',req)+'</RESULTTEXT></RESPONSE>'
}

}

async function getProxyPinSale(ean,tid,product,reference,hostname,userIdHost,userPaswdHost,cashier,txnTime,
                                                        amount,amt,productlogo,provLogo,terms,shortdesciption,company,firstname,lastname,email,phone,title,type,posa_serial,currency,code_redeem,log_prefix,log_suffix,req,currencyCodeP)
{
  try {
   
  let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';
  var extrahead = '';
 
  var eanhead = '<EAN>' + ean + '</EAN>';
  var eantouse = ean;
  if (product.includes('Renewal') || product.includes('renewal')) {
    if(!(await checkIfVodacomFlow(req.hostname) == 'yes'))
    {
      extrahead = '<EXTRADATA>' +
        '<DATA name="CONTRACT">' + reference + '</DATA>' +
        '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
        '</EXTRADATA>';
    }
    else {
      extrahead = '<EXTRADATA>' +
        '<DATA name="CONTRACT">' + reference + '</DATA>' +
        '<DATA name="RedirectionDivisionID">vodacom</DATA>' +
        '</EXTRADATA>';
    }
    
  }



    if(product.toLowerCase().includes('renewal')) {
      let info = await getTestSubscriptionInfo(req.hostname,ean);
      if(info) {
      tidhead = '<TERMINALID>' + info.TestSubscriptionTID + '</TERMINALID>';
      eanhead = '<EAN>' + info.TestSubscriptionEAN + '</EAN>';
      }
    }

  let cashierhead = '';
  if(cashier)
  {
    cashierhead = '<CASHIER>' + cashier + '</CASHIER>';
  }

  let send_sms_tag = '';
  let send_email_tag = '';
  let del_mode = getDeliveryMode(hostname,null);
  if(del_mode.includes('SMS'))
  {
    send_sms_tag = '<SMS>' + '+' + phone + '</SMS>' ;
    
  }

  if(del_mode.includes('EMAIL'))
  {
    send_email_tag = '<EMAIL>' + email + '</EMAIL>' ;                
  }

  let PAN_TAG = '';
  let CURRENTCY_TAG = '';

  if(type == 'POSA')
  {
    PAN_TAG = '<PAN>' + posa_serial + '</PAN>';
    CURRENTCY_TAG = '<CURRENCY>' + currency + '</CURRENCY>';
  }

  //Business in a box
  if(await isBusinesInABoxAkani(tid,ean,req)) {
    let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + reference + '</DATA>';
    if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
      extrahead = extrahead.replace('</EXTRADATA>', REFID_URL_TAG+'</EXTRADATA>')
    }
    else {
      extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
    }
    
  }

  let fetchOptions = {
    method: 'POST',

    body: '<REQUEST type="SALE" STORERECEIPT="1">' +
      '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
      tidhead +
      cashierhead +
      '<TXID>' + (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference) + '</TXID>' +
      '<USERNAME>' + userIdHost + '</USERNAME>' +
      '<CARD>' +
      PAN_TAG +
      eanhead +                  
      '</CARD>' +
      '<AMOUNT>'+ amount +'</AMOUNT>' +
      CURRENTCY_TAG +
      '<CONSUMER>' +
      '<NAME>' + firstname + '</NAME>' +
      '<SURNAME>' + lastname + '</SURNAME>' +
    //  '<SMS>' + '+' + phone + '</SMS>' +
    //  '<EMAIL>' + email + '</EMAIL>' +
      send_sms_tag +
      send_email_tag +
      '<TITLE>' + title + '</TITLE>' +      
      '</CONSUMER>' +
      extrahead +
      '</REQUEST>',

    headers: {
      'Content-Type': 'application/xml',
    },

  }

 
 
  console.log(log_prefix + 'PROXY SALE Request: ' + UPInterfaceURL + log_suffix);

  console.log(fetchOptions.body);
  //mask_xml_data(fetchOptions.body,log_prefix,log_suffix);

 const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
 var jsonResponse = await response.text();

 jsonResponse = await updateRedeemptionURL(jsonResponse);

  const UUID = require('pure-uuid');
  const id = new UUID(4).format();
  let encyptBlockTime = getTimeStamp();

  let block =  id + '/' + reference + '.pkpass' + ',' + encyptBlockTime;
  let token = encrypt(block);
  let jsonResponse_log = jsonResponse ;
  jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
  
  console.log(log_prefix + 'PROXY SALE Response:' + log_suffix);

  mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

  //let passLink = 'https://' + hostname + '/getPASS.pkpass?token=' + token ;
  let encyptBlockTimeGMT = new Date();
  let passLink = 'https://' + hostname + '/getPASS.pkpass?token=' + token + '&tm_cr_token=' + encyptBlockTimeGMT.toUTCString();

  if(jsonResponse.includes('<RESULT>0</RESULT>'))
  {

    let activation_serial_tag = '<ACTIVATIONSERIAL>' + posa_serial + '</ACTIVATIONSERIAL>';
    let product_type_tag = '<PRODUCTTYPE>' + type + '</PRODUCTTYPE>';
    let currency_tag = '<CURRENCYCODEP>'+currencyCodeP+'</CURRENCYCODEP>';      
    let discount_tag = '<PROMODISCOUNT>' + amount + '</PROMODISCOUNT>';
    let promo_tag = '<PROMOCODE>' + 'xxxx' +code_redeem.substring(code_redeem.length - 4, code_redeem.length) + '</PROMOCODE>';
    let partial_tag = '<PARTIALPAY>' + '0'+ '</PARTIALPAY>';
    let apple_pass_tag = '<PASS></PASS>';
    if(await getApplePassAllowed(req.hostname) == 'yes')
    {
      apple_pass_tag = '<PASS>' + passLink + '</PASS>';
    }

    let discRRP = await getDiscountRRP(ean,tid,req);
    let vat = await getItemVAT(req,ean,tid);
    let discountrrp_tag = '<PREDISCOUNTRRP>' + discRRP + '</PREDISCOUNTRRP>';
    let vat_tag = '<VAT>' + vat + '</VAT>';

    jsonResponse = jsonResponse + 
      '<PAID>' + amt + '</PAID>' + 
      '<PRODUCT>' + product + '</PRODUCT>' +
      '<HOME>https://' + hostname + '</HOME>' + '<EAN>' + ean +'</EAN>' + '<TYPE>' + type + '</TYPE>' +
      apple_pass_tag + discount_tag + promo_tag + currency_tag + partial_tag + activation_serial_tag + product_type_tag 
      + discountrrp_tag + vat_tag;     

    jsonResponse_log = jsonResponse ;
    jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");

    mask_xml_data(jsonResponse_log,log_prefix,log_suffix);

    
  }

  
  if (jsonResponse.includes('<RESULT>0</RESULT>')) {
    console.log(reference); 
    var strref = reference;
    var arrRefSplit = strref.split('-');
    var actlink = '';// redeemURL;
    var productKey = '';
    var prodSerial = '';
    if (jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
      var newarr = jsonResponse.split('<DATA name="REDEMPTIONURL">');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</DATA>');
        actlink = arr1[0];
      }
    }

    if (jsonResponse.includes('<PIN>')) {
      var newarr = jsonResponse.split('<PIN>');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</PIN>');
        productKey = arr1[0];
      }
    }

    if (jsonResponse.includes('<SERIAL>')) {
      var newarr = jsonResponse.split('<SERIAL>');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</SERIAL>');
        prodSerial = arr1[0];
      }
    }
    var prodExpiry = '';
    if (jsonResponse.includes('<VALIDTO>')) {
      var newarr = jsonResponse.split('<VALIDTO>');
      if (newarr.length > 1) {
        var arr1 = newarr[1].split('</VALIDTO>');
        prodExpiry = arr1[0];
        if (prodExpiry == '3000-01-01 00:00:00') {
          prodExpiry = 'Never Expires';
        }
      }
    }
 
    

let emailToSend =  email;
let phoneToSend =  phone;
let emailTAG='';
let phoneTAG = '';
if(emailToSend)
{
  if(emailToSend.length > 0)
  {
      emailTAG = '<EMAIL>'+emailToSend+'</EMAIL>';
  }
}
if(phoneToSend)
{
  if(phoneToSend.length > 0)
  {
      phoneTAG = '<PHONE>'+phoneToSend+'</PHONE>';
  }
}


    if ((product.includes('Renewal')) || product.includes('renewal')) {

  

      const fetchOptionsInfo = {
        method: 'POST',

        body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
          '<USERNAME>' + userIdHost + '</USERNAME>' +
          '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
          tidhead +
          '<LOCALDATETIME>' + txnTime + '</LOCALDATETIME>' +
          // '<TXID>' + inforef + '-' + jsonResponsetok.source.bin + auth_code + '</TXID>' +
          '<TXID>' + (reference.includes('EPAY-undefined') ? reference.replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): reference)  + '_PI' + '</TXID>' +
          '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
          '<SUBSCRIPTION>' +
          // '<TOKENID>' + jsonResponsetok.source.id + '</TOKENID>' +
          // '<LASTFOUR>' + jsonResponsetok.source.last4 + '</LASTFOUR>' +
          // '<CARDTYPE>' + jsonResponsetok.source.scheme + '</CARDTYPE>' +
          // '<PAYMENTID>' + jsonResponsetok.id + '</PAYMENTID>' +
          emailTAG +
          phoneTAG +
          //  '<BIN>' + jsonResponsetok.source.bin + '</BIN>' +
          //  '<AUTHCODE>' + auth_code.replace('-','') + '</AUTHCODE>' +
          '</SUBSCRIPTION>' +
          '<TRANSACTIONREF>' +
          '<REFTYPE>SERIAL</REFTYPE>' +
          '<REF>' + reference + '</REF>' +
          '</TRANSACTIONREF>' +
          '</REQUEST>',

        headers: {
          'Content-Type': 'application/xml',
        },
  
      }

   


    }
    let allowed_google = await getGooglePassAllowed(req.hostname);
      let allowed_apple = await getApplePassAllowed(req.hostname);
    if((allowed_apple == 'yes')||(allowed_google == 'yes')) {
    try {

      const findRemoveSync = require('find-remove');
      
      if(allowed_google == 'yes') { 

        let objGoogle = [];
        objGoogle.push({
        reference:reference,
        productLogo:productlogo,
        product:product,
        provider:company,
        serial:prodSerial,
        expiry:prodExpiry,
        amount:amt,
        pin:productKey,
        description:shortdesciption,
        tx_time:txnTime,
        refSplit:arrRefSplit[1],
        phone:phone,
        terms:terms,
        actlink:actlink,
        providerLogo:provLogo,
        id:id,
        stripe:''
      });
      await generateGooglePass(objGoogle[0]);
      //objGoogle[0].stripe = 'https://' + hostname + '/static/media/Google/passes/' + objGoogle[0].id + '/strip@2x.png';
      objGoogle[0].stripe = 'https://' + req.hostname + '/static/media/Google/passes/' + objGoogle[0].id + '_strip@2x.png';
      let googlePassUrl = await createPassObject(objGoogle);

      jsonResponse = jsonResponse + '<PASSGOOGLE>' + googlePassUrl + '</PASSGOOGLE>';
      console.log('Response GPass: ' + googlePassUrl);
      setTimeout(findRemoveSync.bind(this, basepath + 'static/media/Google/passes' , {prefix: objGoogle[0].id}), 900000);
    } else {
      jsonResponse = jsonResponse + '<PASSGOOGLE>' + '' + '</PASSGOOGLE>';
    }

   
      if(allowed_apple == 'yes')
      {
        await generatePass(productlogo, reference, product, prodSerial, prodExpiry, amt, productKey, shortdesciption[0], txnTime, arrRefSplit[1], phone, terms[0], actlink,provLogo, id);
        setTimeout(findRemoveSync.bind(this,folderNamePass + id , {age: {seconds: 60},extensions: '.pkpass',}), 900000);
      }                
 

    }
    catch (err)
    {
      console.log(log_prefix + err + log_suffix);
    }
  }
    return jsonResponse;
    
  }
  else{
    return (jsonResponse + '<HOME>https://' + hostname + '</HOME>' + '<EAN>' + ean +'</EAN>');
  }

}
catch(err)
{
  console.log(err);
  return '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_107',req)+'</RESULTTEXT></RESPONSE>'
}

}

app.get('/getActivationCode', cors(corsOptions), async (req, res) => {
 
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getActivationCode => clientip: ' + clientip);
 
   if(req.headers.referer) 
   {
     if(await checkIfRefererAllowed(req.headers.referer,req)) 
      {
       try {
 
   
    let data = Buffer.from(req.query.data,'base64').toString('utf8');    
    console.log(data)
    let arr = data.split(',');
    if(arr.length > 1)
    {

      let ean_redeem = arr[0];
      let TID = arr[1];



     if((TID == '') || (TID == 'undefined') || (TID == 'notid'))
     {
        TID = getDefaultTID(req.hostname,req);        
     }

  
 
      var txid = getTimeStamp();
     var x = Math.random() * 1000000;
     console.log(x);
     var y = x.toString().split('.');
     console.log(y[0]);
     txid = txid + y[0];
     console.log(txid);
 
      let ref =  getTimeStamp() + '0';
      let reference = 'EPAY-' + TID + (parseInt(ref)).toString(16).toUpperCase() + '-' + txid.substring(0,9);
 
      let session_id = reference;
      let host_log = req.hostname.split('.');
      let method = 'REDEEM_CODE';
      let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
      let log_suffix = '\n</LOG></SESSION_LOG>';
      console.log(log_prefix + req.headers.campaign + '>>API_CALL:getActivationCode => clientip: ' + clientip + log_suffix);

      let customer = await getCustomerName(req.hostname); 
  
      
    

        let blockToParse = await getCatalog(req.hostname,TID,ean_redeem,0,req);
        console.log(blockToParse);
          
        if(blockToParse != 'no_data')
        {      

            let desc_info = await getDescriptionInfo(blockToParse,req.hostname,ean_redeem,req);        
            let add_info = '';
            let type = '';
            if(desc_info.includes('<ADD_INFO>'))
            {
                let arr = desc_info.split('<ADD_INFO>');
                let arr1 = arr[1].split('</ADD_INFO>');
            
                add_info = arr1[0];
                console.log(add_info);                

                arr = add_info.split('<TYPE>');
                arr1 = arr[1].split('</TYPE>');
                type = arr1[0];
            }     
    
            
            console.log(add_info);
            if(type == 'POSA')
            {
              
              let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT>' + '<ADD_INFO>' + add_info + '</ADD_INFO></RESPONSE>';
              console.log(resp);
              res.send(resp); 
            } 
            else
            {              
              let resp = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_158',req) + customer + getMessageIDText('MESSAGEID_133',req)+'</RESULTTEXT></RESPONSE>';
              console.log(resp);
              res.send(resp); 
            }  

            
    
        }
        else
          res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_160',req)+'</RESULTTEXT></RESPONSE>');    
   
     
  }
  else
  {
    
    res.send('failed');
  }
 
 }catch (err)
   {
     console.log(err);
     res.send('failed');
   }
 
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
   } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
 
 
 });

 async function getItemVAT(req,ean,tid){

  let blockToParse = await getCatalog(req.hostname,tid,ean,0,req);       
    console.log('getItemVAT==>>' + req.hostname + ',' + tid + ',' + ean);      

    let VAT = '0';        
  if(blockToParse != 'no_data')
  {
    if(blockToParse.includes('<VAT>')) {
        let a = blockToParse.split('<VAT>');    
        let b = a[1].split('</VAT>');
        let c = b[0];
        if((c == '-1')||(c == '0')){
           VAT = '0';
        }
        else {
          VAT = '5';
        }
    } 

    console.log('ITEM VAT = ' + VAT );
    return VAT;

  }
  else {
    console.log(log_prefix + 'CARREFOUR EAN INFO NOT FOUND !!' + log_suffix);
    let item = ',';
    return item;
  }

 }



async function getProxyMultiCheckout(data_query,clientip,req,jsonResponsetok,voda) 
{
    try {


 let data = Buffer.from(data_query,'base64').toString('utf8');
 console.log(data)
 let arr = data.split(',');
 if(arr.length)
 {
   let local_date = arr[0];
   let code_redeem = arr[1];
   let ean_redeem = arr[2];
   let amount_to_redeem = arr[3];
   let TID = arr[4];
   let currency = arr[5];
   let cashier = arr[6];
   let firstname = arr[7];
   let lastname = arr[8];
   let email = arr[9];
   let phone = arr[10];
   let title = arr[11];
   let charge = arr[12];
   let bCharged = false;

  if((TID == '') || (TID == 'undefined') || (TID == 'notid'))
  {
     TID = getDefaultTID(req.hostname,req);        
  }

  let tidhead = '<TERMINALID>' + TID + '</TERMINALID>' ;

   var txid = getTimeStamp();
  var x = Math.random() * 1000000;
  console.log(x);
  var y = x.toString().split('.');
  console.log(y[0]);
  txid = txid + y[0];
  console.log(txid);
   if(phone.length) {
    txid = phone.substring((phone.length-9),phone.length);
  }

   let ref =  getTimeStamp() + '0';
   let reference = 'EPAY-' + TID + (parseInt(ref)).toString(16).toUpperCase() + '-' + txid.substring(0,9);

  let session_id = reference;
    let host_log = req.hostname.split('.');
    let method = 'REDEEM_CODE';
    let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
    let log_suffix = '\n</LOG></SESSION_LOG>';
    console.log(log_prefix + req.headers.campaign + '>>API_CALL:getRedeemCode => clientip: ' + clientip + log_suffix);

    let up_cred = await getUPCredentials(req);

    let userIdHost = up_cred.userIdHost;
    let userPaswdHost = up_cred.userPaswdHost;
    let customer = up_cred.customer;
  


  let PreAuthAddInfoResponse = await getPromoCardStatus(tidhead,reference,code_redeem,log_prefix,log_suffix,clientip,req);
  let posa_serial = '';


  let ean_to_use = '';
   

  if((PreAuthAddInfoResponse.includes('<RESULT>0</RESULT>'))&&(PreAuthAddInfoResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))&&(PreAuthAddInfoResponse.includes('<ATTRIBUTE NAME="PROXY')))
  {

     let add_info_bundle = '';
     let proxy_sale_bundle = '';
     let jsonResponse_redeem = '';
 
     let arr  = PreAuthAddInfoResponse.split('<ATTRIBUTE NAME="PROXY');
     console.log('JSON:>'+ arr);
     let count_proxy = arr.length;// - 1;
     console.log('arr.length::'+arr.length+arr);

     for(let i=1; i<count_proxy; i++)
     {
       let arr1 = arr[i].split('</ATTRIBUTE>');
       let arr2 = arr1[0].split('">');
       ean_to_use = arr2[1]; //arr1[0]        
       console.log('ean_to_use multi: ' + req.hostname + '::' +  ean_to_use + '::' + TID);
       let blockToParse = await getCatalog(req.hostname,TID,ean_to_use,0,req);

       if(blockToParse == 'no_data')
       {
         console.log(blockToParse);
       }

         
       if(blockToParse != 'no_data')
       {      

           let desc_info = await getDescriptionInfo(blockToParse,req.hostname,ean_to_use,req);        
           let add_info = '';
           let add_info_append = '';      
           let product = '';
           let amount = '';
           let amt = '';
           let terms = '';
           let productlogo = '';
           let shortdesciption = '';
           let company = '';
           let provLogo = '';
           let currencyCodeP = '';
           if(desc_info.includes('<ADD_INFO>'))
           {
               add_info_bundle = add_info_bundle + desc_info;
               let arr = desc_info.split('<ADD_INFO>');
               let arr1 = arr[1].split('</ADD_INFO>');
           
               add_info = arr1[0];
             //  console.log(add_info);      

               arr = add_info.split('<PRODUCT_INFO>');
               arr1 = arr[1].split('</PRODUCT_INFO>');
               product = arr1[0];

               arr = add_info.split('<AMOUNT_INFO>');
               arr1 = arr[1].split('</AMOUNT_INFO>');
               amount = arr1[0];
               add_info_append = arr[0];

               arr = add_info.split('<AMT_INFO>');
               arr1 = arr[1].split('</AMT_INFO>');
               amt = arr1[0];

               arr = add_info.split('<SHORTDESC>');
               arr1 = arr[1].split('</SHORTDESC>');
               shortdesciption = arr1[0];

               arr = add_info.split('<TERMS>');
               arr1 = arr[1].split('</TERMS>');
               terms = arr1[0];

               arr = add_info.split('<LOGO>');
               arr1 = arr[1].split('</LOGO>');
               productlogo = arr1[0];

               arr = add_info.split('<PROVLOGO>');
               arr1 = arr[1].split('</PROVLOGO>');
               provLogo = arr1[0];

               arr = add_info.split('<COMPANY>');
               arr1 = arr[1].split('</COMPANY>');
               company = arr1[0];

               arr = add_info.split('<TYPE>');
               arr1 = arr[1].split('</TYPE>');
               type = arr1[0]; 

               arr = add_info.split('<CURRENCY>');
               arr1 = arr[1].split('</CURRENCY>');
               currencyCodeP = arr1[0];

               if((add_info.includes('<PREDISCOUNTRRP>'))&&(!add_info.includes('none</PREDISCOUNTRRP>')))
                {
                    let rrp_arr = add_info.split('<PREDISCOUNTRRP>');
                    if(rrp_arr.length)
                    {
                        let rrp_arr_1 = rrp_arr[1].split('</PREDISCOUNTRRP>');            
                        let rrp =  rrp_arr_1[0];
                        let rrp_o = rrp;
                        if(rrp.length > 2)
                          rrp = rrp_o.substring(0,rrp_o.length-2) + '.' + rrp_o.substring(rrp_o.length-2,rrp_o.length);
                        
                        add_info = add_info.replace('<PREDISCOUNTRRP>' + rrp_o + '</PREDISCOUNTRRP>','<PREDISCOUNTRRP>' + rrp + '</PREDISCOUNTRRP>');
                    }
                }


           }     
   
           let proxy_sale = ''; 
           if(charge == 'yes')
           {
             
             if(bCharged == false)
             {
               jsonResponse_redeem = await getChargePromoCard(tidhead,reference,amount,code_redeem,log_prefix,log_suffix,false,req.hostname,clientip,req);
               if (jsonResponse_redeem.includes('<RESULT>0</RESULT>')) {
                 bCharged = true;
               }
             }
             if (jsonResponse_redeem.includes('<RESULT>0</RESULT>')) {
              let srcToken = '';
              let last4 = '';
              let cardtype = '';
              let cardbin = '';
              let actionLink = '';
              let payid = '';
              if(jsonResponsetok)
              {
                 srcToken = jsonResponsetok.source.id;
                 last4 = jsonResponsetok.source.last4;
                 cardtype = jsonResponsetok.source.scheme;
                 cardbin = jsonResponsetok.source.bin;
                 actionLink = jsonResponsetok._links.actions.href;
                 payid = jsonResponsetok.id;
                 reference = jsonResponsetok.reference;
              }
              else if(voda) {
                srcToken = voda[0].srcToken;
                last4 = voda[0].last4;
                cardtype = voda[0].cardtype;
                cardbin = null;
                actionLink = null;
                payid = null;
              }
               let ref_pin = reference ;
             // if(count_proxy > 2)
              if(i > 1)
              {
                ref_pin = reference + '_' + i;
              }
               proxy_sale = await getProxyPinSaleMulti(ean_to_use,TID,product,ref_pin,req.hostname,userIdHost,userPaswdHost,cashier,local_date,
               amount,amt,productlogo,provLogo,terms,shortdesciption,company,firstname,lastname,email,phone,title,type,posa_serial,currency,code_redeem,
               srcToken,last4,cardtype,cardbin,actionLink,payid,log_prefix,log_suffix,req,PreAuthAddInfoResponse,currencyCodeP);          
               //res.send(proxy_sale + add_info); 
               let discRRP = await getDiscountRRP(ean_to_use,TID,req);
               let vat = await getItemVAT(req,ean_to_use,TID);
               let discountrrp_tag = '<PREDISCOUNTRRP>' + discRRP + '</PREDISCOUNTRRP>';
               let vat_tag = '<VAT>' + vat + '</VAT>';
               //proxy_sale_bundle = proxy_sale_bundle + '<PROXY_SALE>' + proxy_sale + add_info + vat_tag + discountrrp_tag + '</PROXY_SALE>';
               if(proxy_sale.includes('<RESULT>0</RESULT>')){
                proxy_sale_bundle = proxy_sale_bundle + '<PROXY_SALE>' + proxy_sale + add_info + vat_tag + discountrrp_tag + '</PROXY_SALE>';
               }
             }
             else {
               let resp = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_161',req)+'</RESULTTEXT></RESPONSE>';
               console.log(log_prefix + resp + log_suffix);
               return resp;
               
             }

           }  
           else {
       
             let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT>' + '<ADD_INFO_BUNDLE>' + add_info_bundle + '</ADD_INFO_BUNDLE></RESPONSE>';
    proxy_sale_bundle = proxy_sale_bundle + '<PROXY_SALE>' + add_info + '</PROXY_SALE>';
      
           }   

           
   
       }
       else
       {
         let jResp = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_160',req)+'</RESULTTEXT></RESPONSE>';
         console.log(log_prefix + jResp + log_suffix);
      
         return jResp;
       }   
     }

    //  let jResp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT>' +
    //   '<PROXY_SALE_BUNDLE>' + proxy_sale_bundle +'</PROXY_SALE_BUNDLE>' + '</RESPONSE>';
    //  let jResp_log = jResp;
    //  mask_xml_data(jResp_log,log_prefix,log_suffix);
    //  return jResp;

        //proxy time out sale
        let jResp = '<RESPONSE><RESULT>1023</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_162',req)+'</RESULTTEXT><HOME>' + req.headers.referer + '</HOME><EAN></EAN></RESPONSE>';

        if(proxy_sale_bundle.includes('<PROXY_SALE>')) { 
            jResp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT>' +
              '<PROXY_SALE_BUNDLE>' + proxy_sale_bundle + '</PROXY_SALE_BUNDLE>' + '</RESPONSE>';
            let jResp_log = jResp;
            mask_xml_data(jResp_log,log_prefix,log_suffix);       
        } else {
          console.log(jResp,log_prefix,log_suffix);
        }
        
        return jResp;
   }
   else
   {
     if(!PreAuthAddInfoResponse.includes('<RESULT>0</RESULT>'))
     {
      return PreAuthAddInfoResponse;
     }
     else if(!PreAuthAddInfoResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))
     {
       let errorText = getMessageIDText('MESSAGEID_126',req);
       if(PreAuthAddInfoResponse.includes('<CARDSTATUS>NOTACTIVATED</CARDSTATUS>'))
       {
         errorText = getMessageIDText('MESSAGEID_127',req)
       }
       else if(PreAuthAddInfoResponse.includes('<CARDSTATUS>DEACTIVATED</CARDSTATUS>'))
       {
         errorText = getMessageIDText('MESSAGEID_128',req)
       }
       else if(PreAuthAddInfoResponse.includes('<CARDSTATUS>REDEEMED</CARDSTATUS>'))
       {
         errorText = getMessageIDText('MESSAGEID_129',req);
       }
       
       return '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT></RESPONSE>'; 

     }
     else
     return '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_157',req)+'</RESULTTEXT></RESPONSE>';
   }
}

    }catch (err)
    {
      console.log(err);
      return 'failed';
    }
 }

app.get('/getRedeemCodeMulti', cors(corsOptions), async (req, res) => {
 
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getRedeemCode => clientip: ' + clientip);
 try {
   if(req.headers.referer) 
   {
     if(await checkIfRefererAllowed(req.headers.referer,req)) 
      {

        if((await getProxyCodeAllowed(req.hostname)) == 'yes') {
      
        let jsonResp = await getProxyMultiCheckout(req.query.data,clientip,req,null);            
        console.log(jsonResp);
        res.send(jsonResp); 
        } else {
          let resp = '<RESPONSE><RESULT>170</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_137',req) + '</RESULTTEXT></RESPONSE>';
          console.log(resp);
          res.send(resp);
        }
 
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
   } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } catch (err) {
    console.log(err);
    res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>');
  }
 
 });

app.get('/getRedeemCode', cors(corsOptions), async (req, res) => {
 
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getRedeemCode => clientip: ' + clientip);
 
   if(req.headers.referer) 
   {
     if(await checkIfRefererAllowed(req.headers.referer,req)) 
      {
       try {
 
   
    let data = Buffer.from(req.query.data,'base64').toString('utf8');
    console.log(data)
    let arr = data.split(',');
    if(arr.length)
    {
      let local_date = arr[0];
      let code_redeem = arr[1];
      let ean_redeem = arr[2];
      let amount_to_redeem = arr[3];
      let TID = arr[4];
      let currency = arr[5];
      let cashier = arr[6];
      let firstname = arr[7];
      let lastname = arr[8];
      let email = arr[9];
      let phone = arr[10];
      let title = arr[11];
      let charge = arr[12];

     if((TID == '') || (TID == 'undefined') || (TID == 'notid'))
     {
        TID = getDefaultTID(req.hostname,req);        
     }

     let tidhead = '<TERMINALID>' + TID + '</TERMINALID>' ;
 
      var txid = getTimeStamp();
     var x = Math.random() * 1000000;
     console.log(x);
     var y = x.toString().split('.');
     console.log(y[0]);
     txid = txid + y[0];
     console.log(txid);
 
      let ref =  getTimeStamp() + '0';
      let reference = 'EPAY-' + TID + (parseInt(ref)).toString(16).toUpperCase() + '-' + txid.substring(0,9);
 
     let session_id = reference;
       let host_log = req.hostname.split('.');
       let method = 'REDEEM_CODE';
       let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
       let log_suffix = '\n</LOG></SESSION_LOG>';
       console.log(log_prefix + req.headers.campaign + '>>API_CALL:getRedeemCode => clientip: ' + clientip + log_suffix);
 
  
     
     let up_cred = await getUPCredentials(req);

     let userIdHost = up_cred.userIdHost;
     let userPaswdHost = up_cred.userPaswdHost;
     let customer = up_cred.customer;
   

     let PreAuthAddInfoResponse = await getPromoCardStatus(tidhead,reference,code_redeem,log_prefix,log_suffix,clientip,req);
     let posa_serial = '';


     let ean_to_use = '';
      

     if((PreAuthAddInfoResponse.includes('<RESULT>0</RESULT>'))&&(PreAuthAddInfoResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))&&(PreAuthAddInfoResponse.includes('<ATTRIBUTE NAME="PROXY')))
     {
        let arr  = PreAuthAddInfoResponse.split('<ATTRIBUTE NAME="PROXY');
        let arr1 = arr[1].split('</ATTRIBUTE>');
        ean_to_use = arr1[0];      

        let blockToParse = await getCatalog(req.hostname,TID,ean_to_use,0,req);
        console.log(blockToParse);
          
        if(blockToParse != 'no_data')
        {      

            let desc_info = await getDescriptionInfo(blockToParse,req.hostname,ean_to_use,req);        
            let add_info = '';
            let add_info_append = '';      
            let product = '';
            let amount = '';
            let amt = '';
            let terms = '';
            let productlogo = '';
            let shortdesciption = '';
            let company = '';
            let provLogo = '';
            currencyCodeP = '';
            if(desc_info.includes('<ADD_INFO>'))
            {
                let arr = desc_info.split('<ADD_INFO>');
                let arr1 = arr[1].split('</ADD_INFO>');
            
                add_info = arr1[0];
                console.log(add_info);      

                arr = add_info.split('<PRODUCT_INFO>');
                arr1 = arr[1].split('</PRODUCT_INFO>');
                product = arr1[0];

                arr = add_info.split('<AMOUNT_INFO>');
                arr1 = arr[1].split('</AMOUNT_INFO>');
                amount = arr1[0];
                add_info_append = arr[0];

                arr = add_info.split('<AMT_INFO>');
                arr1 = arr[1].split('</AMT_INFO>');
                amt = arr1[0];

                arr = add_info.split('<SHORTDESC>');
                arr1 = arr[1].split('</SHORTDESC>');
                shortdesciption = arr1[0];

                arr = add_info.split('<TERMS>');
                arr1 = arr[1].split('</TERMS>');
                terms = arr1[0];

                arr = add_info.split('<LOGO>');
                arr1 = arr[1].split('</LOGO>');
                productlogo = arr1[0];

                arr = add_info.split('<PROVLOGO>');
                arr1 = arr[1].split('</PROVLOGO>');
                provLogo = arr1[0];

                arr = add_info.split('<COMPANY>');
                arr1 = arr[1].split('</COMPANY>');
                company = arr1[0];

                arr = add_info.split('<TYPE>');
                arr1 = arr[1].split('</TYPE>');
                type = arr1[0];

                arr = add_info.split('<CURRENCY>');
                arr1 = arr[1].split('</CURRENCY>');
                currencyCodeP = arr1[0];
            }     
    
            let proxy_sale = ''; 
            if(charge == 'yes')
            {
              let jsonResponse_redeem = await getChargePromoCard(tidhead,reference,amount,code_redeem,log_prefix,log_suffix,false,req.hostname,clientip,req);

              if (jsonResponse_redeem.includes('<RESULT>0</RESULT>')) {
                proxy_sale = await getProxyPinSale(ean_to_use,TID,product,reference,req.hostname,userIdHost,userPaswdHost,cashier,local_date,
                amount,amt,productlogo,provLogo,terms,shortdesciption,company,firstname,lastname,email,phone,title,type,posa_serial,currency,code_redeem,log_prefix,log_suffix,req,currencyCodeP);          
                res.send(proxy_sale + add_info);  
              }
              else {
                res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_161',req)+'</RESULTTEXT></RESPONSE>')
              }
            }  
            else {
              console.log(add_info);
              let resp = '<RESPONSE><RESULT>0</RESULT><RESULTTEXT>transaction successful</RESULTTEXT>' + '<ADD_INFO>' + add_info + '</ADD_INFO></RESPONSE>';
              console.log(resp);
              res.send(resp); 
            }   

            
    
        }
        else
          res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_160',req)+'</RESULTTEXT></RESPONSE>');    
      }
      else
      {
        if(!PreAuthAddInfoResponse.includes('<RESULT>0</RESULT>'))
        {
          res.send(PreAuthAddInfoResponse);
        }
        else if(!PreAuthAddInfoResponse.includes('<CARDSTATUS>ACTIVATED</CARDSTATUS>'))
        {
          let errorText = getMessageIDText('MESSAGEID_126',req);
          if(PreAuthAddInfoResponse.includes('<CARDSTATUS>NOTACTIVATED</CARDSTATUS>'))
          {
            errorText = getMessageIDText('MESSAGEID_127',req)
          }
          else if(PreAuthAddInfoResponse.includes('<CARDSTATUS>DEACTIVATED</CARDSTATUS>'))
          {
            errorText = getMessageIDText('MESSAGEID_128',req)
          }
          else if(PreAuthAddInfoResponse.includes('<CARDSTATUS>REDEEMED</CARDSTATUS>'))
          {
            errorText = getMessageIDText('MESSAGEID_129',req);
          }
          
          res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+errorText+'</RESULTTEXT></RESPONSE>'); 

        }
        else
            res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_157',req)+'</RESULTTEXT></RESPONSE>');
      }
  }
 
 }catch (err)
   {
     console.log(err);
     res.send('failed');
   }
 
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
   } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
 
 
 });
/////////////////////////////////////////////////////////////////////

app.get('/getHASH', cors(corsOptions), async (req, res) => {

  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getHash => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        console.log('getHash function started');
        //var str = req.query.otp;
        let str = Buffer.from(req.query.otp,'base64').toString('utf8');
        var arr = str.split(',');
        var otp = arr[0];
        var genHash = arr[1];
        var genHashTime = arr[2];
        let obj_instore = '';
        let reference = '';
        console.log(str);
        console.log(arr);
        if(arr.length == 4)
        {
           let obj_b64 = arr[3];
           let obj_instore_buff = Buffer.from(obj_b64,'base64').toString('utf8');
           console.log(obj_instore_buff);
           //obj_instore = JSON.parse(obj_instore_buff);
           let obj_instore_arr = JSON.parse(obj_instore_buff);
           obj_instore = obj_instore_arr[0];
           console.log(obj_instore);
           reference = obj_instore.reference;
        }
        
        
        let session_id = reference;
        let host_log = req.hostname.split('.');
        let method = 'GET_HASH';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';

        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getHash => clientip: ' + clientip + log_suffix);

        console.log(str);
        var currentTimeStamp = getTimeStamp();
        var otpGenTime = decrypt(genHashTime);
        if (otpGenTime.length > 0) {
          var tmArr = otpGenTime.split(',');
          if (tmArr.length > 0) {
            console.log(currentTimeStamp + '::' + tmArr[1]);
            //if ((currentTimeStamp - tmArr[1]) > 300) {
            if (Number(await date_difference(currentTimeStamp,tmArr[1])) > 300) {
              var response = 'KO' + ',' + 'OTPTimedOut';
              res.send(response);
    
            }
            else {
              console.log(otp);
              const hashValue = crypto.createHash('sha256', secret).update(otp).digest('hex');
              
              if((genHash == hashValue)||(otpTest && (otp == otpTest))) {
                let toencrypt = tmArr[0] + ',' + currentTimeStamp;
                let response = 'OK' + ',' + encrypt(toencrypt);
                if(arr.length == 4) 
                { //gethash instore
                    console.log('obj_instore==>>'+obj_instore);
                    let amount_product = await getAmountEAN(obj_instore.tid,obj_instore.ean,log_prefix,log_suffix,req.hostname,clientip,req);
                    if((obj_instore.promoApplied == '1')&&(obj_instore.discountApplied != '0')&&(obj_instore.promoCode.length > 0))
                    {
                      
                      let result = await chargePromoCode(obj_instore.tid,obj_instore.promoCode,obj_instore.discountApplied,obj_instore.reference,log_prefix,log_suffix,amount_product,req.hostname,clientip,req)
                      if(result != 'Success')
                      {
                        let response =  'KO' + ',' + result;
                        console.log(log_prefix + response +log_suffix);
                        res.send(response);
                        return;
                      }
                    } 
                    else if(obj_instore.promoApplied == '1')
                    {
                      let response =  'KO' + ',' + '<RESPONSE><RESULT>11</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_119',req)+'</RESULTTEXT></RESPONSE>';
                      console.log(log_prefix + response +log_suffix);
                      res.send(response);
                      return;
                    }
                    let amount_serial = Number(amount_product) - Number(obj_instore.discountApplied);
                    let resp = await getPaySerial(obj_instore.tid,obj_instore.reference,amount_serial.toString(),log_prefix,log_suffix,req.hostname,clientip,obj_instore.tid,req);               
                    if((resp.includes('<RESULT>0</RESULT>'))||(resp.includes('<RESULT>1012</RESULT>')))
                    {
                      if(resp.includes('<RESULT>1012</RESULT>')) {
                      await updatePaymentInfoInstore(obj_instore.tid,obj_instore.reference,obj_instore.ean,'DCB',obj_instore.phone.substring((obj_instore.phone.length-4),obj_instore.phone.length),obj_instore.phone,obj_instore.phone,'',req.hostname, log_prefix,log_suffix,req);
                      }
                      // Add code to generate encypted info for promo payment, ean and serial for validation and append to response
                      let a1 = resp.split('<PAN>');
                      let a2 = a1[1].split('</PAN>');
                      let payment_serial = a2[0];
                      let block = amount_product + ',' + payment_serial + ',' + obj_instore.ean + ',' + obj_instore.promoCode + ',' + obj_instore.discountApplied + ',' + obj_instore.reference + ',' + obj_instore.promoApplied;
                      let token = encrypt(block);
                      let add_tag_enc = '<ENCBLOCK>' + token + '</ENCBLOCK>' ;
                      resp = resp.replace('</RESPONSE>', add_tag_enc + '</RESPONSE>');

                      block = obj_instore.phone + ',' + obj_instore.phone.substring(obj_instore.phone.length-4,obj_instore.phone.length) + ',' + 
                      'DCB' + ','+  '' + ',' + '' + ',' + '';
                      token =  encrypt(block);
                      add_tag_enc = '<ENCBLOCKSUBS>' + token + '</ENCBLOCKSUBS>' ;
                      resp = resp.replace('</RESPONSE>', add_tag_enc + '</RESPONSE>');

                      resp = resp.replace('</RESPONSE>', '<PHONE>' + obj_instore.phone + '</PHONE>' + '</RESPONSE>');

                      resp = Buffer.from(resp).toString('base64');  
                      resp = response + ',' + resp;
                      console.log(log_prefix + resp +log_suffix);
                      res.send(resp);
                    }
                    else {
                      console.log(log_prefix + 'Payment serial genartion failed' +log_suffix);
                      res.send('KO,' + resp);
                    }
                    
              }
              else if(arr.length == 5) {
                let buff = Buffer.from(arr[4],'base64').toString('utf8');
                let a = buff.split(',');
                let phone = a[10];
                let data = [];
                data.push({
                  srcToken:phone,
                  last4:phone.substring(phone.length - 4, phone.length),
                  cardtype:'DCB'                                       
                
                })
                let resp = await getProxyMultiCheckout(arr[4],clientip,req,null,data); 
                resp = Buffer.from(resp).toString('base64');               
                resp = response + ',' + resp;
                console.log(log_prefix + resp + log_suffix);
                res.send(resp);

              }
              else
              {
                 console.log(log_prefix + response +log_suffix);
                 res.send(response);
              }
              }
              else {
                let response = 'KO' + ',' + 'timestamp';
                console.log(log_prefix + response +log_suffix);
                res.send(response);
              }

            }

          }
          else {
            let response = 'KO' + ',' + 'timestamp';
            console.log(log_prefix + response +log_suffix);
            res.send(response);
          }
        }
        else {
          let response = 'KO' + ',' + 'timestamp';
          console.log(log_prefix + response +log_suffix);
          res.send(response);
        }

      } catch (error) {
        console.log(error);
        let response = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
        console.log( response);
        res.send(response);
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});



function getSMSBody_PIN_Customer(productkey, reference, serial, phone, product, redeemLink, amount,hostname,jsonResponse) {
  
  var frequency = '';
  var redeemText = '';

  if (redeemLink) {
    redeemText = 'Please redeem the product key: ' + redeemLink + ' ';
  }
  if (product.includes('Renewal')) {
    var amountArr;
    if (amount.includes(' per ')) {
      amountArr = amount.split(' per ');
      amount = amountArr[0];
    }

    frequency = product.includes('1 Month Renewal') ? '/month' : ((product.includes('12 Months Renewal') || product.includes('1 Year Renewal')) ? '/year' : '')
  }

  var smsText = 'Hi, Thank you for your purchase. Your ' + product + ' product key is ' + productkey + ' and order reference ' + reference + '. You will be charged ' + amount + ' on your Vodacom account. Please redeem the product key: ' + redeemLink + ' Further together. Vodacom.';
  
  if(product.includes('Renewal')||product.includes('renewal')){
    smsText = 'Hi, Your ' + product + ' product key is ' + productkey + ' and order reference ' + reference + '. You will be charged at ' + amount + frequency + ' on your Vodacom account. Please redeem the product key: ' + redeemLink + ' To unsubscribe click https://'+ hostname +'/manageaccount/ Further together. Vodacom.';
  
    if(jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
      console.log('New SMS format activation:');
      let a = jsonResponse.split('<DATA name="REDEMPTIONURL">');
      let b = a[1].split('</DATA>');
      let shortUrl = b[0];
  
      smsText = 'Hi, You have successfully subscribed to ' + product + '. Your order reference is ' + reference + '. You will be charged at ' + amount + ' on your Vodacom account. To activate follow this link: ' + shortUrl + ' To unsubscribe click https://'+ hostname +'/manageaccount/ Further together. Vodacom.';
      
    }
    console.log('Success SMS: ' + smsText);
  }
  var smsBody = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<oas:Security soap:mustUnderstand="1" xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<oas:UsernameToken oas1:Id="UsernameToken-1" xmlns:oas1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<oas:Username>'+ username_voda_service + '</oas:Username>' +
    '<oas:Password>'+ password_voda_service + '</oas:Password>' +
    '</oas:UsernameToken>' +
    '</oas:Security>' +
    '</soap:Header>' +
    '<soapenv:Body>' +
    '<loc:sendSms xmlns:loc="http://www.csapi.org/schema/parlayx/sms/send/v2_2/local">' +
    '<loc:addresses>tel:' + phone + '</loc:addresses>' +
    //'<ns12:addresses>tel:27660000000000</ns12:addresses>' +
    '<loc:senderName>'+ senderName_voda_service + '</loc:senderName>' +
    '<loc:message>'+ smsText + '</loc:message>' +
    '</loc:sendSms>' +
    '</soapenv:Body>' +
    '</soapenv:Envelope>';





  return smsBody;

}

function getSMSBody(otp, phone, amount) {

  var sms = '';
  var str = amount;
  var strAmountInDecimal = '';
  if((str != 'nodata') && (!str.includes('.')) )
  {
     strAmountInDecimal = str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
  }

  if (amount == 'nodata') {
    sms = 'Hi, your One-Time PIN is ' + otp + '. This PIN expires in 5 min. Do not share this with anyone. Don' + "'" + 't recognize this activity? Please call Customer Care on 082135, FREE from a Vodacom cellphone number. Vodacom';
  }
  else {
    sms = 'Hi, :) Vodacom payment confirmation for a total of amount ' + 'R' + strAmountInDecimal + '. Your PIN for this purchase is ' + otp + '. Further together, Vodacom';
  }
console.log('tes with old format...');
  var smsBody = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<oas:Security soap:mustUnderstand="1" xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<oas:UsernameToken oas1:Id="UsernameToken-1" xmlns:oas1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<oas:Username>'+ username_voda_service + '</oas:Username>' +
    '<oas:Password>'+ password_voda_service + '</oas:Password>' +
    '</oas:UsernameToken>' +
    '</oas:Security>' +
    '</soap:Header>' +
    '<soapenv:Body>' +
    '<loc:sendSms xmlns:loc="http://www.csapi.org/schema/parlayx/sms/send/v2_2/local">' +
    '<loc:addresses>tel:' + phone + '</loc:addresses>' + 
   // '<ns12:addresses>tel:27660000000000</ns12:addresses>' +
    '<loc:senderName>'+ senderName_voda_service + '</loc:senderName>' + 
    '<loc:message>' + sms + '</loc:message>' +
    '</loc:sendSms>' +
    '</soapenv:Body>' +
    '</soapenv:Envelope>';

var smsBody4444 = '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<SOAP-ENV:Header>' +
        '<ns14:Security xmlns:ns10="http://group.vodafone.com/contract/vfo/fault/v1" xmlns:ns12="http://www.csapi.org/schema/parlayx/sms/send/v2_2/local" xmlns:ns13="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ns14="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:ns15="http://www.csapi.org/schema/parlayx/common/v2_1" xmlns:ns2="http://group.vodafone.com/schema/common/v1" xmlns:ns3="urn:un:unece:uncefact:documentation:standard:CoreComponentType:2" xmlns:ns4="http://group.vodafone.com/schema/vbo/subscription/subscription-profile/v1" xmlns:ns5="http://group.vodafone.com/schema/extension/vbo/subscription/subscription-profile/v1" xmlns:ns6="http://group.vodafone.com/schema/vbm/subscription/subscription-profile/v1" xmlns:ns7="http://group.vodafone.com/contract/vho/header/v1" xmlns:ns8="http://docs.oasis-open.org/wsrf/bf-2" xmlns:ns9="http://www.w3.org/2005/08/addressing">' +
            '<ns14:UsernameToken>' +
                '<ns14:Username>'+ username_voda_service + '</ns14:Username>' +
                '<ns14:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">'+ password_voda_service + '</ns14:Password>' +
            '</ns14:UsernameToken>' +
        '</ns14:Security>' +
    '</SOAP-ENV:Header>' +
    '<SOAP-ENV:Body>' +
        '<ns12:sendSms xmlns:ns10="http://group.vodafone.com/contract/vfo/fault/v1" xmlns:ns12="http://www.csapi.org/schema/parlayx/sms/send/v2_2/local" xmlns:ns13="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ns14="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:ns15="http://www.csapi.org/schema/parlayx/common/v2_1" xmlns:ns2="http://group.vodafone.com/schema/common/v1" xmlns:ns3="urn:un:unece:uncefact:documentation:standard:CoreComponentType:2" xmlns:ns4="http://group.vodafone.com/schema/vbo/subscription/subscription-profile/v1" xmlns:ns5="http://group.vodafone.com/schema/extension/vbo/subscription/subscription-profile/v1" xmlns:ns6="http://group.vodafone.com/schema/vbm/subscription/subscription-profile/v1" xmlns:ns7="http://group.vodafone.com/contract/vho/header/v1" xmlns:ns8="http://docs.oasis-open.org/wsrf/bf-2" xmlns:ns9="http://www.w3.org/2005/08/addressing">' +
            '<ns12:addresses>tel:' + phone + '</ns12:addresses>' +
            '<ns12:senderName>'+ senderName_voda_service + '</ns12:senderName>' +
            '<ns12:message>' + sms + '</ns12:message>' +
        '</ns12:sendSms>' +
    '</SOAP-ENV:Body>' +
'</SOAP-ENV:Envelope>';

  return smsBody;

}

app.get('/getCaptcha', async (req, res) => {

  const clientip = req.headers['incap-client-ip'] ;  
  console.log(req.headers.campaign + '>>API_CALL:getCaptcha => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
         const { CaptchaGenerator } = require("captcha-canvas");
          const captcha = new CaptchaGenerator()
          .setDimension(150, 450) 
          .setCaptcha({size: 50, font:'DejaVu Sans Mono', color: "#70c62d"})
          .setDecoy({font:'DejaVu Sans Mono',size:30, opacity: 0.5})
          .setTrace({color: "#70c62d"});
          const buffer = captcha.generateSync(); //everything is optional simply using `new CaptchaGenerator()` will also work.
          let auth_token = encrypt(getTimeStamp() + ',' + captcha.text);

          let imageData = 'data:image/png;base64,' + buffer.toString('base64');
          res.send({image:imageData, token:auth_token});

      }
        catch (error) {
          console.log(error);          
          res.send('exception');
         
       
        }

      } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  

});

async function checkSubscriptionAvailability(TID,phone,hostname,req)
{
  try {  
 
    phone = phone.substring(phone.length-9,phone.length);
    
    let currentDate = getFormattedTime();
    let ref =  getTimeStamp();
    let reference = 'EPAY-' + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;

    let up_cred = await getUPCredentials(req);

    let userIdHost = up_cred.userIdHost;
    let userPaswdHost = up_cred.userPaswdHost;
    

    let TERMINAL_ID = getDefaultTID(req.hostname,req);

    
    if(!((await checkIfVodacomFlow(req.hostname)) == 'yes'))
    {
      if((TID.length) && (TID != 'undefined'))
      {
        TERMINAL_ID = TID;
        reference = 'EPAY-' + TERMINAL_ID + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;

      }   

    
    }
                 

    if((req.headers.referer.includes('/mcafee')) && (TEST_IP_AZURE == clientip)) {
      let info = await getTestSubscriptionInfo(req.hostname,null) 
      if(info) {          
            TERMINAL_ID = info.TestSubscriptionTID ;      
            reference = 'EPAY-' + TERMINAL_ID + (parseInt(ref)).toString(16).toUpperCase() + '-' + phone;      
      }
    }

    const fetchOptions = {
      method: 'POST',
      body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
        '<AUTHORIZATION>' +
        '<USERNAME>' + userIdHost + '</USERNAME>' +
        '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
        '</AUTHORIZATION>' +
        '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
        '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
        '<TXID>' + reference + '</TXID>' +
        '<SUBSCRIPTION>' +
        '<PHONE>' + phone + '</PHONE>' +
        '<STATUS>ACTIVE</STATUS>' +
        '</SUBSCRIPTION>' +
        '</REQUEST>',

      headers: {
        'Content-Type': 'application/xml',
      },

    }
    //console.log(fetchOptions.body);
    var contractFetchTimeout = setTimeout(() => {return false}, 30000);
    
    
      const response = await fetch(getContractURL, fetchOptions,proxy_url);
      let jsonResponse = await response.text();
      console.log(jsonResponse)
      clearTimeout(contractFetchTimeout);
      if((jsonResponse.includes('<RESULT>0</RESULT>'))&&(jsonResponse.includes('</SUBSCRIPTION>'))) {
        return true;
      }
      else {
        const fetchOptions_unsubs = {
          method: 'POST',
          body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
            '<AUTHORIZATION>' +
            '<USERNAME>' + userIdHost + '</USERNAME>' +
            '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
            '</AUTHORIZATION>' +
            '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
            '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
            '<TXID>' + 'UNSUBS' +  reference  + '</TXID>' +
            '<SUBSCRIPTION>' +
            '<PHONE>' + phone + '</PHONE>' +
            '<STATUS>UNSUBSCRIBED</STATUS>' +
            '</SUBSCRIPTION>' +
            '</REQUEST>',

          headers: {
            'Content-Type': 'application/xml',
          },

        }
        const response_unsubs = await fetch(getContractURL, fetchOptions_unsubs,proxy_url);
        let jsonResponse_unsubs = await response_unsubs.text();
        console.log(jsonResponse_unsubs);
        if((jsonResponse_unsubs.includes('<RESULT>0</RESULT>'))&&(jsonResponse_unsubs.includes('</SUBSCRIPTION>')))
        {
         return true;
        }
        else 
        {
          
            const fetchOptions_inactive = {
              method: 'POST',
              body: '<REQUEST type="SUBSCRIPTION" mode="CHECK">' +
                '<AUTHORIZATION>' +
                '<USERNAME>' + userIdHost + '</USERNAME>' +
                '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                '</AUTHORIZATION>' +
                '<TERMINALID>'+TERMINAL_ID+'</TERMINALID>' +
                '<LOCALDATETIME>' + currentDate + '</LOCALDATETIME>' +
                '<TXID>' + 'INACT' +  reference  + '</TXID>' +
                '<SUBSCRIPTION>' +
                '<PHONE>' + phone + '</PHONE>' +
                '<STATUS>INACTIVE</STATUS>' +
                '</SUBSCRIPTION>' +
                '</REQUEST>',
    
              headers: {
                'Content-Type': 'application/xml',
              },
    
            }
            const response_inactive = await fetch(getContractURL, fetchOptions_inactive,proxy_url);
            let jsonResponse_inactive = await response_inactive.text();
            console.log(jsonResponse_inactive);
            if((jsonResponse_inactive.includes('<RESULT>0</RESULT>'))&&(jsonResponse_inactive.includes('</SUBSCRIPTION>')))
            {
             return true;
            }
            else
             return false;
            
          

        }
      //   return false;
        
      }
  
    }
    catch(err)
    {
      console.log(err);
      return false;
    }

}


app.get('/sendSMS_ib', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;  
  console.log(req.headers.campaign + '>>API_CALL:sendSMS_ib => clientip: ' + clientip);
 
  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        console.log(req.headers);
        console.log('req.headers.host ==>> ' + req.headers.host);
        //var strData = req.query.data;
        let strData = Buffer.from(req.query.data,'base64').toString('utf8');
        console.log(strData);

        //var str = req.query.data;
        let str = Buffer.from(req.query.data,'base64').toString('utf8');
        console.log(str);
        var arr = str.toString().split(",");

         let session_id = arr[0];
         let host_log = req.hostname.split('.');
         let api = 'SEND_OTP_MANAGEACCOUNT';
         let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ api +'</METHOD><LOG>\n';
         let log_suffix = '\n</LOG></SESSION_LOG>';

         console.log(log_prefix + req.headers.campaign + '>>API_CALL:sendSMS_ib => clientip: ' + clientip + log_suffix);
        
        let phone = arr[1];   
        
        let TID = arr[3];
        let enteredCaptcha = arr[4];
        let encToken = arr[5];      
        let method = arr[6];  

        let decrypt_block = decrypt(encToken);
        let decArr = decrypt_block.split(',');
        let timeCaptchaGen = decArr[0];
        let captcha = decArr[1];
        
        if((Number(await date_difference(getTimeStamp(),timeCaptchaGen)) > 180) && (method == 'send'))
        {
          console.log(log_prefix + 'captchaExpired' + log_suffix);
          res.send('captchaExpired');

        }
        else if(!(captcha == enteredCaptcha))
        {
          console.log(log_prefix + 'invalidCaptcha' + log_suffix);
          res.send('invalidCaptcha');
        }
        else if((!(await checkSubscriptionAvailability(TID,phone,req.hostname,req)))&&(method == 'send'))
        {
          console.log(log_prefix + 'noSubscriptions' + log_suffix);
          res.send('noSubscriptions');
        }
        else {       

        var x = Math.floor(100000 + Math.random() * 900000);
        var y = x.toString().split('.');
        var otp = y[0];

        const hashValue = crypto.createHash('sha256', secret).update(otp).digest('hex');
        console.log("Hash Obtained is: ", hashValue);

        var timestamp = getTimeStamp();
        console.log(timestamp);

        let host_name = await getCustomerName(req.hostname);
       
  
       // var infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infobip_msg_sender+ '","text":"Hi, your One Time Password is '+otp+' and will expire in 5 min. Do not share this with anyone. Don'+"'"+'t recognize this activity? Please call Customer Care.'+'"'+'}]}';
       var infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infobip_msg_sender+ '","text":"Hi, your One Time Password is '+otp+' and will expire in 5 min. Do not share this with anyone. Don'+"'"+'t recognize this activity? Please call '+ host_name + getMessageIDText('MESSAGEID_154',req)+'"'+'}]}'; 
        mask_json_data(infobip_smsbody,log_prefix,log_suffix);
        //console.log(infobip_smsbody);
        const fetchOptions = {
          method: 'POST',

          body: infobip_smsbody,

          headers: {
            'Authorization': 'App ' + infobipAuth,  
            'Content-Type': 'application/json',
          },
          
        }

        let infobipSMSURL = infobipURL;  
        console.log(log_prefix + 'Request JSON to infobip server:' + infobipSMSURL + log_suffix);
        var smsTimeout = setTimeout(() => res.send('apiTimeout'), 30000);
        try {
           const response = await fetch(infobipSMSURL, fetchOptions,proxy_url);
           console.log(response.status);
          let jsonResponse = await response.json();
         // let jsonResponse = JSON.parse('{"messages":[{"messageId":"4071313962514335686996","status":{"description":"Message sent to next instance","groupId":1,"groupName":"PENDING","id":26,"name":"PENDING_ACCEPTED"},"to":"971*******11"}]}')
          console.log(log_prefix + 'Response JSON from infobip server:' + log_suffix);
          mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix);

         // console.log(jsonResponse);
          clearTimeout(smsTimeout);
         // console.log(JSON.stringify(jsonResponse));   
          
          if(response.status == 200)
          {
            console.log(jsonResponse.messages[0].status.name) ; 
          if (jsonResponse.messages[0].status.name == 'PENDING_ACCEPTED') {
            var timeStamp = getTimeStamp();
            console.log(hashValue + ',' + timeStamp);        
            var toencrypt = arr[0] + ',' + timeStamp + ',' + arr[1];
            var timeStampRefEncrypted = encrypt(toencrypt);
            console.log(log_prefix + hashValue + ',' + timeStampRefEncrypted + log_suffix);
            res.send(hashValue + ',' + timeStampRefEncrypted);
          }
          else {
            console.log(log_prefix + 'otpFailed not accpted' + log_suffix);
            res.send('otpFailed');
          }
        }
        else{
          console.log(log_prefix + 'otpFailed response code' + response.status  + log_suffix);
          res.send('otpFailed'); 
        }

          
        }
        catch (error) {
          console.log(error);
          clearTimeout(smsTimeout);
          console.log(log_prefix + 'exception' + log_suffix);
          res.send('exception');          
          return;
        }

      }

      } catch (error) {
        console.log(error);
        clearTimeout(smsTimeout);    
        res.send('exception');
       
     
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});

async function getUPCredentials(req) {

  let userIdHost = 'undefined';
  let userPaswdHost = 'undefined';
  let customer = 'undefined';                
  let host = (req.hostname.split('.'))[0];

  if (req.hostname.includes(DOMAIN_3)) {
    userIdHost = user_domain_3;
    userPaswdHost = password_domain_3;
    customer = customer_name_D3;  
  }
  else if(req.hostname.includes(DOMAIN_2))
  {
    userIdHost = user_domain_2;
    userPaswdHost = password_domain_2;
    customer = customer_name_D2;
    
  }
  else if (req.hostname.includes(DOMAIN_1)) {     

    userIdHost = user_domain_1;
    userPaswdHost = password_domain_1;
    customer = customer_name_D1;      
  }
  else if (req.hostname.includes(DOMAIN_0)) {     

    userIdHost = user_domain_0;
    userPaswdHost = password_domain_0;
    customer = customer_name_D0;      
  }
  else if (config[host]) {    
   if(config[host].user_domain)
      userIdHost = config[host].user_domain;
    
   if(config[host].password_domain) 
      userPaswdHost = config[host].password_domain;

   if(config[host].customer_name)
    customer = config[host].customer_name;      
  }
  if(userPaswdHost.length > 5) {
    if(userPaswdHost.substring(0,5) == '!PWD!')
    {
      userPaswdHost = decrypt_pwd(userPaswdHost.substring(5,userPaswdHost.length),PWD_SECRET_KEY,PWD_IV);
    }
  }

  let obj = {
    userIdHost: userIdHost,
    userPaswdHost: userPaswdHost,
    customer: customer
  }

  if(req.headers.referer.includes('/turkey')) {
      obj = {
    userIdHost: 'UPTest_Turkey_Endless',
    userPaswdHost: '29fb2f707c27c425',
    customer: customer
  }
  }

  return obj;

}


app.get('/sendSMS', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:sendSMS => clientip: ' + clientip);

  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        console.log(req.headers);
        const clientip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        console.log('clientip: ' + clientip);
        console.log('req.headers.host ==>> ' + req.headers.host);
        //var strData = req.query.data;
        let strData = Buffer.from(req.query.data,'base64').toString('utf8');
        console.log(strData);
        var arrData = strData.toString().split(",");
        let use_xml_interface = getXMLFlag(req.hostname);   

        //////////////////////
        let session_id = arrData[0];
        let host_log = req.hostname.split('.');
        let api = 'SEND_OTP';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ api +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';
        console.log(log_prefix + req.headers.campaign + '>>API_CALL:sendSMS => clientip: ' + clientip + log_suffix);
        //////////////////////

        let XML_TID = getDefaultTID(req.hostname,req);
         
    
          
        if((use_xml_interface == '0')||(arrData[2] == 'nodata')) {

         let str = Buffer.from(req.query.data,'base64').toString('utf8');
          console.log(str);
          var arr = str.toString().split(",");

 if (isTest) {
                        var timeStamp = getTimeStamp();
                        hashValue = '524342423423442423423'
                        console.log(hashValue + ',' + timeStamp);
                        var toencrypt = arr[0] + ',' + timeStamp + ',' + arr[1];
                        var timeStampRefEncrypted = encrypt(toencrypt);
                        console.log(log_prefix + hashValue + ',' + timeStampRefEncrypted + ',' + subscriberInfo + log_suffix);
                        res.send(hashValue + ',' + timeStampRefEncrypted + ',' + subscriberInfo);
                        return;
                      }

          var validationBody = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">' +
            '<soap:Header>' +
            '<ns2:SourceType xmlns:ns6="http://group.vodafone.com/schema/common/v1" xmlns:ns5="http://group.vodafone.com/contract/vfo/fault/v1" xmlns:ns4="http://www.w3.org/2005/08/addressing" xmlns:ns3="http://docs.oasis-open.org/wsrf/bf-2" xmlns:ns2="http://group.vodafone.com/contract/vho/header/v1">' +
            '<ns2:CountryCode>ZA</ns2:CountryCode>' +
            '<ns2:Operator>OnMobile</ns2:Operator>' +
            '<ns2:Division>IT</ns2:Division>' +
            '<ns2:System>OnMobile</ns2:System>' +
            '</ns2:SourceType>' +
            '<ns2:Correlation xmlns:ns6="http://group.vodafone.com/schema/common/v1" xmlns:ns5="http://group.vodafone.com/contract/vfo/fault/v1" xmlns:ns4="http://www.w3.org/2005/08/addressing" xmlns:ns3="http://docs.oasis-open.org/wsrf/bf-2" xmlns:ns2="http://group.vodafone.com/contract/vho/header/v1">' +
            '<ns2:ConversationID>' + arr[0] + '</ns2:ConversationID>' +
            '</ns2:Correlation>' +
            '</soap:Header>' +
            '<soap:Body>' +
            '<ns5:GetSubscriptionProfileListVBMRequest xmlns="http://group.vodafone.com/schema/common/v1" xmlns:ns2="urn:un:unece:uncefact:documentation:standard:CoreComponentType:2" xmlns:ns3="http://group.vodafone.com/schema/vbo/subscription/subscription-profile/v1" xmlns:ns4="http://group.vodafone.com/schema/extension/vbo/subscription/subscription-profile/v1" xmlns:ns5="http://group.vodafone.com/schema/vbm/subscription/subscription-profile/v1" xmlns:ns6="http://group.vodafone.com/schema/vbo/subscription/subscription/v1" xmlns:ns7="http://group.vodafone.com/schema/extension/vbo/subscription/subscription/v1" xmlns:ns8="http://docs.oasis-open.org/wsrf/bf-2" xmlns:ns9="http://www.w3.org/2005/08/addressing" xmlns:ns10="http://group.vodafone.com/contract/vfo/fault/v1" xmlns:ns11="http://group.vodafone.com/contract/vho/header/v1" xmlns:ns12="http://group.vodafone.com/schema/vbm/subscription/subscription/v1">' +
            '<Criteria>' +
            '<QueryExpression>' +
            '<ValueExpression QueryOperatorCode="EQUALS" Path="/SubscriptionProfileVBO/Parts/Subscription/MSISDN">' +
            '<Value>' + arr[1] + '</Value>' +
            '</ValueExpression>' +
            '<ValueExpression QueryOperatorCode="EQUALS" Path="/SubscriptionProfileVBO/Categories/Category">' +
            '<Value>Profile</Value>' +
            '</ValueExpression>' +
            '</QueryExpression>' +
            '</Criteria>' +
            '</ns5:GetSubscriptionProfileListVBMRequest>' +
            '</soap:Body>' +
            '</soap:Envelope>';

          const fetchOptions = {
            method: 'POST',

            body: validationBody,

            headers: {
              'Authorization': 'Basic ' + Auth_vodacom,
              'Content-Type': 'application/xml',
            },

	          
        
          }
          console.log(log_prefix + validationBody + log_suffix);
          console.log(log_prefix + 'vodacomValidationPhoneURL is going..' + vodacomValidationPhoneURL + log_suffix);
          var valResponseSent = 0;
          var valTimeout = setTimeout(() => { console.log('val time out'); valResponseSent = 1; res.send('apiTimeout');return}, 30000);
          try {
        
           let jsonResponse = '';
            const response = await fetch(vodacomValidationPhoneURL, fetchOptions,proxy_url);           
            jsonResponse = await response.text();
           
           
            console.log(log_prefix + jsonResponse + log_suffix);
            clearTimeout(valTimeout);
            if(jsonResponse.includes('<!DOCTYPE HTML PUBLIC'))
            {
              console.log('<!DOCTYPE HTML PUBLIC FOUND');
              if(jsonResponse.includes('404--Not Found')) 
              {
		              console.log(log_prefix + 'Voda_Service_Error: Validation Failed - URI not found!' + log_suffix);

                  res.send('Voda_Service_Error: Validation Failed - URI not found!');
                  return;
              }
              else if(jsonResponse.includes('401--Unauthorized')) {
                console.log(log_prefix + 'Voda_Service_Error: Validation Failed - 401 Unauthorized!'+ log_suffix);
                res.send('Voda_Service_Error: Validation Failed - 401 Unauthorized!');
                return;

              }
              else
              {
                console.log(log_prefix + 'Voda_Service_Error: Validation Failed!' + log_suffix);
                res.send('Voda_Service_Error: Validation Failed!');
                return;
              }
            }

            var resArr1 = jsonResponse.toString().split('<cmn:CharacteristicsValue characteristicName="ChargeToBillAuthorized"><cmn:Value>');

            var resArr2 = jsonResponse.toString().split('<cmn:CharacteristicsValue characteristicName="AccountStatus"><cmn:Value>');

            var subscriberInfo = '';

            var resSubsvbo = jsonResponse.toString().split('<vbo:Subscription>');
            if (resSubsvbo.length > 1) {
              var resSubs1 = resSubsvbo[1].toString().split('<cmn:Type>');
              if (resSubs1.length > 1) {
                var resSubs2 = resSubs1[1].toString().split('</cmn:Type>');
                subscriberInfo = resSubs2[0];

              }
            }

            if ((resArr1.length > 1) && (resArr2.length > 1)) {
              var resArr3 = resArr1[1].split('</cmn:Value>');
              var resArr4 = resArr2[1].split('</cmn:Value>');

              if ((resArr3.length > 0) && (resArr4.length > 0)) {

                if((resArr3[0] == 'true') && (resArr4[0] == 'active')) {

                  var x = Math.floor(100000 + Math.random() * 900000)
                  var y = x.toString().split('.');                 
                  var otp = y[0];

                  const hashValue = crypto.createHash('sha256', secret).update(otp).digest('hex');
                  console.log("Hash Obtained is: ", hashValue);

                  var timestamp = getTimeStamp();
                  console.log(timestamp);
                  var smsBody = getSMSBody(otp, arr[1], arr[2]);
                 

                  console.log(smsBody);
                  const fetchOptions = {
                    method: 'POST',

                    body: smsBody,

                    headers: {
                      'Authorization': 'Basic ' +  Auth_vodacom,

                      'Content-Type': 'application/xml',
                    },

		               
                  }
                  console.log(log_prefix + smsBody + log_suffix);
               
                  console.log(log_prefix +'vodacomSMSURL is going..'+ vodacomSMSURL + log_suffix);
                  

                  var smsTimeout = setTimeout(() => {console.log('send sms time out');res.send('apiTimeout')}, 30000);
                  try {
            

                  let jsonResponse = '';
                     const response = await fetch(vodacomSMSURL, fetchOptions,proxy_url);           
                    jsonResponse = await response.text();
                   
                   
                    console.log(log_prefix + 'RESPONSE:: '+jsonResponse + log_suffix);
                    clearTimeout(smsTimeout);
               

                    if(jsonResponse.includes('<!DOCTYPE HTML PUBLIC'))
                    {
                      if(jsonResponse.includes('404--Not Found')) 
                      {
                          console.log(log_prefix + 'Voda_Service_Error: SMS Send Failed - URI not found!' + log_suffix);
                          res.send('Voda_Service_Error: SMS Send Failed - URI not found!');
                          return;
                      }
                      else if(jsonResponse.includes('401--Unauthorized')) {
                        console.log(log_prefix + 'Voda_Service_Error: SMS Send Failed - 401 Unauthorized!' + log_suffix);
                        res.send('Voda_Service_Error: SMS Send Failed - 401 Unauthorized!');
                        return;

                      }
                      else
                      {
                        console.log(log_prefix + 'Voda_Service_Error: SMS Send failed!' + log_suffix);
                        res.send('Voda_Service_Error: SMS Send failed!');
                        return;
                      }
                    }

                    var resArr1 = jsonResponse.toString().split('<loc:result>');

                    if (resArr1.length > 1) {

                      var resArr2 = resArr1[1].split('</loc:result>');

                      if (resArr2.length > 0) {
                        var timeStamp = getTimeStamp();
                        console.log(hashValue + ',' + timeStamp);
                        var toencrypt = arr[0] + ',' + timeStamp + ',' + arr[1];
                        var timeStampRefEncrypted = encrypt(toencrypt);
                        console.log(log_prefix + hashValue + ',' + timeStampRefEncrypted + ',' + subscriberInfo + log_suffix);
                        res.send(hashValue + ',' + timeStampRefEncrypted + ',' + subscriberInfo);
                      }
                      else {
                        console.log(log_prefix + 'OTP Failed' + log_suffix);
                        res.send('otpFailed');
                      }

                    }
                    else {
                      console.log(log_prefix + 'OTP Failed' + log_suffix);
                      res.send('otpFailed');

                    }
                  }
                  catch (error) {
                    console.log(error);
                    let response = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
                    console.log(log_prefix + response + log_suffix);
                    res.send(response);
                    return;
                  }



                }
                else if ((resArr3[0] == 'false')) {
                  console.log(log_prefix + 'chargeToBillFalse' + log_suffix);

                  res.send('chargeToBillFalse');
                }
                else {
                  console.log(log_prefix +'OTP Failed'  + log_suffix);
                  res.send('otpFailed');

                }
              }
              else {
                console.log(log_prefix +'Validation Failed'  + log_suffix);
                res.send('valFailed');
              }
           }
            else {
              console.log(log_prefix +'Validation Failed'  + log_suffix);
              res.send('valFailed');
            }
          }
          catch (error) {
            console.log(error);
            console.log('certificate error');
            clearTimeout(valTimeout);
            console.log(log_prefix +'exception'  + log_suffix);
            res.send('exception');
            return;
          }
        }
        else if(use_xml_interface == '1') {
          
          let str = Buffer.from(req.query.data,'base64').toString('utf8');
          console.log(str);
          var arr = str.toString().split(",");
          let str_amount = arr[2];

		          console.log('Ident Parse 1');
              var bodyVal = '<COMMAND>' +
                '<FUNKTION>2</FUNKTION>' +
                '<TERMINAL-ID>'+XML_TID+'</TERMINAL-ID>' +
                '<USERLOGIN>'+user_xml+'</USERLOGIN>' +
                '<PASSWORD>'+password_xml+'</PASSWORD>' +
                // '<IDENT>' + sessionIdent + '</IDENT>' +
                '<PAN>' + arr[1] + '</PAN>' +
                '<CARDTYPE>2643</CARDTYPE>' +
                '<BETRAG>' + str_amount + '</BETRAG>' +
                '<VALUTA>710</VALUTA>' +                
                '</COMMAND>';
              console.log(log_prefix + bodyVal + log_suffix);
              const fetchOptionsVal = {
                method: 'POST',

                body: bodyVal,

                headers: {
                  'Destination': 'cwxmlgate'
                },

              }
 	            console.log(fetchOptionsVal);

              var valResponseSent = 0;
              var valTimeout = setTimeout(() => { console.log(log_prefix +'val time out' + log_suffix); valResponseSent = 1; res.send('apiTimeout'); return }, 30000);
              try {
                const responseVal = await fetch(XMLInterfaceURL, fetchOptionsVal,proxy_url);
                const xmlResponseVal = await responseVal.text();
                
                clearTimeout(valTimeout);
                console.log(log_prefix + xmlResponseVal + log_suffix);
                var parseString = require('xml2js').parseString;
                var respCode = '';
                var active = '';
                var chargeToBill = '';
                var subscriptionInfo = '';
                parseString(xmlResponseVal, function (err, result) {
                  console.log(result.ANSWER);
                  console.log(result.ANSWER.EXTRADATA[0]);
                  console.log(result.ANSWER.EXTRADATA[0]['SubscriptionProfile:status'][0]);
                  console.log(result.ANSWER.EXTRADATA[0]['cmn:Specification'][0]['cmn:CharacteristicsValue'][0]['cmn:Value'][0]);
                  console.log(result.ANSWER.EXTRADATA[0]['cmn:Specification'][0]['cmn:CharacteristicsValue'][1]['cmn:Value'][0]);
                  respCode = result.ANSWER.FEHLERCODE;
                  active = result.ANSWER.EXTRADATA[0]['cmn:Specification'][0]['cmn:CharacteristicsValue'][0]['cmn:Value'][0];
                  chargeToBill = result.ANSWER.EXTRADATA[0]['cmn:Specification'][0]['cmn:CharacteristicsValue'][1]['cmn:Value'][0];
                  subscriptionInfo = result.ANSWER.EXTRADATA[0]['SubscriptionProfile:type'];
                });
               
                if ((respCode == '0000') && (active == 'active') && (chargeToBill == 'true')) {

                  var bodyIdent = '<COMMAND>' +
                  '<FUNKTION>52</FUNKTION>' +
                  '<TERMINAL-ID>'+XML_TID+'</TERMINAL-ID>' +
                  '<USERLOGIN>'+user_xml+'</USERLOGIN>' +
                  '<PASSWORD>'+password_xml+'</PASSWORD>' +
                  '<ACTION>CREATE</ACTION>' +
                  '<PAYMODE>direct</PAYMODE>' +
                  '<CURRENCY>ZAR</CURRENCY>' +
                  '<USTREF>PING</USTREF>' +
                  '</COMMAND>';
               
      
                console.log(log_prefix + bodyIdent + log_suffix);
      
                const fetchOptionsIdent = {
                  method: 'POST',
      
                  body: bodyIdent,
      
                  headers: {
      
                    'Destination': 'cwxmlgate',
                  },
      
                }
           
                console.log(log_prefix + 'XML Ident Request: ' + XMLInterfaceURL + log_suffix);
                var valIdentResponseSent = 0;
                var identTimeout = setTimeout(() => { console.log(log_prefix + 'ident time out' + log_suffix); valIdentResponseSent = 1; res.send('apiTimeout') }, 30000);
                try {
                 const responseIdent = await fetch(XMLInterfaceURL, fetchOptionsIdent,proxy_url);
                 const xmlResponseIdent = await responseIdent.text();
                 
                  clearTimeout(identTimeout);
                  console.log(log_prefix + xmlResponseIdent + log_suffix);
                  if (xmlResponseIdent.includes('<FEHLERCODE>0000</FEHLERCODE>')) {
                    console.log('Ident OK');
      
                    var parseString = require('xml2js').parseString;
                    console.log('Ident Parse 1');
                    var sessionIdent = '';
                    parseString(xmlResponseIdent, function (err, result) {
                      console.log(result.ANSWER);
                      console.log(result.ANSWER.IDENT);
                      sessionIdent = result.ANSWER.IDENT;
                    });
             
                  console.log(str_amount);
                  var strAmountInDecimal = str_amount.substring(0, (str_amount.length - 2)) + "." + str_amount.substring((str_amount.length - 2), str_amount.length);
                  console.log(strAmountInDecimal);
                  var bodysms = '<COMMAND>' +
                    '<FUNKTION>2</FUNKTION>' +
                    '<TERMINAL-ID>'+XML_TID+'</TERMINAL-ID>' +
                    '<USERLOGIN>'+user_xml+'</USERLOGIN>' +
                    '<PASSWORD>'+password_xml+'</PASSWORD>' +
                    '<IDENT>' + sessionIdent + '</IDENT>' +
                    '<PAN>' + arr[1] + '</PAN>' +
                    '<CARDTYPE>2643</CARDTYPE>' + 
                    '<BETRAG>' + str_amount + '</BETRAG>' +
                    '<VALUTA>710</VALUTA>' +
                    '<EXTRADATA>SENDOTP=TRUE</EXTRADATA>' +
                    '</COMMAND>';                  
                    console.log(log_prefix + bodysms + log_suffix);
                  const fetchOptionsSendSMS = {
                    method: 'POST',

                    body: bodysms,

                    headers: {
        
                      'Destination': 'cwxmlgate'
                    },
         
                  }
                  console.log(fetchOptionsSendSMS);
                  console.log(log_prefix + 'XML URL: ' + XMLInterfaceURL + log_suffix);
                  var responseSMSSent = 0;
                  var valTimeoutSMS = setTimeout(() => { console.log( log_prefix + 'SMS time out' + log_suffix); responseSMSSent = 1; res.send('apiTimeout'); return }, 30000);

                  try {
                   const responseSMS = await fetch(XMLInterfaceURL, fetchOptionsSendSMS,proxy_url);
                   const xmlResponseSMS = await responseSMS.text();
                    clearTimeout(valTimeoutSMS);
                    console.log('send started...00');
                    console.log(log_prefix + xmlResponseSMS + log_suffix);
                    console.log('send started...0');
                    if (xmlResponseSMS.includes('<FEHLERCODE>0000</FEHLERCODE>')) {
                      console.log('send started...');
                      var timeStamp = getTimeStamp();
                      console.log(sessionIdent + ',' + timeStamp);
                      // var toencrypt = arr[0] + ',' + timeStamp; @@ident
                      var toencrypt = arr[0] + ',' + timeStamp + ',' + sessionIdent;
                      var timeStampRefEncrypted = encrypt(toencrypt);
                      console.log(sessionIdent + ',' + timeStampRefEncrypted + ',' + subscriptionInfo);
                      // res.send(sessionIdent + ',' + timeStampRefEncrypted + ',' + subscriptionInfo); @@ident
                      console.log(log_prefix + subscriptionInfo + ',' + timeStampRefEncrypted + ',' + subscriptionInfo + log_suffix);
                      res.send(subscriptionInfo + ',' + timeStampRefEncrypted + ',' + subscriptionInfo);
                    }
                    else {
                      //Send error text from response
                      console.log(log_prefix + 'OTP Failed' + log_suffix);
                      res.send('otpFailed');
                    }

                  } catch (err) {
                    // Send failed response
                    console.log(log_prefix + 'OTP Failed' + log_suffix);
                    res.send('otpFailed');
                  }

                }
                else {
                   //Generate Indent Failed
                    console.log(log_prefix + 'Generate Indent Failed' + log_suffix);
                    res.send('genIndentFailed');
                }

              }
              catch (err) {
                console.log(log_prefix + 'Generate Indent Failed' + log_suffix);
                res.send('genIndentFailed');
              }

                }
                else {            
                //val failed 
                if (chargeToBill == 'false') {
                    console.log(log_prefix + 'chargeToBillFalse' + log_suffix);
                    res.send('chargeToBillFalse');
                }
                else
                {
                    console.log(log_prefix + 'Validation Failed' + log_suffix);
                    res.send('valFailed');
                }
            }

          } catch (err) {            

            console.log(log_prefix + 'Validation Failed' + log_suffix);
            res.send('valFailed');

          }
        }
        else if(use_xml_interface == '2') {
          try {
          let str = Buffer.from(req.query.data,'base64').toString('utf8');
          console.log(str);
          var arr = str.toString().split(",");
          let str_amount = arr[2];
          let txidn = getTimeStamp();
          txidn = 'EPAY-'+(parseInt(txidn)).toString(16).toUpperCase() + '-' + arr[1].substring(arr[1].length-9,arr[1].length);
		          console.log('Ident Parse 1');
              let up_cred  = await getUPCredentials(req); 
                           
              var bodyVal = '<REQUEST TYPE="ALTPAY" MODE="RESERVE" VERSION="3" STORERECEIPT="1">' +           
                
                '<AUTHORIZATION>' +
                '<USERNAME>'+up_cred.userIdHost+'</USERNAME>' +
                '<PASSWORD>'+up_cred.userPaswdHost+'</PASSWORD>' +
                '</AUTHORIZATION>' +
                '<TERMINALID>'+XML_TID+'</TERMINALID>' +
                '<TXID>'+ txidn +'</TXID>' +
                '<AMOUNT>' + str_amount + '</AMOUNT>' +
                '<CURRENCY>710</CURRENCY>' + 
                '<CARD>'  +
                '<PAN>' + arr[1] + '</PAN>' +
                '</CARD>'  +
               // '<CARDTYPE>2643</CARDTYPE>' +   
                '<EXTRADATA>'  +
                '<DATA name="CARDTYPE">2643</DATA>' +
                '</EXTRADATA>'  +

                               
                '</REQUEST>';
              console.log(log_prefix + bodyVal + log_suffix);
              const fetchOptionsVal = {
                method: 'POST',

                body: bodyVal                

              }
 	            console.log(fetchOptionsVal);
              
              var valResponseSent = 0;
              var valTimeout = setTimeout(() => { console.log(log_prefix +'val time out' + log_suffix); valResponseSent = 1; res.send('apiTimeout'); return }, 30000);
              let ALTPayInterfaceURL = UPInterfaceURL;
              console.log(fetchOptionsVal);
               console.log(log_prefix + 'UP ALTPay URL: ' + ALTPayInterfaceURL + log_suffix);
                const responseVal = await fetch(ALTPayInterfaceURL, fetchOptionsVal,proxy_url);
                const xmlResponseVal = await responseVal.text();
                
                clearTimeout(valTimeout);
                console.log(log_prefix + xmlResponseVal + log_suffix);
                
               
                if ((xmlResponseVal.includes('<RESULT>0</RESULT>')) 
                      && (xmlResponseVal.includes('<DATA name="cmn:Characteristic_1_Value_0">active</DATA>')) 
                      && (xmlResponseVal.includes('<DATA name="cmn:Characteristic_2_Value_0">true</DATA>'))) {                  
                
                  console.log(str_amount);
                  var strAmountInDecimal = str_amount.substring(0, (str_amount.length - 2)) + "." + str_amount.substring((str_amount.length - 2), str_amount.length);
                  console.log(strAmountInDecimal);

                  let up_cred  = await getUPCredentials(req); 
                 

                  var bodysms = '<REQUEST TYPE="ALTPAY" MODE="RESERVE" VERSION="3" STORERECEIPT="1">' +           
                
                '<AUTHORIZATION>' +
                '<USERNAME>'+up_cred.userIdHost+'</USERNAME>' +
                '<PASSWORD>'+up_cred.userPaswdHost+'</PASSWORD>' + 
                '</AUTHORIZATION>' +
                '<TERMINALID>'+XML_TID+'</TERMINALID>' +
                '<TXID>'+ txidn + '_OTP' +'</TXID>' +
                '<AMOUNT>' + str_amount + '</AMOUNT>' +
                '<CURRENCY>710</CURRENCY>' + 
                '<CARD>'  +
                '<PAN>' + arr[1] + '</PAN>' +
                '</CARD>'  +
                '<EXTRADATA>'  +
                '<DATA name="CARDTYPE">2643</DATA>' +
                '<DATA name="SENDOTP">TRUE</DATA>' +
                '</EXTRADATA>'  +                             
                               
                '</REQUEST>';
                           
                  console.log(log_prefix + bodysms + log_suffix);
                  const fetchOptionsSendSMS = {
                    method: 'POST',

                    body: bodysms

                   
         
                  }
                  console.log(fetchOptionsSendSMS);
                  console.log(log_prefix + 'XML URL: ' + ALTPayInterfaceURL + log_suffix);
                  var responseSMSSent = 0;
                  var valTimeoutSMS = setTimeout(() => { console.log( log_prefix + 'SMS time out' + log_suffix); responseSMSSent = 1; res.send('apiTimeout'); return }, 30000);

                  try {
                   const responseSMS = await fetch(ALTPayInterfaceURL, fetchOptionsSendSMS,proxy_url);
                   const xmlResponseSMS = await responseSMS.text();
                    clearTimeout(valTimeoutSMS);
                    console.log('send started...00');
                    console.log(log_prefix + xmlResponseSMS + log_suffix);
                    console.log('send started...0');
                    if (xmlResponseSMS.includes('<RESULT>0</RESULT>')) {
                      console.log('send started...');
                      var timeStamp = getTimeStamp();
                     // let sessionIdentUP = '';
                     let sessionIdentUP = '';

                  if(xmlResponseSMS.includes('<DATA name="TRACE">')) {
                     let a = xmlResponseSMS.split('<DATA name="TRACE">');
                     let b = a[1].split('</DATA>');
                     sessionIdentUP = b[0];
 
                  }
                      let subscriptionInfoUP = 'Contract';
                      if(xmlResponseVal.includes('<DATA name="SubscriptionProfile:type">')){
                        let a = xmlResponseVal.split('<DATA name="SubscriptionProfile:type">');
                        let b = a[1].split('</DATA>');
                        subscriptionInfoUP = b[0];
                      }
                      console.log(sessionIdentUP + ',' + timeStamp);
                      // var toencrypt = arr[0] + ',' + timeStamp; @@ident
                      var toencrypt = arr[0] + ',' + timeStamp + ',' + sessionIdentUP;
                      var timeStampRefEncrypted = encrypt(toencrypt);
                      console.log(sessionIdentUP + ',' + timeStampRefEncrypted + ',' + subscriptionInfoUP);
                      // res.send(sessionIdent + ',' + timeStampRefEncrypted + ',' + subscriptionInfo); @@ident
                      console.log(log_prefix + sessionIdentUP + ',' + timeStampRefEncrypted + ',' + subscriptionInfoUP + log_suffix);
                      res.send(sessionIdentUP + ',' + timeStampRefEncrypted + ',' + subscriptionInfoUP);
                    }
                    else {
                      //Send error text from response
                      console.log(log_prefix + 'OTP Failed' + log_suffix);
                      res.send('otpFailed');
                    }

                  } catch (err) {
                    // Send failed response
                    console.log(log_prefix + 'OTP Failed' + log_suffix);
                    res.send('otpFailed');
                  }

                }
                else {            
                  //val failed 
                  if (xmlResponseVal.includes('<DATA name="cmn:Characteristic_2_Value_0">false</DATA>')) {
                      console.log(log_prefix + 'chargeToBillFalse' + log_suffix);
                      res.send('chargeToBillFalse');
                  }
                  else
                  {
                      console.log(log_prefix + 'Validation Failed' + log_suffix);
                      res.send('valFailed');
                  }
              }         

                
              
                

          } catch (err) {            

            console.log(log_prefix + 'Validation Failed' + log_suffix);
            res.send('valFailed');

          }
        }
      } catch (error) {
        console.log(error);
        let response = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>';
        //console.log(log_prefix + response + log_suffix);
        res.send(response);
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});



function getUnsubscribeBody_ib(phone, subscriptionID, product, reference) {
  var smstext = 'Hi, you have successfully unsubscribed from ' + product + '. Reference number: ' +  reference + '. For any further queries call Customer Care on 082135, FREE from any Vodacom cell phone number. Vodacom';
  var infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+infobip_msg_sender+ '","text":"' + smstext + '"}]}';

  return infobip_smsbody;

}

function getUnsubscribeBody(phone, subscriptionID, product, reference) {
  var smstext = 'Hi, you have successfully unsubscribed from ' + product + '. Reference number: ' +  reference + '. For any further queries call Customer Care on 082135, FREE from any Vodacom cell phone number. Vodacom';
  var smsBody = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
    '<soap:Header xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">' +
    '<oas:Security soap:mustUnderstand="1" xmlns:oas="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' +
    '<oas:UsernameToken oas1:Id="UsernameToken-1" xmlns:oas1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' +
    '<oas:Username>'+ username_voda_service + '</oas:Username>' +
    '<oas:Password>'+ password_voda_service + '</oas:Password>' +
    '</oas:UsernameToken>' +
    '</oas:Security>' +
    '</soap:Header>' +
    '<soapenv:Body>' +
    '<loc:sendSms xmlns:loc="http://www.csapi.org/schema/parlayx/sms/send/v2_2/local">' +
    '<loc:addresses>tel:' + phone + '</loc:addresses>' +
   // '<ns12:addresses>tel:27660000000000</ns12:addresses>' +
    '<loc:senderName>'+ senderName_voda_service + '</loc:senderName>' +
    '<loc:message>' + smstext + '</loc:message>' +
    '</loc:sendSms>' +
    '</soapenv:Body>' +
    '</soapenv:Envelope>';

  return smsBody;


}

app.get('/getUnsubscribe', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getUnsubscribe => clientip: ' + clientip);
  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        //var str = req.query.param;
        let str = Buffer.from(req.query.param,'base64').toString('utf8');
        //console.log(str);
        console.log(str);
        var arr = str.toString().split(",");

        let session_id = arr[6];
        let host_log = req.hostname.split('.');
        let method = 'GET_UNSUBSCRIBE';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';
        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getUnsubscribe => clientip: ' + clientip + log_suffix);
        var timeCurr = getTimeStamp();
        var decryptedString = decrypt(arr[5]);
        var tmA = decryptedString.split(',');
        if (tmA.length > 0) {

          {
            console.log(timeCurr + '::' + tmA[1]);
            if (Number(await date_difference(timeCurr,tmA[1])) > 300) {
              res.send('timeout');
            }
            else {
              const hashValue = crypto.createHash('sha256', secret).update(arr[3]).digest('hex');
              //if(hashValue == arr[4]) {
              if((hashValue == arr[4])||(otpTest && (arr[3] == otpTest))) {

                let up_cred = await getUPCredentials(req);

                let userIdHost = up_cred.userIdHost;
                let userPaswdHost = up_cred.userPaswdHost;

                let customer = up_cred.customer;

                

                let tid = getDefaultTID(req.hostname,req);
                let tidhead = '<TERMINALID>' + tid + '</TERMINALID>';
              
		             let contract_id = arr[6];
                

                let txid = getTimeStamp();
                let x = Math.random() * 1000000;
                console.log(x);
                let y = x.toString().split('.');
                console.log(y[0]);
                txid = txid + y[0];
                console.log(txid);
                let tid_prefix = '';
                 if(contract_id.includes('-'))
                 {
                    let con_a = contract_id.split('-');
                    let sub_con = con_a[1] ? con_a[1] : '';
                    if(sub_con.length == 20)
                    {
                        tid = sub_con.substring(0,8);
                        tid_prefix = tid;
                    }
                    let sub_ph = con_a[2] ? con_a[2] : '';
                    if(sub_ph.length > 0)
                    {
                        txid = sub_ph;
                    }
                 }

                 let inforef = 'EPAY-' + tid_prefix + (parseInt(getTimeStamp())).toString(16).toUpperCase() + '-' + txid;
                 tidhead = '<TERMINALID>' + tid + '</TERMINALID>';

                const fetchOptions = {
                  method: 'POST',

                  body: '<REQUEST TYPE="SUBSCRIPTION" MODE="UNSUBSCRIBE">' +
                    '<USERNAME>' + userIdHost + '</USERNAME>' +
                    '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                    '<LOCALDATETIME>' + arr[0] + '</LOCALDATETIME>' +
                    '<TXID>' + inforef  + '</TXID>' +
                    tidhead +                     
                    '<SUBSCRIPTION>' +
                    '<SUBSCRIPTIONID>' + arr[6] + '</SUBSCRIPTIONID>' +
                    '</SUBSCRIPTION>' +
                    '<RECEIPT><CHARSPERLINE>40</CHARSPERLINE></RECEIPT>' +


                    '</REQUEST>',

                  headers: {
                    'Content-Type': 'application/xml',
                  },
                
                }
                console.log(log_prefix + 'UNSUBSCRIBE REQUEST: ' + UPInterfaceURL + log_suffix);
                mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
                var unsubscribeTimeout = setTimeout(() => res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_138',req)+'</RESULTTEXT></RESPONSE>'), 30000);

                try {
                  const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
                  let jsonResponse = await response.text();
                  clearTimeout(unsubscribeTimeout);

                  let jsonResponse_log = jsonResponse;
          	  jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
                  mask_xml_data(log_prefix + jsonResponse_log + log_suffix);

              

                  if (jsonResponse.includes('<RESULT>0</RESULT>')) {

                   if(!((await checkIfVodacomFlow(req.hostname)) == 'yes'))
                    {
                      var infobip_smsbody = getUnsubscribeBody_ib(arr[7], arr[6], arr[8], inforef.split('-')[0]);
                      console.log(log_prefix + 'Infobip SMS: ' + infobipSMSURL + log_suffix );
		                  mask_json_data(infobip_smsbody,log_prefix,log_suffix);
                      const fetchOptions = {
                        method: 'POST',

                        body: infobip_smsbody,

                        headers: {
                          'Authorization': 'App ' + infobipAuth,  
                          'Content-Type': 'application/json',
                        },
                        
                      }

                      let infobipSMSURL = infobipURL;  

                      var smsTimeout = setTimeout(() => console.log('SMS send time out'), 30000);
                      try {
                        const response = await fetch(infobipSMSURL, fetchOptions,proxy_url);
                        console.log(response.status);
                        let jsonResponse = await response.json();

                       
                        clearTimeout(smsTimeout);
                        
                        mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix);
 
                      } catch(error) {
                        console.log(error);
                      }

                    }
                    else{
                  
                    var smsBody = getUnsubscribeBody(arr[7], arr[6], arr[8], inforef.split('-')[1]);
                    console.log(smsBody);
                    const fetchOptionsCustomer = {
                      method: 'POST',

                      body: smsBody,

                      headers: {
                        'Authorization': 'Basic ' + Auth_vodacom,
                        'Content-Type': 'application/xml',
                      },
                      
                    }
                    const responseCus = await fetch(vodacomSMSURL, fetchOptionsCustomer,proxy_url);
                    const jsonResponseCus = await responseCus.text();

                    console.log('SMS Response');
                    console.log(log_prefix + jsonResponseCus + log_suffix);
                
		                }

                  }

                  jsonResponse = jsonResponse.replace('</RESPONSE>','<CUSTOMER>' + customer + '</CUSTOMER></RESPONSE>');
                  res.send(jsonResponse);
                } catch (error) {
                  console.log(error);
                  let customer = await getCustomerName(req.hostname);
                  let support_url = await getDomainSupportUrl(req.hostname);

                  let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_107',req) + getMessageIDText('MESSAGEID_148',req)+ customer + getMessageIDText('MESSAGEID_103',req)+ support_url + '</RESULTTEXT></RESPONSE>';;
                  

                  
                  res.send(str);
                }
              }

            }


          }


        }
        else {

          res.send('unauthorized');
        }

      } catch (error) {
        console.log(error);
        let customer = await getCustomerName(req.hostname);
        let support_url = await getDomainSupportUrl(req.hostname);
        let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_107',req) + getMessageIDText('MESSAGEID_148',req)+ customer + getMessageIDText('MESSAGEID_103',req)+ support_url + '</RESULTTEXT></RESPONSE>';;
        res.send(str);
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
});


function getVodaChargeBody(phone, serviceid, amount, reference) {

  var chargeBody = '<er-request id="100007" client-application-id="'+ client_application_id_voda_service +'" purchase_locale="en_ZA" language_locale="en_ZA">' +
    '<payload>' +
    '<usage-auth-rate-charge>' +
    '<msisdn>' + phone + '</msisdn>' +
    '<service-id>' + serviceid + '</service-id>' +
    '<usage-attributes>' +
    '<force-purchase>true</force-purchase>' +
    '</usage-attributes>' +
    '<rating-attributes>' +
    '<pre-rate>' + amount + '</pre-rate>' +
    '<pre-rate-price-is-gross>true</pre-rate-price-is-gross>' +
    '<external-trans-id>' + reference + '</external-trans-id>' +
    '<partner-id>' + partner_id_voda_service + '</partner-id>' +
    '<content-name>' + content_name_voda_service +'</content-name>' +
    '</rating-attributes>' +
    '</usage-auth-rate-charge>' +
    '</payload>' +
    '</er-request>';



  return chargeBody;

}

function getXMLFlag (hostname){
    let host = (hostname.split('.'))[0];
    let use_xml_interface = '0'

    if(hostname == DOMAIN_1)
    {
        use_xml_interface = use_domain_1_xml_interface;
    }
    else if(hostname == DOMAIN_3)
    {
        use_xml_interface = use_domain_3_xml_interface;
    }
    else if(hostname == DOMAIN_2)
    {
        use_xml_interface = use_domain_2_xml_interface;
    }
    else if((hostname == DOMAIN_0))
    {
        use_xml_interface = use_domain_0_xml_interface;
    } else if(config[host]) {
      if(config[host].use_xml_interface) {
        use_xml_interface = config[host].use_xml_interface;
      }
    }

    return use_xml_interface;

}

async function updateRedeemptionURL(response) {

  let jsonResponse = response;

  if(jsonResponse.includes('<DATA name="ProductDownloadUrl">')) {
                                
    if(!jsonResponse.includes('<DATA name="REDEMPTIONURL">')) {
      jsonResponse = jsonResponse.replace('<DATA name="ProductDownloadUrl">','<DATA name="REDEMPTIONURL">');
      console.log('ProductDownloadUrl ==>> REDEMPTIONURL');
    } else {
      console.log('SALE RESPONSE ALREADY HAVE REDEMPTIONURL!');
      jsonResponse = jsonResponse.replace('<DATA name="REDEMPTIONURL">','<DATA name="REDEMPTIONURLOLD">');
      jsonResponse = jsonResponse.replace('<DATA name="ProductDownloadUrl">','<DATA name="REDEMPTIONURL">');
    }
    
  }

  return jsonResponse;
  
}


app.get('/getPIN', cors(corsOptions), limiter_amount_mismatch_domain_3, async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getPIN => clientip: ' + clientip);


  if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {
        //var str = req.query.data;
        var str = Buffer.from(req.query.data,'base64').toString('utf8');        
        console.log(str);
        var arr = str.toString().split(",");
        let cashier = arr[16];
        ////////////HARD STOP DISCOUNT PROMO FOR SECURITY///////////////
        
        arr[17] = '0' //discount
        arr[18] = '0'; //promoApplied
        arr[19] = ''; //promoCode
        arr[20] = arr[8]; //partialPay
        
        ////////////////////////////////////////////////////////////////
        
        let session_id = '';
        {
          var txid = getTimeStamp();
          var x = Math.random() * 1000000000;    
          var y = x.toString().split('.');  
          session_id = 'EPAY-'+(parseInt(txid)).toString(16).toUpperCase() + '-' + y[0];
        }        
        let host_log = req.hostname.split('.');
        let api = 'GET_PIN';
        let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ api +'</METHOD><LOG>\n';
        let log_suffix = '\n</LOG></SESSION_LOG>';
        console.log(log_prefix + req.headers.campaign + '>>API_CALL:getPIN => clientip: ' + clientip + log_suffix);
        console.log(log_prefix + str + log_suffix);
        ////////////////////////////////////////////////

        var timeCurr = getTimeStamp();
        var decryptedString = decrypt(arr[7]);
        var tmA = decryptedString.split(',');
        var timeoutValToCompare = 120+180;
        let use_xml_interface = getXMLFlag(req.hostname);
        
        if ((use_xml_interface == '1')||(use_xml_interface == '2')) {
          timeoutValToCompare = 300;
        }
        if (tmA.length > 0) {
          if (arr[2] == tmA[0]) {
            console.log(timeCurr + '::' + tmA[1]);
          
            if (Number(await date_difference(timeCurr,tmA[1])) > timeoutValToCompare)
            {
              console.log(log_prefix + 'Sesion Timeout' + log_suffix);
              res.send('timeout');
            }
            else {
                
//((use_xml_interface == '0')||(route.params.promofull == true))
              if (use_xml_interface == '0') {
                const hashValue = crypto.createHash('sha256', secret).update(arr[5]).digest('hex');
                //if(hashValue == arr[6]) {
                 if((hashValue == arr[6])||(otpTest && (arr[5] == otpTest))) {
                  currentDate = getFormattedTime();
                  var txid = getTimeStamp();

                  var x = Math.random() * 1000000;
                  console.log(x);
                  var y = x.toString().split('.');
                  console.log(y[0]);
                  txid = txid + y[0];
                  console.log(txid);

                  var tidhead = '';
                  
             
                  let gtid_t = arr[1];
                  tidhead = '<TERMINALID>'+ arr[1] +'</TERMINALID>';
                  
                  if((arr[1] == '') || (arr[1] == 'undefined') || (arr[1] == 'notid'))
                  {
                    gtid_t = getDefaultTID(req.hostname,req);
                    tidhead = '<TERMINALID>'+ gtid_t +'</TERMINALID>';
                  }

                  let up_cred = await getUPCredentials(req);

                  userIdHost = up_cred.userIdHost;
                  userPaswdHost = up_cred.userPaswdHost;

                    
                    let eantofind = arr[3];
                    let product_variable = false;
                    let amount = await getAmountEAN(gtid_t,eantofind,log_prefix,log_suffix,req.hostname,clientip,req);
                    if(amount != 'none') {
                    let reslt = await checkIfVariableProductAndInRange(arr[8],eantofind,gtid_t,log_prefix,log_suffix,req);
                    if(reslt == 2){
                      amount = arr[8];
                      product_variable = true;
                    } else if(reslt == 1){
                      //Security error block ip
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid_t + ' Reason: GET_PIN Variable product range check failed'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      let resp = '<RESPONSE>' +'<RESULT>161</RESULT>' +'<RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>' + '<HOME>https://' + req.hostname + '</HOME>' + '<EAN>' + eantofind +'</EAN>' + '</RESPONSE>';
                      res.send(resp);
                      return;
                    } else if(reslt == -1){
                      //Security error block ip
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid_t + ' Reason: GET_PIN product not in catalog'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      let resp = '<RESPONSE>' +'<RESULT>162</RESULT>' +'<RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>' + '<HOME>https://' + req.hostname + '</HOME>' + '<EAN>' + eantofind +'</EAN>' + '</RESPONSE>';
                      res.send(resp);
                      return;
                    }
                    

                    let currencycode = 'AED';                    
                    let country_code = await getCountryCode(req.hostname);
                    if(country_code == 'ZA') {
                      currencycode = 'ZAR';
                    } else if(country_code == 'TR') {
                      currencycode = 'TRY';
                    } else if(country_code == 'SA') {
                      currencycode = 'SAR';
                    }
                    var getSymbolFromCurrency = require('currency-symbol-map');
                    var symbol = getSymbolFromCurrency(currencycode);
                    if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
                      symbol = '\u{2800}';
                    }
                    let str1 = symbol + amount.substring(0, (amount.length - 2)) + "." + amount.substring((amount.length - 2), amount.length);
                    console.log(log_prefix + 'Amount from Catalog: ' + amount + log_suffix);
                    console.log(log_prefix + 'Amount from Catalog: ' + str1 + log_suffix);
                    console.log(log_prefix + 'Currency from Catalog: ' +currencycode + log_suffix);
                    ///////////////////////////////////////////////////////////////////////////////////////////////////

                    var str = arr[8];
                    let discount = arr[17];
                    let amtcmp = (Number(str)+Number(discount)).toString();
                    let product_type = arr[15];
                    let activation_serial = arr[21];
                    let prod_type_sale = arr[22];
                    let currency_code = arr[23];
                    
               
                    if (amtcmp != amount) {
                      res.statusCode = 451;
                      console.log(log_prefix + 'Amount mismatch' + log_suffix);
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid_t + ' Reason: GET_PIN Amount mismatch'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      res.send('Amount mismatch');
                      return;

                    }
                    else {

                     //Add charge promo
                     let promoCode = arr[19];
                     let a1 = tidhead.split('<TERMINALID>')
                     let a2 = a1[1].split('</TERMINALID>');
                     let tid = a2[0];
                     let amount_product = amount;
                     let promoApplied = arr[18];
                     if(promoApplied == '1')//promo applied
                     {
                     let chargeResp = await chargePromoCode(tid,promoCode,discount,arr[2],log_prefix,log_suffix,amount_product,req.hostname,clientip,req);
                     console.log(log_prefix + 'Promo charge response: ' + chargeResp + log_suffix);
                     if(chargeResp != 'Success')
                     {
                       res.send(chargeResp);
                       return;
                     }
                     }
                     let fetchOptionsCharge = '';
                     if(str != '0')
                     {
                      var strAmountInDecimal = str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
                     
                      var chargeBody = getVodaChargeBody(arr[4], arr[9], strAmountInDecimal, arr[2]);
                      console.log(log_prefix + chargeBody + log_suffix);
                       fetchOptionsCharge = {
                        method: 'POST',

                        body: chargeBody,

                        headers: {
                          'Authorization': 'Basic ' + Auth_vodacom,
                          'Content-Type': 'application/xml',
                        },
                        
                      }
                      console.log(log_prefix + 'vodacomChargeURL: ' + vodacomChargeURL + log_suffix);
                      var chargeTimeout = setTimeout(() => {console.log(log_prefix + 'vodacomChargeURL: Timeout' + log_suffix);res.send('chargeApiTimeout')}, 30000);
                    }
                      try {
                        let jsonResponseCharge = 'full_discount';
                        if(str != '0')
                        {
                            const response = await fetch(vodacomChargeURL, fetchOptionsCharge,proxy_url);
                            jsonResponseCharge = await response.text();
                          
                        clearTimeout(chargeTimeout);
                        console.log(log_prefix + jsonResponseCharge + log_suffix);
                        }
                        if (((jsonResponseCharge.toString().includes('<is-success>true</is-success>')) && (jsonResponseCharge.toString().includes('<code>ACCEPTED</code>')))||jsonResponseCharge.toString().includes('full_discount')) {
	            
                          let up_cred = await getUPCredentials(req);

                          var userIdHost = up_cred.userIdHost;
                          var userPaswdHost = up_cred.userPaswdHost;
                          let customer = up_cred.customer;
                          let paymentId = '';
                          if(jsonResponseCharge.toString().includes('<transaction-id>'))
                          {
                            let a = jsonResponseCharge.split('<transaction-id>');
                            if(a.length)
                            {
                              let a1 = a[1].split('</transaction-id>');
                              if(a1.length)
                                paymentId = a1[0];
                            }
                          }
                          var tidhead = '';
                          
                          tidhead = '<TERMINALID>'+ arr[1] +'</TERMINALID>';
                  
                        if((arr[1] == '') || (arr[1] == 'undefined') || (arr[1] == 'notid'))
                        {
                            let gtid = getDefaultTID(req.hostname,req);
                            tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
                        }

                        

                          var extrahead = '';
                          var eanhead = '<EAN>' + arr[3] + '</EAN>';
                          if (arr[10].includes('Renewal') || arr[10].includes('renewal')) {
                            extrahead = '<EXTRADATA>' +
                              '<DATA name="CONTRACT">' + arr[2] + '</DATA>' +
                              '<DATA name="RedirectionDivisionID">vodacom</DATA>' +
                              '</EXTRADATA>';
                           
                          }  

                          let cashierhead = '';
                          if(cashier.length)
                          {
                            cashierhead = '<CASHIER>' + cashier + '</CASHIER>';
                          }
                          
                          let send_sms_tag = '';
                          let del_mode = getDeliveryMode(req.hostname,null);
                          if(del_mode.includes('SMS'))
                          {
                            send_sms_tag = '<CONSUMER>' +
                            '<SMS>' + '+' + arr[4] + '</SMS>' +
                            '</CONSUMER>' ;
                          }
                          let PAN_TAG = '';
                          let CURRENTCY_TAG = ''; 
                          let AMOUNT_TAG_PIN = '<AMOUNT>'+ arr[8]  +'</AMOUNT>' ;   //amount_product
                          let AMOUNT_TAG_POSA = '';                    
                          if(prod_type_sale == 'POSA') {
                            PAN_TAG = '<PAN>' + activation_serial + '</PAN>';
                            CURRENTCY_TAG = '<CURRENCY>' + currency_code + '</CURRENCY>';
                            AMOUNT_TAG_PIN = '';
                            AMOUNT_TAG_POSA = '<AMOUNT>'+ arr[8] +'</AMOUNT>'; //amount_product
                          }
                          
                          //Business in a box
                          if(await isBusinesInABoxAkani(tid,eantofind,req)) {
                            let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + arr[2] + '</DATA>';
                            if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                              extrahead = extrahead.replace('</EXTRADATA>', REFID_URL_TAG+'</EXTRADATA>')
                            }
                            else {
                              extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
                            }
                            
                          }

                          const fetchOptions = {
                            method: 'POST',

                            body: '<REQUEST type="SALE" STORERECEIPT="1">' +
                              '<LOCALDATETIME>' + arr[0] + '</LOCALDATETIME>' +
                              '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                              tidhead +    
                              cashierhead +                         
                              '<TXID>' + (arr[2].includes('EPAY-undefined') ? arr[2].replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): arr[2])
                               + '</TXID>' +
                              '<USERNAME>' + userIdHost + '</USERNAME>' +
                              '<CARD>' +
                              AMOUNT_TAG_PIN + 
                              //'<AMOUNT>'+ arr[8] +'</AMOUNT>' +
                              PAN_TAG +
                              eanhead +
                              '</CARD>' +
                              AMOUNT_TAG_POSA +
                              '<Comment>' + 'PaymentMethod=vodacom|</Comment>' +
                              CURRENTCY_TAG +
                              // '<CONSUMER>' +
                              // '<SMS>' + '+' + arr[4] + '</SMS>' +
                              // '</CONSUMER>' +
                              send_sms_tag +
                              extrahead +
                              '</REQUEST>',

                            headers: {
                              'Content-Type': 'application/xml',
                            },
                
                          }
			                     mask_xml_data(fetchOptions.body,log_prefix,log_suffix)
                           console.log(log_prefix + 'SALE URL: ' + UPInterfaceURL + log_suffix);
                          var upSaleTimeout = setTimeout(() => {console.log(log_prefix + 'SALE URL: TIMEOUT' + log_suffix);res.send('chargeApiTimeout')}, 30000);
                          try {
                            const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
                            let jsonResponse = await response.text();
                          
                            clearTimeout(upSaleTimeout);

                            //console.log(jsonResponse);
                            mask_xml_data(jsonResponse,log_prefix,log_suffix);

                            if (jsonResponse.includes('<RESULT>0</RESULT>')) {
                              jsonResponse = await updateRedeemptionURL(jsonResponse);

                              var key, reference, serial;
                              var phone = arr[4];
                              var arrpin = jsonResponse.split('<PIN>');
                              var arrreference = jsonResponse.split('<TXID>');
                              var arrserial = jsonResponse.split('<SERIAL>');
                              if ((arrpin.length > 1) && (arrreference.length > 1) && (arrserial.length > 1)) {
                                var arrpin1 = arrpin[1].split('</PIN>');
                                var arrreference1 = arrreference[1].split('</TXID>');
                                var arrserial1 = arrserial[1].split('</SERIAL>');
                                if ((arrpin1.length > 1) && (arrreference1.length > 1) && (arrserial1.length > 1)) {
                                  key = arrpin1[0];
                                  reference = arrreference1[0];
                                  var tm = reference.split('-');
                                  var refTime = reference;
                                  if (tm.length > 1) {
                                    refTime = tm[1];
                                  }
                                  serial = arrserial1[0];
                                  console.log(key + ',' + refTime + ',' + serial + ',' + phone);

                                  var smsBody = getSMSBody_PIN_Customer(key, refTime, serial, phone, arr[10], arr[13], arr[14],req.hostname,jsonResponse);
                                  console.log(log_prefix + smsBody + log_suffix);
                                  const fetchOptionsCustomer = {
                                    method: 'POST',

                                    body: smsBody,

                                    headers: {
                                      'Authorization': 'Basic ' + Auth_vodacom,
                                      'Content-Type': 'application/xml',
                                    },
                                    
                                  }
                                  console.log(log_prefix + 'SEND SMS: ' + vodacomSMSURL + log_suffix);
                                  var txnConfirmation = setTimeout(() => console.log('sale confirmation message send timedout.'), 30000);
                                  try {
                                    const responseCus = await fetch(vodacomSMSURL, fetchOptionsCustomer,proxy_url);
                                    const jsonResponseCus = await responseCus.text();
                                  
                                    clearTimeout(txnConfirmation);
                                    console.log('SMS Response');
                                    console.log(log_prefix+jsonResponseCus + log_suffix);
                                  } catch (error) {
                                    console.log(error);
                                    console.log(log_prefix+'Something went wrong' + log_suffix);
                                    res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>');
                                    return;
                                  }

                                }
                              }
                              let activation_serial_tag = '<ACTIVATIONSERIAL>' + activation_serial + '</ACTIVATIONSERIAL>';
                              let product_type_tag = '<PRODUCTTYPE>' + prod_type_sale + '</PRODUCTTYPE>';
                              jsonResponse = jsonResponse.replace('</RESPONSE>', activation_serial_tag + product_type_tag + '</RESPONSE>');
                              //Add Payment Info Here for renewal product
                              let product_name = arr[10];
                              if (((product_name.includes('Renewal')) || product_name.includes('renewal'))) {                
                                let phoneTAGN = '<PHONE>' + phone +  '</PHONE>';                          
                                let a1 = eanhead.split('<EAN>')
                                let a2 = a1[1].split('</EAN>');
                                let eantouse = a2[0];
                                const fetchOptionsInfo = {
                                  method: 'POST',
                
                                  body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
                                    '<USERNAME>' + userIdHost + '</USERNAME>' +
                                    '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                                    tidhead +
                                    '<LOCALDATETIME>' + getFormattedTime() + '</LOCALDATETIME>' +
                                    '<TXID>' + (arr[2].includes('EPAY-undefined') ? arr[2].replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): arr[2]) + '_PI' + '</TXID>' +
                                    '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
                                    '<SUBSCRIPTION>' +
                                    '<TOKENID>' + phone + '</TOKENID>' +
                                    '<LASTFOUR>' + phone.substring(phone.length-4,phone.length) + '</LASTFOUR>' +
                                    '<CARDTYPE>' + 'DCB' + '</CARDTYPE>' +                        
                                    phoneTAGN + //send_sms_tag +   
                                    '<EMAIL></EMAIL>' +                               
                                    '</SUBSCRIPTION>' +
                                    '<TRANSACTIONREF>' +
                                    '<REFTYPE>CONTRACTID</REFTYPE>' +
                                    '<REF>' + arr[2] + '</REF>' +
                                    '</TRANSACTIONREF>' +
                                    '</REQUEST>',
                
                                  headers: {
                                    'Content-Type': 'application/xml',
                                  },
                            
                                }
              
                             
                              console.log(log_prefix + 'PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
                              mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
                              console.log(log_prefix + paymentInfoURL + log_suffix);
                              const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
                              var jsonResponseInfo = await response.text();
                           
                              console.log(log_prefix + 'PAYMENTINFO Response:' + log_suffix);
                              let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
                              mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);
              
                              }
                            }
                            else {
                            
                             if(arr[8] != '0') //full discount
                             {
                                let response = await processRefundVodacomAPI(arr[8],arr[2]+ '-r','act_id',paymentId,arr[3],arr[1],arr[2],customer,log_prefix,log_suffix,true,req);
                                console.log(log_prefix +  response + log_suffix);
                             }
                             
                             let a1 = tidhead.split('<TERMINALID>'); 
                             let a2 = a1[1].split('</TERMINALID>');
                             let tid_used = a2[0];
                             let promocode = arr[19];
                             
                             if(promoApplied == '1')//promo applied
                             {
                             	let result_refund_promo = await refundPromoDiscount(tid_used,arr[2], promocode,log_prefix,log_suffix,req);
                             	console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                             }
                                 
                            
                            }
                        
                            console.log(log_prefix+jsonResponse + log_suffix);
                            res.send(jsonResponse);
                          }
                          catch (error) {
                            console.log(log_prefix+'Exception' + log_suffix);
                            console.log(error);
                          }
                        }
                        else {
                          var errorArr = jsonResponseCharge.toString().split('<error-description>');
                          var errorText = getMessageIDText('MESSAGEID_163',req);
                          if (errorArr.length > 1) {
                            var arr = errorArr[1].split('</error-description>');
                            if (arr[0].length > 0)
                              errorText = arr[0];
                          }
                          
                          var responseFailureCharge = '<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>' + 'Hi, ' + errorText + ' Vodacom' + '</RESULTTEXT></RESPONSE>';
                          console.log(log_prefix + responseFailureCharge + log_suffix);
                          res.send(responseFailureCharge);
                        }
                      } catch (error) {
                        console.log(error);
                        console.log(log_prefix + 'Something went wrong' + log_suffix);
                        res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>');
                      }
                    }
                  }
                  else {
                    var resp = '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_159',req)+'</RESULTTEXT></RESPONSE>'
                    console.log(log_prefix + resp + log_suffix);
                    res.send(resp);

                  }
                }
                else {
                  console.log(log_prefix + 'unauthorized' + log_suffix);
                  res.send('unauthorized');
                }
              }
              else if(use_xml_interface == '1') {

                let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
                if(isIpTrusted)
                {
                 
                   currentDate = getFormattedTime();
                   var txid = getTimeStamp();  

                 var x = Math.random() * 1000000;
                 console.log(x);
                 var y = x.toString().split('.');
                 console.log(y[0]);
                 txid = txid + y[0];
                 console.log(txid);

                 var tidhead = '';

                 tidhead = '<TERMINALID>'+ arr[1] +'</TERMINALID>';
                  let gtid = arr[1];
                if((arr[1] == '') || (arr[1] == 'undefined') || (arr[1] == 'notid'))
                {
                 gtid = getDefaultTID(req.hostname,req);
                tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
                }

                 let gtid_t = gtid;
                   let up_cred = await getUPCredentials(req);

                  userIdHost = up_cred.userIdHost;
                  userPaswdHost = up_cred.userPaswdHost;

                    
                    let eantofind = arr[3];
                    let product_variable = false;
                    let amount = await getAmountEAN(gtid_t,eantofind,log_prefix,log_suffix,req.hostname,clientip,req);
                    if(amount != 'none') {
                    let reslt = await checkIfVariableProductAndInRange(arr[8],eantofind,gtid_t,log_prefix,log_suffix,req);
                    if(reslt == 2){
                      amount = arr[8];
                      product_variable = true;
                    } else if(reslt == 1){
                      //Security error block ip
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid_t + ' Reason: GET_PIN Variable product range check failed'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      let resp = '<RESPONSE>' +'<RESULT>161</RESULT>' +'<RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>' + '<HOME>https://' + req.hostname + '</HOME>' + '<EAN>' + eantofind +'</EAN>' + '</RESPONSE>';
                      res.send(resp);
                      return;
                    } else if(reslt == -1){
                      //Security error block ip
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid_t + ' Reason: GET_PIN product not in catalog'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      let resp = '<RESPONSE>' +'<RESULT>162</RESULT>' +'<RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>' + '<HOME>https://' + req.hostname + '</HOME>' + '<EAN>' + eantofind +'</EAN>' + '</RESPONSE>';
                      res.send(resp);
                      return;
                    }
                    

                    let currencycode = 'AED';                    
                    let country_code = await getCountryCode(req.hostname);
                    if(country_code == 'ZA') {
                      currencycode = 'ZAR';
                    } else if(country_code == 'TR') {
                      currencycode = 'TRY';
                    } else if(country_code == 'SA') {
                      currencycode = 'SAR';
                    }
                    var getSymbolFromCurrency = require('currency-symbol-map');
                    var symbol = getSymbolFromCurrency(currencycode);
                    if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
                      symbol = '\u{2800}';
                    }
                    str1 = symbol + amount.substring(0, (amount.length - 2)) + "." + amount.substring((amount.length - 2), amount.length);
                    console.log(log_prefix + 'Amount from Catalog: ' + amount + log_suffix);
                    console.log(log_prefix + 'Amount from Catalog: ' + str1 + log_suffix);
                    console.log(log_prefix + 'Currency from Catalog: ' +currencycode + log_suffix);
                    ///////////////////////////////////////////////////////////////////////////////////////////////////

                    var str = arr[8];
                    let discount = arr[17];
                    let amtcmp = (Number(str)+Number(discount)).toString();
                    let product_type = arr[15];
                    let activation_serial = arr[21];
                    let prod_type_sale = arr[22];
                    let currency_code = arr[23];
                    
                 
                    if (amtcmp != amount) {
                      res.statusCode = 451;
                      console.log(log_prefix + 'Amount mismatch' + log_suffix);
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid_t + ' Reason: GET_PIN Amount mismatch'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      res.send('Amount mismatch');
                      return;

                   }
                   else {

                    let promoCode = arr[19];
                     let a1 = tidhead.split('<TERMINALID>')
                     let a2 = a1[1].split('</TERMINALID>');
                     let tid = a2[0];
                     let amount_product = amount;
                     let promoApplied = arr[18];
                     if(promoApplied == '1')//promo applied
                     {

                     let chargeResp = await chargePromoCode(tid,promoCode,discount,arr[2],log_prefix,log_suffix,amount_product,req.hostname,clientip,req);
                     console.log(log_prefix+'Promo charge response: ' + chargeResp+log_suffix);
                     if(chargeResp != 'Success')
                     {                       
                       res.send(chargeResp);
                       return;
                     }
                     }

                var str = arr[8];
                var strAmountInDecimal = str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
                const clientip = req.headers['incap-client-ip'] ;
                console.log(log_prefix + 'clientip: ' + clientip + log_suffix);
                let XML_TID = getDefaultTID(req.hostname,req);
                
                let charge_ident = tmA[2];
                var bodyCharge = '<COMMAND>' +
                  '<IPADR>' + clientip + '</IPADR>' +
                  '<FUNKTION>3</FUNKTION>' +
                  '<TERMINAL-ID>'+XML_TID+'</TERMINAL-ID>' +
                  '<USERLOGIN>'+user_xml+'</USERLOGIN>' +
                  '<PASSWORD>'+password_xml+'</PASSWORD>' +
                   // '<IDENT>' + arr[6] + '</IDENT>' + //@@Ident
                  '<IDENT>' + tmA[2] + '</IDENT>' +
                  '<PAN>' + arr[4] + '</PAN>' + 
                  '<BETRAG>' + str + '</BETRAG>' + 
                  '<VALUTA>710</VALUTA>' +
                  '<CARDTYPE>2643</CARDTYPE>' +
                  '<EXTRADATA>' +
                 // '|PIN=' + arr[5] + '|' +
                  'PIN=' + arr[5] + '|' +
                  'SERVICEID=' + arr[9] + '|' +
                  '</EXTRADATA>' +
                  '</COMMAND>';
                console.log(log_prefix + bodyCharge + log_suffix);

                const fetchOptionsCharge = {
                  method: 'POST',

                  body: bodyCharge,

                  headers: {
                    'Destination': 'cwxmlgate',
                  },
           
                }
                console.log(log_prefix + 'XML URL: ' + XMLInterfaceURL + log_suffix);
                var chargeResponseSent = 0;
                var chargeTimeout = setTimeout(() => { console.log(log_prefix+'charge request time out' + log_suffix); chargeResponseSent = 1; res.send('apiTimeout') }, 30000);
                try {
                  const responseCharge = await fetch(XMLInterfaceURL, fetchOptionsCharge,proxy_url);
                  const xmlResponseCharge = await responseCharge.text();                


                  clearTimeout(chargeTimeout);
                  console.log(log_prefix +  xmlResponseCharge + log_suffix);
                  var parseString = require('xml2js').parseString;

                  var statusCode = '';
                  var statusText = '';
                  parseString(xmlResponseCharge, function (err, result) {
                    console.log(result.ANSWER);
                    statusCode = result.ANSWER.FEHLERCODE;
                    statusText = result.ANSWER.FEHLERTEXT;

                  });

                  if (xmlResponseCharge.includes('<FEHLERCODE>0000</FEHLERCODE>')) {

                    var tidhead = '';
                    tidhead = '<TERMINALID>'+ arr[1] +'</TERMINALID>';
                    let tid_to_use = arr[1];
                    if((arr[1] == '') || (arr[1] == 'undefined') || (arr[1] == 'notid'))
                    {
                    let gtid = getDefaultTID(req.hostname,req);
                    tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
                    tid_to_use = gtid;
                    }

                    let up_cred = await getUPCredentials(req);

                    var userIdHost = up_cred.userIdHost;
                    var userPaswdHost = up_cred.userPaswdHost;
                    let customer = up_cred.customer;

                     

                    var extrahead = '';
                    let ean_to_use = arr[3];
                    var eanhead = '<EAN>' + arr[3] + '</EAN>';
                    if (arr[10].includes('Renewal') || arr[10].includes('renewal')) {
                      extrahead = '<EXTRADATA>' +
                        '<DATA name="CONTRACT">' + arr[2] + '</DATA>' +
                        '<DATA name="RedirectionDivisionID">sharafdg</DATA>' +
                        '</EXTRADATA>';
                     
                    }

                    let cashierhead = '';
                    if(cashier.length)
                    {
                      cashierhead = '<CASHIER>' + cashier + '</CASHIER>';
                    }
                    let send_sms_tag = '';
                    let del_mode = getDeliveryMode(req.hostname,null);
                    if(del_mode.includes('SMS'))
                    {
                      send_sms_tag = '<CONSUMER>' +
                      '<SMS>' + '+' + arr[4] + '</SMS>' +
                      '</CONSUMER>' ;
                    }

                    let PAN_TAG = '';
                    let CURRENTCY_TAG = ''; 
                    let AMOUNT_TAG_PIN = '<AMOUNT>'+ arr[8] +'</AMOUNT>' ;   
                    let AMOUNT_TAG_POSA = '';                    
                    if(prod_type_sale == 'POSA') {
                      PAN_TAG = '<PAN>' + activation_serial + '</PAN>';
                      CURRENTCY_TAG = '<CURRENCY>' + currency_code + '</CURRENCY>';
                      AMOUNT_TAG_PIN = '';
                      AMOUNT_TAG_POSA = '<AMOUNT>'+ arr[8] +'</AMOUNT>'
                    }

                    //Business in a box
                    if(await isBusinesInABoxAkani(tid,eantofind,req)) {
                      let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + arr[2] + '</DATA>';
                      if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                        extrahead = extrahead.replace('</EXTRADATA>', REFID_URL_TAG+'</EXTRADATA>')
                      }
                      else {
                        extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
                      }
                      
                    }


                    const fetchOptions = {
                      method: 'POST',

                      body: '<REQUEST type="SALE" STORERECEIPT="1">' +
                        '<LOCALDATETIME>' + arr[0] + '</LOCALDATETIME>' +
                        '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                        tidhead +
                        cashierhead +
                        '<TXID>' + (arr[2].includes('EPAY-undefined') ? arr[2].replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): arr[2]) + '</TXID>' +
                        '<USERNAME>' + userIdHost + '</USERNAME>' +
                        '<CARD>' +
                        PAN_TAG +
                        eanhead +
                        '</CARD>' +
                        AMOUNT_TAG_PIN +
                        AMOUNT_TAG_POSA +
                        '<Comment>' + 'PaymentMethod=vodacom|</Comment>' +
                        '<COMMENT>' + charge_ident + '</COMMENT>' +
                        CURRENTCY_TAG +
                       // '<AMOUNT>'+ arr[8] +'</AMOUNT>' +
                        // 
                        send_sms_tag +
                        '<COMMENT>' + arr[6] + '</COMMENT>' +
                        extrahead +
                        '</REQUEST>',

                      headers: {
                        'Content-Type': 'application/xml',
                      },
              
                    }
                    mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
                    console.log(log_prefix + 'SALE URL: '+ UPInterfaceURL + log_suffix)
                   const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
                   let jsonResponse = await response.text();                   
                   mask_xml_data(jsonResponse,log_prefix,log_suffix);
                    //console.log(jsonResponse);
// voda activation
                    if (jsonResponse.includes('<RESULT>0</RESULT>')) {
                      jsonResponse = await updateRedeemptionURL(jsonResponse);
                      var key, reference, serial;
                      var phone = arr[4];
                      var arrpin = jsonResponse.split('<PIN>');
                      var arrreference = jsonResponse.split('<TXID>');
                      var arrserial = jsonResponse.split('<SERIAL>');
                      if ((arrpin.length > 1) && (arrreference.length > 1) && (arrserial.length > 1)) {
                        var arrpin1 = arrpin[1].split('</PIN>');
                        var arrreference1 = arrreference[1].split('</TXID>');
                        var arrserial1 = arrserial[1].split('</SERIAL>');
                        if ((arrpin1.length > 1) && (arrreference1.length > 1) && (arrserial1.length > 1)) {
                          key = arrpin1[0];
                          reference = arrreference1[0];
                          var tm = reference.split('-');
                          var refTime = reference;
                          if (tm.length > 1) {
                            refTime = tm[1];
                          }
                          serial = arrserial1[0];
                          console.log(key + ',' + refTime + ',' + serial + ',' + phone + ',' + arr[10] + ',' + arr[13] + ',' + arr[14]);

                          var smsBody = getSMSBody_PIN_Customer(key, refTime, serial, phone, arr[10], arr[13], arr[14],req.hostname,jsonResponse);
                          console.log(log_prefix + smsBody + log_suffix);
                          const fetchOptionsCustomer = {
                            method: 'POST',

                            body: smsBody,

                            headers: {
                              'Authorization': 'Basic ' + Auth_vodacom,
                              'Content-Type': 'application/xml',
                            },
                            
                          }
                          console.log(log_prefix + 'SMS URL: ' + vodacomSMSURL + log_suffix);
                          const responseCus = await fetch(vodacomSMSURL, fetchOptionsCustomer,proxy_url);
                          const jsonResponseCus = await responseCus.text();
                          
                          console.log('SMS Response');
                          console.log(log_prefix + jsonResponseCus + log_suffix);

                        }
                      }
                      let activation_serial_tag = '<ACTIVATIONSERIAL>' + activation_serial + '</ACTIVATIONSERIAL>';
                      let product_type_tag = '<PRODUCTTYPE>' + prod_type_sale + '</PRODUCTTYPE>';
                      jsonResponse = jsonResponse.replace('</RESPONSE>', activation_serial_tag + product_type_tag + '</RESPONSE>');
                      //Add Payment Info Here for renewal product
                      let product_name = arr[10];
                        if (((product_name.includes('Renewal')) || product_name.includes('renewal'))) {                
                          let phoneTAGN = '<PHONE>' +  phone +  '</PHONE>';
                                
                          let a1 = eanhead.split('<EAN>')
                          let a2 = a1[1].split('</EAN>');
                          let eantouse = a2[0];
                          const fetchOptionsInfo = {
                            method: 'POST',
          
                            body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
                              '<USERNAME>' + userIdHost + '</USERNAME>' +
                              '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                              tidhead +
                              '<LOCALDATETIME>' + getFormattedTime() + '</LOCALDATETIME>' +
                              '<TXID>' + (arr[2].includes('EPAY-undefined') ? arr[2].replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): arr[2]) + '_PI' + '</TXID>' +
                              '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
                              '<SUBSCRIPTION>' +
                              '<TOKENID>' + phone + '</TOKENID>' +
                              '<LASTFOUR>' + phone.substring(phone.length-4,phone.length) + '</LASTFOUR>' +
                              '<CARDTYPE>' + 'DCB' + '</CARDTYPE>' +  
                              '<PAYMENTID>' + charge_ident   + '</PAYMENTID>'+                       
                               phoneTAGN + //send_sms_tag +   
                              '<EMAIL></EMAIL>' +                                   
                              '</SUBSCRIPTION>' +
                              '<TRANSACTIONREF>' +
                              '<REFTYPE>CONTRACTID</REFTYPE>' +
                              '<REF>' + arr[2] + '</REF>' +
                              '</TRANSACTIONREF>' +
                              '</REQUEST>',
          
                            headers: {
                              'Content-Type': 'application/xml',
                            },
                      
                          }
        
                        
                        console.log(log_prefix + 'PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
                        mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
                        console.log(log_prefix + paymentInfoURL + log_suffix);
                        const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
                        var jsonResponseInfo = await response.text();
                      
                        console.log(log_prefix + 'PAYMENTINFO Response:' + log_suffix);
                        let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
                        mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);
        
                        }
                    } 
                    else {
                          let paymentId = charge_ident;
                          let response = await processRefundVodacomXML(arr[8],reference + '-r','act_id',paymentId,ean_to_use,tid_to_use,reference,customer,log_prefix,log_suffix,req);
                          console.log(log_prefix +  response + log_suffix);  

                          let a1 = tidhead.split('<TERMINALID>'); 
                          let a2 = a1[1].split('</TERMINALID>');
                          let tid_used = a2[0];
                          let promocode = arr[19];
                          if(promoApplied == '1') {
                          let result_refund_promo = await refundPromoDiscount(tid_used,arr[2], promocode,log_prefix,log_suffix,req);
                          console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                          }
                    }                 
                    console.log(log_prefix + jsonResponse + log_suffix);
                    res.send(jsonResponse);
                  }
                  else {        
                    var responseFailureCharge = '<RESPONSE><RESULT>' + statusCode + '</RESULT><RESULTTEXT>' + statusText + '</RESULTTEXT></RESPONSE>';
                    console.log(log_prefix + responseFailureCharge + log_suffix);
                    res.send(responseFailureCharge);
                  }

                } catch (err) {
                  console.log(err);
                  console.log(log_prefix + 'Payment failed exception' + log_suffix);
                    res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_163',req)+'</RESULTTEXT></RESPONSE>');
                }
              } 
            }
            else {
              var resp = '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_159',req)+'</RESULTTEXT></RESPONSE>'
              console.log(log_prefix + resp + log_suffix);
              console.log(resp);
              res.send(resp);

            }
          
                }else
                {  
                  console.log(log_prefix + 'Service is IP restricted' + log_suffix);
                    res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_139',req)+'</RESULTTEXT></RESPONSE>');
                }
            }
            else if(use_xml_interface == '2') {

              let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
              if(isIpTrusted)
              {
               
                currentDate = getFormattedTime();
                 var txid = getTimeStamp();  

               var x = Math.random() * 1000000;
               console.log(x);
               var y = x.toString().split('.');
               console.log(y[0]);
               txid = txid + y[0];
               console.log(txid);

               var tidhead = '';

               tidhead = '<TERMINALID>'+ arr[1] +'</TERMINALID>';
               let gtid = arr[1];
              if((arr[1] == '') || (arr[1] == 'undefined') || (arr[1] == 'notid'))
              {
               gtid = getDefaultTID(req.hostname,req);
              tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
              }
              let gtid_t = gtid;
   
                 let up_cred = await getUPCredentials(req);

                  userIdHost = up_cred.userIdHost;
                  userPaswdHost = up_cred.userPaswdHost;

                    
                    let eantofind = arr[3];
                    let product_variable = false;
                    let amount = await getAmountEAN(gtid,eantofind,log_prefix,log_suffix,req.hostname,clientip,req);
                    if(amount != 'none') {
                    let reslt = await checkIfVariableProductAndInRange(arr[8],eantofind,gtid,log_prefix,log_suffix,req);
                    if(reslt == 2){
                      amount = arr[8];
                      product_variable = true;
                    } else if(reslt == 1){
                      //Security error block ip
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid + ' Reason: GET_PIN Variable product range check failed'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      let resp = '<RESPONSE>' +'<RESULT>161</RESULT>' +'<RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>' + '<HOME>https://' + req.hostname + '</HOME>' + '<EAN>' + eantofind +'</EAN>' + '</RESPONSE>';
                      res.send(resp);
                      return;
                    } else if(reslt == -1){
                      //Security error block ip
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid + ' Reason: GET_PIN product not in catalog'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      let resp = '<RESPONSE>' +'<RESULT>162</RESULT>' +'<RESULTTEXT>'+getMessageIDText('MESSAGEID_118',req)+'</RESULTTEXT>' + '<HOME>https://' + req.hostname + '</HOME>' + '<EAN>' + eantofind +'</EAN>' + '</RESPONSE>';
                      res.send(resp);
                      return;
                    }
                    

                    let currencycode = 'AED';                    
                    let country_code = await getCountryCode(req.hostname);
                    if(country_code == 'ZA') {
                      currencycode = 'ZAR';
                    } else if(country_code == 'TR') {
                      currencycode = 'TRY';
                    } else if(country_code == 'SA') {
                      currencycode = 'SAR';
                    }
                    var getSymbolFromCurrency = require('currency-symbol-map');
                    var symbol = getSymbolFromCurrency(currencycode);
                    if((currencycode == 'AED') && (getIsNewDirhunSymbol(req) == 'yes')) {
                      symbol = '\u{2800}';
                    }
                    str1 = symbol + amount.substring(0, (amount.length - 2)) + "." + amount.substring((amount.length - 2), amount.length);
                    console.log(log_prefix + 'Amount from Catalog: ' + amount + log_suffix);
                    console.log(log_prefix + 'Amount from Catalog: ' + str1 + log_suffix);
                    console.log(log_prefix + 'Currency from Catalog: ' +currencycode + log_suffix);
                    ///////////////////////////////////////////////////////////////////////////////////////////////////

                    var str = arr[8];
                    let discount = arr[17];
                    let amtcmp = (Number(str)+Number(discount)).toString();
                    let product_type = arr[15];
                    let activation_serial = arr[21];
                    let prod_type_sale = arr[22];
                    let currency_code = arr[23];
                    
                  
                    if (amtcmp != amount) {
                      res.statusCode = 451;
                      console.log(log_prefix + 'Amount mismatch' + log_suffix);
                      let alert = 'SECURITY ALERT: Blocked Access: ' + clientip + ' TID: ' + gtid + ' Reason: GET_PIN Amount mismatch'
                      console.log(log_prefix + alert + log_suffix);
                      if(BlockedIPs) {
                        BlockedIPs = BlockedIPs + ',' + clientip;
                      }else {
                        BlockedIPs = clientip;
                      }
                      res.send('Amount mismatch');
                      return;

                  }
                 else {

                  let promoCode = arr[19];
                   let a1 = tidhead.split('<TERMINALID>')
                   let a2 = a1[1].split('</TERMINALID>');
                   let tid = a2[0];
                   let amount_product = amount;
                   let promoApplied = arr[18];
                   if(promoApplied == '1')//promo applied
                   {

                   let chargeResp = await chargePromoCode(tid,promoCode,discount,arr[2],log_prefix,log_suffix,amount_product,req.hostname,clientip);
                   console.log(log_prefix,'Promo charge response: ' + chargeResp,log_suffix);
                   if(chargeResp != 'Success')
                   {                       
                     res.send(chargeResp);
                     return;
                   }
                   }

              var str = arr[8];
              var strAmountInDecimal = str.substring(0, (str.length - 2)) + "." + str.substring((str.length - 2), str.length);
              const clientip = req.headers['incap-client-ip'] ;
              console.log(log_prefix + 'clientip: ' + clientip + log_suffix);
              let XML_TID = getDefaultTID(req.hostname,req);
              
              let charge_ident = tmA[2];
              let up_cred = await getUPCredentials(req);
              //alt charge
              var bodyCharge = '<REQUEST TYPE="ALTPAY" MODE="CAPTURE">' +           
              '<AUTHORIZATION>' +
              '<USERNAME>'+up_cred.userIdHost+'</USERNAME>' +
              '<PASSWORD>'+up_cred.userPaswdHost+'</PASSWORD>' + 
              '</AUTHORIZATION>' +
              '<TERMINALID>'+XML_TID+'</TERMINALID>' +
              '<TXID>'+ arr[2] + '_CHARGE' +'</TXID>' +
              '<AMOUNT>' + str + '</AMOUNT>' +
              '<CURRENCY>710</CURRENCY>' + 
              '<CARD>'  +
              '<PAN>' + arr[4] + '</PAN>' +
              '</CARD>'  +
              '<EXTRADATA>' +
              '<DATA name="APP">epayPOSAndroid</DATA>' +
               '<DATA name="CUSTOMER_SCAN">1</DATA>' +
               '<DATA name="CARDTYPE">2643</DATA>' +
               '<DATA name="TRACE">'+ tmA[2] +'</DATA>' +
               '<DATA name="PIN">' + arr[5]  + '</DATA>' +
               '<DATA name="SERVICEID">'+arr[9]+'</DATA>' +
              '</EXTRADATA>' +            
               '</REQUEST>';

              console.log(log_prefix + bodyCharge + log_suffix);

              const fetchOptionsCharge = {
                method: 'POST',

                body: bodyCharge               
         
              }
              let ALTPayInterfaceURL = UPInterfaceURL;
              console.log(log_prefix + 'ALTPAY URL: ' + ALTPayInterfaceURL + log_suffix);
              var chargeResponseSent = 0;
              var chargeTimeout = setTimeout(() => { console.log(log_prefix+'charge request time out' + log_suffix); chargeResponseSent = 1; res.send('apiTimeout') }, 30000);
              try {
                const responseCharge = await fetch(ALTPayInterfaceURL, fetchOptionsCharge,proxy_url);
                const xmlResponseCharge = await responseCharge.text();                


                clearTimeout(chargeTimeout);
                console.log(log_prefix +  xmlResponseCharge + log_suffix);
                var parseString = require('xml2js').parseString;

                var statusCode = '';
                var statusText = '';
                parseString(xmlResponseCharge, function (err, result) {
                  console.log(result.RESPONSE);
                  statusCode = result.RESPONSE.RESULT[0];
                  statusText = result.RESPONSE.RESULTTEXT[0];

                });

                if(xmlResponseCharge.includes('<RESULT>0</RESULT>')) {

                  var tidhead = '';
                  tidhead = '<TERMINALID>'+ arr[1] +'</TERMINALID>';
                  let tid_to_use = arr[1];
                  if((arr[1] == '') || (arr[1] == 'undefined') || (arr[1] == 'notid'))
                  {
                    let gtid = getDefaultTID(req.hostname,req);
                    tidhead = '<TERMINALID>'+ gtid +'</TERMINALID>';
                    tid_to_use = gtid;
                  }

                  let up_cred = await getUPCredentials(req);

                  var userIdHost = up_cred.userIdHost;
                  var userPaswdHost = up_cred.userPaswdHost;
                  let customer = up_cred.customer;

                  

                   

                  var extrahead = '';
                  let ean_to_use = arr[3];
                  var eanhead = '<EAN>' + arr[3] + '</EAN>';
                  if (arr[10].includes('Renewal') || arr[10].includes('renewal')) {
                    extrahead = '<EXTRADATA>' +
                      '<DATA name="CONTRACT">' + arr[2] + '</DATA>' +
                      '<DATA name="RedirectionDivisionID">vodacom</DATA>' +
                      '</EXTRADATA>';
                   
                  }

                  let cashierhead = '';
                  if(cashier.length)
                  {
                    cashierhead = '<CASHIER>' + cashier + '</CASHIER>';
                  }
                  let send_sms_tag = '';
                  let del_mode = getDeliveryMode(req.hostname,null);
                  if(del_mode.includes('SMS'))
                  {
                    send_sms_tag = '<CONSUMER>' +
                    '<SMS>' + '+' + arr[4] + '</SMS>' +
                    '</CONSUMER>' ;
                  }

                  let PAN_TAG = '';
                  let CURRENTCY_TAG = ''; 
                  let AMOUNT_TAG_PIN = '<AMOUNT>'+ arr[8] +'</AMOUNT>' ;   
                  let AMOUNT_TAG_POSA = '';                    
                  if(prod_type_sale == 'POSA') {
                    PAN_TAG = '<PAN>' + activation_serial + '</PAN>';
                    CURRENTCY_TAG = '<CURRENCY>' + currency_code + '</CURRENCY>';
                    AMOUNT_TAG_PIN = '';
                    AMOUNT_TAG_POSA = '<AMOUNT>'+ arr[8] +'</AMOUNT>';
                  }

                  //Business in a box
                  if(await isBusinesInABoxAkani(tid,eantofind,req)) {
                    let REFID_URL_TAG = '<DATA name="QRCODE">' + 'https://' + req.hostname + '?REFID=' + arr[2] + '</DATA>';
                    if((extrahead.length)&&(extrahead.includes('</EXTRADATA>'))) {
                      extrahead = extrahead.replace('</EXTRADATA>', REFID_URL_TAG+'</EXTRADATA>')
                    }
                    else {
                      extrahead = '<EXTRADATA>'+ REFID_URL_TAG + '</EXTRADATA>';
                    }
                    
                  }

                  const fetchOptions = {
                    method: 'POST',

                    body: '<REQUEST type="SALE" STORERECEIPT="1">' +
                      '<LOCALDATETIME>' + arr[0] + '</LOCALDATETIME>' +
                      '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                      tidhead +
                      cashierhead +
                      '<TXID>' + (arr[2].includes('EPAY-undefined') ? arr[2].replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): arr[2]) + '</TXID>' +
                      '<USERNAME>' + userIdHost + '</USERNAME>' +
                      '<CARD>' +
                      PAN_TAG +
                      eanhead +
                      '</CARD>' +
                      AMOUNT_TAG_PIN +
                      AMOUNT_TAG_POSA +
                      '<Comment>' + 'PaymentMethod=vodacom|</Comment>' +
                     // '<COMMENT>' + charge_ident + '</COMMENT>' +
                      CURRENTCY_TAG +
                     // '<AMOUNT>'+ arr[8] +'</AMOUNT>' +
                      // 
                      send_sms_tag +
                      '<COMMENT>' + arr[6] + '</COMMENT>' +
                      extrahead +
                      '</REQUEST>',

                    headers: {
                      'Content-Type': 'application/xml',
                    },
            
                  }
                  mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
                  console.log(log_prefix + 'SALE URL: '+ UPInterfaceURL + log_suffix)
                 const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
                 let jsonResponse = await response.text();                   
                 mask_xml_data(jsonResponse,log_prefix,log_suffix);
                  //console.log(jsonResponse);
// voda activation
                  if (jsonResponse.includes('<RESULT>0</RESULT>')) {
                    jsonResponse = await updateRedeemptionURL(jsonResponse);
             
                    var key, reference, serial;
                    var phone = arr[4];
                    var arrpin = jsonResponse.split('<PIN>');
                    var arrreference = jsonResponse.split('<TXID>');
                    var arrserial = jsonResponse.split('<SERIAL>');
                    if ((arrpin.length > 1) && (arrreference.length > 1) && (arrserial.length > 1)) {
                      var arrpin1 = arrpin[1].split('</PIN>');
                      var arrreference1 = arrreference[1].split('</TXID>');
                      var arrserial1 = arrserial[1].split('</SERIAL>');
                      if ((arrpin1.length > 1) && (arrreference1.length > 1) && (arrserial1.length > 1)) {
                        key = arrpin1[0];
                        reference = arrreference1[0];
                        var tm = reference.split('-');
                        var refTime = reference;
                        if (tm.length > 1) {
                          refTime = tm[1];
                        }
                        serial = arrserial1[0];
                        console.log(key + ',' + refTime + ',' + serial + ',' + phone + ',' + arr[10] + ',' + arr[13] + ',' + arr[14]);

                        var smsBody = getSMSBody_PIN_Customer(key, refTime, serial, phone, arr[10], arr[13], arr[14],req.hostname,jsonResponse);
                        console.log(log_prefix + smsBody + log_suffix);
                        const fetchOptionsCustomer = {
                          method: 'POST',

                          body: smsBody,

                          headers: {
                            'Authorization': 'Basic ' + Auth_vodacom,
                            'Content-Type': 'application/xml',
                          },
                          
                        }
                        console.log(log_prefix + 'SMS URL: ' + vodacomSMSURL + log_suffix);
                        const responseCus = await fetch(vodacomSMSURL, fetchOptionsCustomer,proxy_url);
                        const jsonResponseCus = await responseCus.text();
                        
                        console.log('SMS Response');
                        console.log(log_prefix + jsonResponseCus + log_suffix);

                      }
                    }
                    let activation_serial_tag = '<ACTIVATIONSERIAL>' + activation_serial + '</ACTIVATIONSERIAL>';
                    let product_type_tag = '<PRODUCTTYPE>' + prod_type_sale + '</PRODUCTTYPE>';
                    jsonResponse = jsonResponse.replace('</RESPONSE>', activation_serial_tag + product_type_tag + '</RESPONSE>');
                    //Add Payment Info Here for renewal product
                    let product_name = arr[10];
                      if (((product_name.includes('Renewal')) || product_name.includes('renewal'))) {                
                        let phoneTAGN = '<PHONE>' +  phone +  '</PHONE>';
                              
                        let a1 = eanhead.split('<EAN>')
                        let a2 = a1[1].split('</EAN>');
                        let eantouse = a2[0];
                        const fetchOptionsInfo = {
                          method: 'POST',
        
                          body: '<REQUEST type="SUBSCRIPTION" MODE="PAYMENTINFO">' +
                            '<USERNAME>' + userIdHost + '</USERNAME>' +
                            '<PASSWORD>' + userPaswdHost + '</PASSWORD>' +
                            tidhead +
                            '<LOCALDATETIME>' + getFormattedTime() + '</LOCALDATETIME>' +
                            '<TXID>' + (arr[2].includes('EPAY-undefined') ? arr[2].replace('EPAY-undefined',('EPAY-' + getDefaultTID(req.hostname,req))): arr[2]) + '_PI' + '</TXID>' +
                            '<PRODUCTID>' + eantouse + '</PRODUCTID>' +
                            '<SUBSCRIPTION>' +
                            '<TOKENID>' + phone + '</TOKENID>' +
                            '<LASTFOUR>' + phone.substring(phone.length-4,phone.length) + '</LASTFOUR>' +
                            '<CARDTYPE>' + 'DCB' + '</CARDTYPE>' +  
                            '<PAYMENTID>' + charge_ident   + '</PAYMENTID>'+                       
                             phoneTAGN + //send_sms_tag +   
                            '<EMAIL></EMAIL>' +                                   
                            '</SUBSCRIPTION>' +
                            '<TRANSACTIONREF>' +
                            '<REFTYPE>CONTRACTID</REFTYPE>' +
                            '<REF>' + arr[2] + '</REF>' +
                            '</TRANSACTIONREF>' +
                            '</REQUEST>',
        
                          headers: {
                            'Content-Type': 'application/xml',
                          },
                    
                        }
      
                      
                      console.log(log_prefix + 'PAYMENTINFO Request:' +  paymentInfoURL + log_suffix);
                      mask_xml_data(fetchOptionsInfo.body,log_prefix,log_suffix);
                      console.log(log_prefix + paymentInfoURL + log_suffix);
                      const response = await fetch(paymentInfoURL, fetchOptionsInfo,proxy_url);
                      var jsonResponseInfo = await response.text();
                    
                      console.log(log_prefix + 'PAYMENTINFO Response:' + log_suffix);
                      let jsonResponse_log_info = jsonResponseInfo.replace(/\r?\n|\r/g, " ");
                      mask_xml_data(jsonResponse_log_info,log_prefix,log_suffix);
      
                      }
                  } 
                  else {
                        let paymentId = charge_ident;
                        let response = await processRefundVodacomALTPAY(arr[8],reference + '-r','act_id',paymentId,ean_to_use,tid_to_use,arr[2]+'_CHARGE',customer,log_prefix,log_suffix,req);
                        console.log(log_prefix +  response + log_suffix);  

                        let a1 = tidhead.split('<TERMINALID>'); 
                        let a2 = a1[1].split('</TERMINALID>');
                        let tid_used = a2[0];
                        let promocode = arr[19];
                        if(promoApplied == '1') {
                        let result_refund_promo = await refundPromoDiscount(tid_used,arr[2], promocode,log_prefix,log_suffix);
                        console.log(log_prefix + 'result_refund_promo: ' + result_refund_promo + log_suffix);
                        }
                  }                 
                  console.log(log_prefix + jsonResponse + log_suffix);
                  res.send(jsonResponse);
                }
                else {        
                  var responseFailureCharge = '<RESPONSE><RESULT>' + statusCode + '</RESULT><RESULTTEXT>' + statusText + '</RESULTTEXT></RESPONSE>';
                  console.log(log_prefix + responseFailureCharge + log_suffix);
                  res.send(responseFailureCharge);
                }

              } catch (err) {
                console.log(err);
                console.log(log_prefix + 'Payment failed exception' + log_suffix);
                  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+getMessageIDText('MESSAGEID_163',req)+'</RESULTTEXT></RESPONSE>');
              }
            } 
          }
          else {
            var resp = '<RESPONSE><RESULT>99</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_159',req)+'</RESULTTEXT></RESPONSE>'
            console.log(log_prefix + resp + log_suffix);
            console.log(resp);
            res.send(resp);

          }
        
              }else
              {  
                console.log(log_prefix + 'Service is IP restricted' + log_suffix);
                  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_139',req)+'</RESULTTEXT></RESPONSE>');
              }
          }

            }

          }
          else {
            console.log(log_prefix + 'Unauthorized' + log_suffix);
            res.send('unauthorized');
          }

        }
        else {
          console.log(log_prefix + 'Unauthorized' + log_suffix);
          res.send('unauthorized');
        }

      } catch (error) {
     
        console.log(error);
        res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>');
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

});




var requestIp = require('request-ip');
const { hostname } = require('os');

const months = [
  {mon:'Jan', mon_num:'01', num_days:31 },
  {mon:'Feb', mon_num:'02', num_days:28 },
  {mon:'Mar', mon_num:'03', num_days:31 },
  {mon:'Apr', mon_num:'04', num_days:30 },
  {mon:'May', mon_num:'05', num_days:31 },
  {mon:'Jun', mon_num:'06', num_days:30 },
  {mon:'Jul', mon_num:'07', num_days:31 },
  {mon:'Aug', mon_num:'08', num_days:31 },
  {mon:'Sep', mon_num:'09', num_days:30 },
  {mon:'Oct', mon_num:'10', num_days:31 },
  {mon:'Nov', mon_num:'11', num_days:30 },
  {mon:'Dec', mon_num:'12', num_days:31 },

]

let catalog = '0';

async function checkIfCatalogFileExpired(fileName)
{

  if(isTest)
    return false;

  if(catalog == '1')
  {
    return true;
  }

  if(!fs.existsSync(catalogDirectory + fileName))
    return true;

  let time_expiry = refreshCatalogTime;//'080000';
  const { birthtime } = fs.statSync(catalogDirectory + fileName);
  console.log('Catalog Creation TimeDate: ' + birthtime );
  let arrTime = birthtime.toString().split(' ');
  let time = arrTime[4];
  let mon_num;
  let num_days;
  let i=0;
  for(i=0; i<12; i++)
  {
    if(months[i].mon == arrTime[1])
    {
      mon_num = months[i].mon_num;
      num_days = months[i].num_days;
      break;
    }
  }
  console.log('time: ' + time);
  let creationTime = time.split(':'); 
  let creationDateTimeStamp = arrTime[3] + mon_num + arrTime[2] + creationTime[0] + creationTime[1] +creationTime[2];
  
  console.log('creationDateTimeStamp: ' + creationDateTimeStamp);  

  let currentDate = getTimeStamp(); 
  let date_current = currentDate.substring(0,8);

  console.log('currentDate: ' + currentDate); 
  console.log('date_current: ' + date_current);
  console.log('time_expiry: ' + time_expiry);

  console.log('date_difference: ' + date_current + time_expiry + ' - ' +creationDateTimeStamp);

  let condition1 = (await date_difference( currentDate,date_current + time_expiry));
  let condition2 = ( await date_difference(date_current + time_expiry ,creationDateTimeStamp));
  console.log('condition1J: ' + JSON.stringify(condition1));
  console.log('condition2J: ' + JSON.stringify(condition2));

  console.log('condition1: ' + condition1);
  console.log('condition2: ' + condition2);

  
  if((condition1 > 0)&&(condition2 > 0))
  {      
    return true;
  }
  else
  {   
    return false;
  }

  
  
}

function getcampaignString(req) {
  let host = (req.hostname.split('.'))[0];
    let campaignString = '';
    if(req.hostname == DOMAIN_1)
    {
      campaignString = campaign_domain_1;
    }
    else if(req.hostname == DOMAIN_3)
    {
      campaignString = campaign_domain_3;
    }
    else if(req.hostname == DOMAIN_2)
    {
      campaignString = campaign_domain_2;
    }
    else if(req.hostname == DOMAIN_0)
    {
      campaignString = campaign_domain_0;
    } else if(config[host]) {
      if(config[host].campaign) {
        campaignString = config[host].campaign;
      }
    }

    if(campaignString.length == 0) {
      campaignString = 'NO_CAMPAIGN_HEAD';
    }

    return campaignString;

}

function getCampaignTID(hostname,req)
{
    let host = (hostname.split('.'))[0];
    let campaignTID = '';
    if(hostname == DOMAIN_1)
    {
      campaignTID = campaignTID_domain_1;
    }
    else if(hostname == DOMAIN_3)
    {
      campaignTID = campaignTID_domain_3;
    }
    else if(hostname == DOMAIN_2)
    {
      campaignTID = campaignTID_domain_2;
    }
    else if(hostname == DOMAIN_0)
    {
      campaignTID = campaignTID_domain_0;
    } else if(config[host]) {
      if(config[host].campaignTID) {
        campaignTID = config[host].campaignTID;
      }
    }

    
    return campaignTID;
}

function getDefaultTID(hostname,req)
{
    let defaultTID = '';
    let host = (hostname.split('.'))[0];
    //if(hostname == DOMAIN_0 || isTest)
    if(hostname == DOMAIN_0)
    {
        defaultTID = defaultTID_domain_0;
    }else if(hostname == DOMAIN_1)
    {
        defaultTID = defaultTID_domain_1;
    }
    else if(hostname == DOMAIN_3)
    {
        defaultTID = defaultTID_domain_3;
    }
    else if(hostname == DOMAIN_2)
    {
        defaultTID = defaultTID_domain_2;
    } else if(config[host]) {
      if(config[host].defaultTID) {
        defaultTID = config[host].defaultTID;
      }
    }
    else 
    {
        defaultTID = '';
    } 
    //TEST_IP_AZURE
    if(req.headers.referer.includes('carrefour'))
      {
        defaultTID = '93880042';
      }
      else
      if(req.headers.referer.includes('lulu'))
      {
        defaultTID = 'UAE00545';
      }
      else
      if(req.headers.referer.includes('/akani'))
      {
        defaultTID = '93889311'; // '47869017';
      }
      else
      if(req.headers.referer.includes('/alt'))
      {
        defaultTID = '93889311';// '47869017';
      }
     else
      if(req.headers.referer.includes('samsungcare'))
      {
        defaultTID = '93880433';
      }
     else
      if(req.headers.referer.includes('/turkey'))
      {
        defaultTID = '93889695';
      }

   
    return defaultTID;
}

async function getCatalog(host,tid,ean,flag,req) {
  let tidhead = '';
  currentDate = getFormattedTime();
  var txid = getTimeStamp();
  var x = Math.random() * 1000000;
  console.log(x);
  var y = x.toString().split('.');
  console.log(y[0]);
  txid = txid + y[0];
  console.log(txid);

  let hostCatalogFileName =  tid + '_' +(host.split('.'))[0] +'.txt';

  let jsonResponse = '';

Console.log('get catalog data...');

  if(fs.existsSync(catalogDirectory + hostCatalogFileName))
  {
     jsonResponse = fs.readFileSync(catalogDirectory + hostCatalogFileName, 'utf8');
   
     console.log('Catalog Data Read from Cache..');

  }
  else
  {

        let up_cred = await getUPCredentials(req);

        var userIdHost = up_cred.userIdHost;
        var userPaswdHost = up_cred.userPaswdHost;

        

        tidhead = '<TERMINALID>'+tid+'</TERMINALID>';

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
            'Content-Type': 'application/xml',
          },
        

        }

        const response = await fetch(UPInterfaceURL, fetchOptions,proxy_url);
        jsonResponse = await response.text();    
      //  jsonResponse = jsonResponse.replace('</CATALOG>', test + '</CATALOG>');
   

  }
  if((jsonResponse.includes('<RESULT>0</RESULT>'))&&(jsonResponse.includes('<CATALOG>'))&&(!jsonResponse.includes('<CATALOG />'))) {
  
    jsonResponse =await limitMAXAMOUNT(jsonResponse,req) ;
    jsonResponse = await updateCatalogDataDiscountRRP(jsonResponse,req);
  }

  if(flag==0)
  {
  if(jsonResponse.includes('<EAN>'+ean+'</EAN>'))
  {
    let arr = jsonResponse.split('<EAN>'+ean+'</EAN>');
    let pin_type_str = arr[0].substring(arr[0].length-50,arr[0].length);
        let pin_type = '';
        if((pin_type_str.includes('<TYPE>'))&&(pin_type_str.includes('</TYPE>')))
        {
            let arr = pin_type_str.split('<TYPE>');
            let arr1 = arr[1].split('</TYPE>');
            pin_type = arr1[0];
        }
        let arr_1 = arr[1].split('</ARTICLE>');
        let blockToParse = '<RESPONSE>'+ '<TYPE>' + pin_type + '</TYPE>' + '<EAN>'+ean+'</EAN>' + arr_1[0]  +'</RESPONSE>';
        
        if(!(blockToParse.includes('<INFO>')&&blockToParse.includes('</INFO>'))) 
        {
          blockToParse = 'no_data';
        }



    return blockToParse;
    
  }
  else
  {
    return 'no_data';
  }
}
else
  return jsonResponse;

}


let remotebannerlocation;

async function getBannerImageListForHost(hostname,language,bannerlocation) {

  var host = hostname.split('.');
  var path2Fetch = host[0] + '/' + language + '/list.txt';
  var imageDir =  bannerlocation + 'banners/' + path2Fetch;

  if(isTest)
    imageDir='C:/work/web/WebServer/master/banners/endless/en/list.txt';

  console.log('Banner image location: ' + imageDir);
  files = [];
  try {
  if(fs.existsSync(imageDir))
  {
  let imageList = fs.readFileSync(imageDir,'utf-8');
  if(imageList.includes('\n'))
  {
    let list = imageList.split('\n');
    for(let i=0; i<list.length;i++)
    {
      if(list[i].length)
      {
        files.push(list[i]);  
      }
    }    
  }
}

 }
 catch(err) { 
  console.log(err);
  }
  console.log(files);
  return files;
}

let basepath = '/var/www/html/'


async function getDemoImageListForHost(hostname,language,demolocation,req) {

  var host = hostname.split('.');
  let host_prefix = host[0];


  var path2Fetch = host_prefix + '/' + language + '/list.txt';
  var imageDir =  demolocation + 'Screens/' + path2Fetch;

  console.log('demo image location: ' + imageDir);
  files = [];
  try {
  if(fs.existsSync(imageDir))
  {
  let imageList = fs.readFileSync(imageDir,'utf-8');
  if(imageList.includes('\n'))
  {
    let list = imageList.split('\n');
    for(let i=0; i<list.length;i++)
    {
      if(list[i].length)
      {
        files.push(list[i]);  
      }
    }    
  }
}

 }
 catch(err) { 
  console.log(err);
  }
  console.log(files);
  return files;
}

async function getDemoData(hostname,req) {

  let demoData = '';

  let demos_array_en = '';
  let demos_array_ar = '';
  let demo_location = basepath + 'static/media/';
  let demo_location_remote = 'https://' + hostname + '/static/media/';

  
  demos_array_en = await getDemoImageListForHost(hostname,'en',demo_location,req);
  demos_array_ar = await getDemoImageListForHost(hostname,'ar',demo_location,req);

  let host = hostname.split('.');
  let host_prefix = host[0];

  if(demos_array_en)
  {
  for(let i=0; i<demos_array_en.length; i++)
  {
    demoData = demoData + '<DEMOIMAGE>' + demo_location_remote + 'Screens/' + host_prefix + '/en/' + demos_array_en[i] +'</DEMOIMAGE>';
  }
}

  if(demos_array_ar)
  {
  for(let i=0; i<demos_array_ar.length; i++)
  {
    demoData = demoData + '<DEMOIMAGEAR>'+ demo_location_remote + 'Screens/'+ host_prefix + '/ar/' + demos_array_ar[i] +'</DEMOIMAGEAR>';
  } 
} 

  let final_demo_xml = '<DEMOS>' + demoData + '</DEMOS>';
    console.log('final_demo_xml: '+ final_demo_xml);
  return final_demo_xml;

}

async function getBannersData(hostname) {

  let bannerData = '';

  let banners_array_en = '';
  let banners_array_ar = '';
  let banner_location = basepath + 'static/media/';
  let banner_location_remote = 'https://' + hostname + '/static/media/';

  if(remotebannerlocation)
  {
    banner_location = remotebannerlocation + 'static/media/';
  }
  banners_array_en = await getBannerImageListForHost(hostname,'en',banner_location);
  banners_array_ar = await getBannerImageListForHost(hostname,'ar',banner_location);

  let host = hostname.split('.');
  
  
  if(banners_array_en)
  {
  for(let i=0; i<banners_array_en.length; i++)
  {
    bannerData = bannerData + '<BANNERIMAGE>' + banner_location_remote + 'banners/' + host[0] + '/en/' + banners_array_en[i] +'</BANNERIMAGE>';
  }
}

  if(banners_array_ar)
  {
  for(let i=0; i<banners_array_ar.length; i++)
  {
    bannerData = bannerData + '<BANNERIMAGEAR>'+ banner_location_remote + 'banners/'+ host[0] + '/ar/' + banners_array_ar[i] +'</BANNERIMAGEAR>';
  } 
} 

  let final_banner_xml = '<BANNERS>' + bannerData + '</BANNERS>';

  return final_banner_xml;

}



async function getDomainLogo(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
    return ('https://' + hostname + '/static/media/logos/' + domain1_logo);
  }
  else if(hostname == DOMAIN_2)
  {
    return ('https://' + hostname + '/static/media/logos/' + domain2_logo);
  }
  else if(hostname == DOMAIN_3)
  {
    return ('https://' + hostname + '/static/media/logos/' + domain3_logo);
  }
  else if(hostname == DOMAIN_0)
  {
    return ('https://' + hostname + '/static/media/logos/' + domain0_logo);
  } else if(config[host]) {
    if(config[host].DOMAIN_LOGO) {
      return ('https://' + hostname + '/static/media/logos/' + config[host].DOMAIN_LOGO);
    }
  }
}

async function getDomainTheme(hostname) {
  let host = (hostname.split('.'))[0];

  if(hostname == DOMAIN_1)
  {
    return domain1_theme;
  }
  else if(hostname == DOMAIN_2)
  {
    return domain2_theme;
  }
  else if(hostname == DOMAIN_3)
  {
    return domain3_theme;
  }
  else if(hostname == DOMAIN_0)
  {
    return domain0_theme;
  } else if(config[host]) {
    if(config[host].APP_THEME) {
      return config[host].APP_THEME;
    }
  } else {
    return domain0_theme;
  }
}



async function getCountryCode(hostname) {
  
  let code = 'AE';
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0) {
    code = DOMAIN_0_COUNTRY_CODE;
  } else if(hostname == DOMAIN_1) {
    code = DOMAIN_1_COUNTRY_CODE;
  } else if(hostname == DOMAIN_2) {
    code = DOMAIN_2_COUNTRY_CODE;
  } else if(hostname == DOMAIN_3) {
    code = DOMAIN_3_COUNTRY_CODE;
  } else if(config[host]) {
    if(config[host].COUNTRY_CODE) {
      code = config[host].COUNTRY_CODE;
    }
  }

  return code;

}



// Validate the Apple Pay session


app.post('/getValidateAppleSession', async(req, res) => {

  const clientip = req.headers['incap-client-ip'] ;
  console.log('>>API_CALL:getValidateAppleSession => clientip: ' + clientip);

  var txid = getTimeStamp();
  var x = Math.random() * 1000000;      
  var y = x.toString().split('.');      
  txid = txid + y[0];

  let session_id = txid;
  let host_log = req.hostname.split('.');
  let method = 'VALIDATE_APPLEPAY_SESSION';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';
 
   if (req.headers.referer) {
     if (await checkIfRefererAllowed(req.headers.referer,req)) {
       try {
 
 let info = await getApplePayMerchantInfo(req);
 console.log(log_prefix + JSON.stringify(info) + log_suffix);
 let host = (req.hostname.split('.'))[0];
  if(info) {

    let proxy_url_curl_option = '';
    if(config.proxyurl) {
      proxy_url_curl_option = ' -x ' + config.proxyurl;
    }
   
   const  appleUrl = req.body;
   console.log(log_prefix + 'Validate session url from client: ' +  appleUrl + log_suffix);
   let script = "curl -k -vvvvv"  + proxy_url_curl_option + " -m 2 --data " + "'" + '{"merchantIdentifier": "' + info.merchantIdentifier + '","displayName": "'+ info.shopDisplayName +'","domainName":"'+ req.hostname +'"}' + "'" + ' --cert '+ info.certificatePathPEM +' --key '+ info.certificatePathKEY + ' ' + info.sessionEndpoint;
   console.log(log_prefix + 'Validate session curl request: ' +  script + log_suffix);

   for(let retry=0;retry < 4;retry++) {
    try {
          let result = await runShellCmd(script);

          let obj = JSON.parse(result);
          console.log(log_prefix + 'CURL APPLEPAY SESSION SUCCESS (retry: ' + retry + ')'  + log_suffix);
          console.log(obj);
          res.send(obj);
          return;
      } catch (err) {   
          console.log(log_prefix + 'CURL APPLEPAY FAILED WITH EXCEPTION (retry: ' + retry + ')'  + log_suffix);        
          if(err.includes('curl:')) {
            let a = err.split('curl:');
            let error = a[1];
            console.log(log_prefix + 'CURL FAILED WITH ERROR : ' + error +  + log_suffix);
          } else {
            console.log(log_prefix + JSON.stringify(err) + log_suffix);
          }
            
      }
    }
    console.log(log_prefix + 'payment_not_completed' + log_suffix);
    res.send('payment_not_completed');
   
 //============================================================
   } else {
     console.log(log_prefix + 'applepay config not found!' + log_suffix);
     console.log(log_prefix + 'payment_not_completed' + log_suffix);
     res.send('payment_not_completed');
  }
 
 
   } catch (error) {
      
         console.log(log_prefix + JSON.stringify(error) + log_suffix);
         console.log(log_prefix + 'payment_not_completed' + log_suffix);
         res.send('payment_not_completed');
 
       }
 
     } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
   } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
 
 })



// Tokenise the Apple Pay payload
app.post('/getApplePay', async(req, res) => {
 const clientip = req.headers['incap-client-ip'] ;
 console.log('>>API_CALL:getApplePay => clientip: ' + clientip);

 var txid = getTimeStamp();
  var x = Math.random() * 1000000;      
  var y = x.toString().split('.');      
  txid = txid + y[0];

  let session_id = txid;
  let host_log = req.hostname.split('.');
  let method = 'APPLEPAY_TOKEN_REQUEST_CHECKOUT';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';

 if (req.headers.referer) {
    if (await checkIfRefererAllowed(req.headers.referer,req)) {
      try {



    let cred = await getCheckoutCredentials(req.hostname,req);
      if(cred)      {



let details = JSON.parse(req.body);
  console.log(details);
  const {
    version,
    data,
    signature,
    header
  } = details.token.paymentData

  const fetchOptions = {
    method: 'POST',

    body: JSON.stringify({
      type: 'applepay',
      token_data: {
        version: version,
        data: data,
        signature: signature,
        header:{
          ephemeralPublicKey: header.ephemeralPublicKey,
          publicKeyHash: header.publicKeyHash,
          transactionId: header.transactionId
        }
      }
    }),

    headers: {
      'Content-Type': 'application/json',     
      'Authorization': cred.publicKey
//'pk_sbox_dudgbdofqkdfvklefqyqolb7xmp'
//'pk_test_963b9a17-e72a-4bfc-9480-710961e62bcd'
//'pk_sbox_dudgbdofqkdfvklefqyqolb7xmp'// PUBLIC_KEY
         
    },
 
  }
   console.log(log_prefix + JSON.stringify(fetchOptions) + log_suffix);

   let token_url = cred.url;
   token_url = token_url.replace('payments','tokens');
   console.log(log_prefix + 'Checkout token Url: ' + token_url + log_suffix);
   const response = await fetch(token_url, fetchOptions, proxy_url);
   const jsonResponse = await response.json();
   console.log(log_prefix + JSON.stringify(jsonResponse)  + log_suffix);
   res.send(jsonResponse);
   return;
} else {
  console.log(log_prefix + 'checkout config not found!' + log_suffix);
  console.log(log_prefix + 'payment_not_completed' + log_suffix);
  res.send('payment_not_completed');
}

  } catch (error) {
     
        console.log(log_prefix + JSON.stringify(error)  + log_suffix);
        console.log(log_prefix + 'payment_not_completed' + log_suffix);
        res.send('payment_not_completed');
      }

    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }

 })

async function getCustomerName(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return customer_name_D0;
  }
  else if(hostname == DOMAIN_1)
  {
    return customer_name_D1;
  }
  else if(hostname == DOMAIN_2)
  {
    return customer_name_D2;
  }
  else if(hostname == DOMAIN_3)
  {
    return  customer_name_D3;
  } else if(config[host]) {
    if(config[host].CUSTOMERNAME) {
      return config[host].CUSTOMERNAME;
    }
  }
  
  return '';
  
}

async function getDomainFont(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return DOMAIN_0_FONT_NAME;
  }
  else if(hostname == DOMAIN_1)
  {
    return DOMAIN_1_FONT_NAME;
  }
  else if(hostname == DOMAIN_2)
  {
    return DOMAIN_2_FONT_NAME;
  }
  else if(hostname == DOMAIN_3)
  {
    return  DOMAIN_3_FONT_NAME;
  } else if(config[host]) {
    if(config[host].FONT_NAME) {
      return config[host].FONT_NAME;
    }
  }
  
  return 'Century Gothic';
  
}


async function getProviderSortOrder(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return DOMAIN_0_SORT_ORDER;
  }
  else if(hostname == DOMAIN_1)
  {
    return DOMAIN_1_SORT_ORDER;
  }
  else if(hostname == DOMAIN_2)
  {
    return DOMAIN_2_SORT_ORDER;
  }
  else if(hostname == DOMAIN_3)
  {
    return  DOMAIN_3_SORT_ORDER;
  } 
  else if(config[host]) {
    if(config[host].SORT_ORDER) {
      return config[host].SORT_ORDER;
    }
  }
 
  return 'F';
  
}

async function getAnalyticsAllowed(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return DOMAIN_0_GOOGLE_ANALYTICS;
  }
  else if(hostname == DOMAIN_1)
  {
    return DOMAIN_1_GOOGLE_ANALYTICS;
  }
  else if(hostname == DOMAIN_2)
  {
    return DOMAIN_2_GOOGLE_ANALYTICS;
  }
  else if(hostname == DOMAIN_3)
  {
    return  DOMAIN_3_GOOGLE_ANALYTICS;
  }
  else if(config[host]) {
    if(config[host].google_analytics) {
      return config[host].google_analytics;
    }
  }
  
  return 'no';
  

}




async function getGooglePassAllowed(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return DOMAIN_0_GOOGLE_PASS;
  }
  else if(hostname == DOMAIN_1)
  {
    return DOMAIN_1_GOOGLE_PASS;
  }
  else if(hostname == DOMAIN_2)
  {
    return DOMAIN_2_GOOGLE_PASS;
  }
  else if(hostname == DOMAIN_3)
  {
    return  DOMAIN_3_GOOGLE_PASS;
  }
  else if(config[host]) {
    if(config[host].GOOGLE_PASS) {
      return config[host].GOOGLE_PASS;
    }
  }
  
  return 'no';
  

}

async function getApplePassAllowed(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return DOMAIN_0_APPLE_PASS;
  }
  else if(hostname == DOMAIN_1)
  {
    return DOMAIN_1_APPLE_PASS;
  }
  else if(hostname == DOMAIN_2)
  {
    return DOMAIN_2_APPLE_PASS;
  }
  else if(hostname == DOMAIN_3)
  {
    return  DOMAIN_3_APPLE_PASS;
  }
  else if(config[host]) {
    if(config[host].APPLE_PASS) {
      return config[host].APPLE_PASS;
    }
  }

  return 'no';
  

}

async function getSortInfo(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return DOMAIN_0_SORT_INFO;
  }
  else if(hostname == DOMAIN_1)
  {
    return DOMAIN_1_SORT_INFO;
  }
  else if(hostname == DOMAIN_2)
  {
    return DOMAIN_2_SORT_INFO;
  }
  else if(hostname == DOMAIN_3)
  {
    return  DOMAIN_3_SORT_INFO;
  }
  else if(config[host]) {

    let sort_info = '';
      if(config[host].SORT_ORDER_PROVIDER) {
        sort_info = config[host].SORT_ORDER_PROVIDER;
      }

      sort_info = sort_info + '::::';

      if(config[host].SORT_ORDER_PRODUCT) {
        sort_info = sort_info + config[host].SORT_ORDER_PRODUCT;
      }

      sort_info = sort_info + '::::';
      if(config[host].HIGHLIGHT_EAN) {
      let reverse_str = config[host].HIGHLIGHT_EAN;
      
      if(config[host].HIGHLIGHT_EAN.includes(',')) {        
        let tokens = config[host].HIGHLIGHT_EAN.split( "," );        
        reverse_str = tokens.reverse().join(",");
      }

      sort_info = sort_info + reverse_str;
      }

      sort_info = sort_info + '::::';
      if(config[host].HIGHLIGHT_EAN_BACKGROUND) {
        sort_info = sort_info + config[host].HIGHLIGHT_EAN_BACKGROUND;
      }

      return sort_info;
    
  }
  else {
    return '';
  }

}

async function getDomainSupportUrl(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
    return domain1_support_url;
  }
  else if(hostname == DOMAIN_2)
  {
    return domain2_support_url;
  }
  else if(hostname == DOMAIN_3)
  {
    return domain3_support_url;
  }
  else if(hostname == DOMAIN_0)
  {
    return domain0_support_url;
  } 
  else if(config[host]) {
    if(config[host].CUSTOMERSUPPORT) {
      return config[host].CUSTOMERSUPPORT;
    }
  }
 
  return '';
  
}


async function getDomainHIGHLIGHTProviders(hostname) {

  let result = '';
  let host = (hostname.split('.'))[0];

  if(hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].HIGHLIGHT_PROVIDERS) {
      result = config['domain_1'].HIGHLIGHT_PROVIDERS;
    }
   }
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].HIGHLIGHT_PROVIDERS) {
        result = config['domain_2'].HIGHLIGHT_PROVIDERS;
      }
    }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].HIGHLIGHT_PROVIDERS) {
        result = config['domain_3'].HIGHLIGHT_PROVIDERS;
      }
    }
  }
  else if(hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].HIGHLIGHT_PROVIDERS) {
        result = config['domain_0'].HIGHLIGHT_PROVIDERS;
      }
    }
  } 
  else if(config[host]) {
    if(config[host].HIGHLIGHT_PROVIDERS) {
      result = config[host].HIGHLIGHT_PROVIDERS;
    }
  }

  return result;

}

async function getProxyCodeAllowed(hostname) {

  let result = 'no'
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].PROXY_CODE_ALLOWED) {
      result = config['domain_1'].PROXY_CODE_ALLOWED;
    }
   }
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].PROXY_CODE_ALLOWED) {
        result = config['domain_2'].PROXY_CODE_ALLOWED;
      }
    }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].PROXY_CODE_ALLOWED) {
        result = config['domain_3'].PROXY_CODE_ALLOWED;
      }
    }
  }
  else if(hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].PROXY_CODE_ALLOWED) {
        result = config['domain_0'].PROXY_CODE_ALLOWED;
      }
    }
  }
  else if(config[host]) {
    if(config[host].PROXY_CODE_ALLOWED) {
      result = config[host].PROXY_CODE_ALLOWED;
    }
  }

  return result;

}

async function getDomainIdleTimeout(hostname) {

  let result = ''
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].IDLE_TIMEOUT) {
      result = config['domain_1'].IDLE_TIMEOUT;
    }
   }
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].IDLE_TIMEOUT) {
        result = config['domain_2'].IDLE_TIMEOUT;
      }
    }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].IDLE_TIMEOUT) {
        result = config['domain_3'].IDLE_TIMEOUT;
      }
    }
  }
  else if(hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].IDLE_TIMEOUT) {
        result = config['domain_0'].IDLE_TIMEOUT;
      }
    }
  }
  else if(config[host]) {
    if(config[host].IDLE_TIMEOUT) {
      result = config[host].IDLE_TIMEOUT;
    }
  }

  return result;

}
//DOMAIN_FOOTER_L_NAME + DOMAIN_FOOTER_R_NAME + DOMAIN_FOOTER_L_LINK + DOMAIN_FOOTER_R_LINK ;
async function getDomainConfig(req) {
  let host = (req.hostname.split('.'))[0];
  //if(req.hostname == DOMAIN_0 || isTest) {
  if(req.hostname == DOMAIN_0) {
     let result = config['domain_0'];
     result['DOMAIN_TITLE'] = DOMAIN_0_TITLE;
     result['DOMAIN_FOOTER_L_NAME'] = DOMAIN_0_FOOTER_L_NAME;
     result['DOMAIN_FOOTER_R_NAME'] = DOMAIN_0_FOOTER_R_NAME;
     result['DOMAIN_FOOTER_L_LINK'] = DOMAIN_0_FOOTER_L_LINK;
     result['DOMAIN_FOOTER_R_LINK'] = DOMAIN_0_FOOTER_R_LINK;
     return result;

  } else if(req.hostname == DOMAIN_1) {

    let result = config['domain_1'];
     result['DOMAIN_TITLE'] = DOMAIN_1_TITLE;
     result['DOMAIN_FOOTER_L_NAME'] = DOMAIN_1_FOOTER_L_NAME;
     result['DOMAIN_FOOTER_R_NAME'] = DOMAIN_1_FOOTER_R_NAME;
     result['DOMAIN_FOOTER_L_LINK'] = DOMAIN_1_FOOTER_L_LINK;
     result['DOMAIN_FOOTER_R_LINK'] = DOMAIN_1_FOOTER_R_LINK;
     return result;

  } else if(req.hostname == DOMAIN_2) {

    let result = config['domain_2'];
     result['DOMAIN_TITLE'] = DOMAIN_2_TITLE;
     result['DOMAIN_FOOTER_L_NAME'] = DOMAIN_2_FOOTER_L_NAME;
     result['DOMAIN_FOOTER_R_NAME'] = DOMAIN_2_FOOTER_R_NAME;
     result['DOMAIN_FOOTER_L_LINK'] = DOMAIN_2_FOOTER_L_LINK;
     result['DOMAIN_FOOTER_R_LINK'] = DOMAIN_2_FOOTER_R_LINK;
     return result;

  } else if(req.hostname == DOMAIN_3) {

    let result = config['domain_3'];
     result['DOMAIN_TITLE'] = DOMAIN_0_TITLE;
     result['DOMAIN_FOOTER_L_NAME'] = DOMAIN_3_FOOTER_L_NAME;
     result['DOMAIN_FOOTER_R_NAME'] = DOMAIN_3_FOOTER_R_NAME;
     result['DOMAIN_FOOTER_L_LINK'] = DOMAIN_3_FOOTER_L_LINK;
     result['DOMAIN_FOOTER_R_LINK'] = DOMAIN_3_FOOTER_R_LINK;
     return result;

  } else  if(config[host]) {
    return config[host];
  } else {
    console.log('Domain not available');
    return null;
  }
}

async function getProviderOverrrideList(req) {

  let result = '';
  let host = (req.hostname.split('.'))[0];
  if(req.hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].PROVIDER_LOGO_OVERRIDE) {
      result = config['domain_1'].PROVIDER_LOGO_OVERRIDE;
    }
   }
  }
  else if(req.hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].PROVIDER_LOGO_OVERRIDE) {
        result = config['domain_2'].PROVIDER_LOGO_OVERRIDE;
      }
    }
  }
  else if(req.hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].PROVIDER_LOGO_OVERRIDE) {
        result = config['domain_3'].PROVIDER_LOGO_OVERRIDE;
      }
    }
  }
  else if(req.hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].PROVIDER_LOGO_OVERRIDE) {
        result = config['domain_0'].PROVIDER_LOGO_OVERRIDE;
      }
    }
  }
  else if(config[host]) {
    if(config[host].PROVIDER_LOGO_OVERRIDE) {
      result = config[host].PROVIDER_LOGO_OVERRIDE;
    }
  }

  if(result) {
   
    result = result.join('<||>');
  }

  return result;

}

async function getIncentiveProviderProductList(req) {

  let result = '';
  let host = (req.hostname.split('.'))[0];
  if(req.hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].INCENTIVE_PRODUCT_LIST) {
      result = config['domain_1'].INCENTIVE_PRODUCT_LIST;
    }
   }
  }
  else if(req.hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].INCENTIVE_PRODUCT_LIST) {
        result = config['domain_2'].INCENTIVE_PRODUCT_LIST;
      }
    }
  }
  else if(req.hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].INCENTIVE_PRODUCT_LIST) {
        result = config['domain_3'].INCENTIVE_PRODUCT_LIST;
      }
    }
  }
  else if(req.hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].INCENTIVE_PRODUCT_LIST) {
        result = config['domain_0'].INCENTIVE_PRODUCT_LIST;
      }
    }
  }
  else if(config[host]) {
    if(config[host].INCENTIVE_PRODUCT_LIST) {
      result = config[host].INCENTIVE_PRODUCT_LIST;
    }
  }

  if(result) {
   
    result = JSON.stringify(result);
  }

  return result;

}

async function getIncentiveRetailerList(req) {

  let result = '';
  let host = (req.hostname.split('.'))[0];
  if(req.hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
    if(config['domain_1'].INCENTIVE_RETAILER_LIST) {
      result = config['domain_1'].INCENTIVE_RETAILER_LIST;
    }
   }
  }
  else if(req.hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].INCENTIVE_RETAILER_LIST) {
        result = config['domain_2'].INCENTIVE_RETAILER_LIST;
      }
    }
  }
  else if(req.hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].INCENTIVE_RETAILER_LIST) {
        result = config['domain_3'].INCENTIVE_RETAILER_LIST;
      }
    }
  }
  else if(req.hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
      if(config['domain_0'].INCENTIVE_RETAILER_LIST) {
        result = config['domain_0'].INCENTIVE_RETAILER_LIST;
      }
    }
  }
  else if(config[host]) {
    if(config[host].INCENTIVE_RETAILER_LIST) {
      result = config[host].INCENTIVE_RETAILER_LIST;
    }
  }

  return result;

}

///////////////////////////INFOBIP NEW CORRIDORE///////////////////////////

async function getDomainSuccessSMS(req) {   


  let hostname =  req.hostname;
  let result = 'Your card <articlePlaceholder> has been successfully purchased. Your pin is <pinPlaceholder>. Serial number of your giftcard is <serialNumberPlaceholder>. You can also redeem here <urlPlaceholder>';
  let host = (hostname.split('.'))[0];

  if(hostname == DOMAIN_1)
  {
    if(config['domain_1']) {
      if(config['domain_1'].SUCCESS_ORDER_SMS) {
        result =  config['domain_1'].SUCCESS_ORDER_SMS;
      }
    }
    
  }
  else if(hostname == DOMAIN_2)
  {
    if(config['domain_2']) {
      if(config['domain_2'].SUCCESS_ORDER_SMS) {
        result =  config['domain_2'].SUCCESS_ORDER_SMS;
      }
    }
  }
  else if(hostname == DOMAIN_3)
  {
    if(config['domain_3']) {
      if(config['domain_3'].SUCCESS_ORDER_SMS) {
        result =  config['domain_3'].SUCCESS_ORDER_SMS;
      }
    }
  }
  else if(hostname == DOMAIN_0)
  {
    if(config['domain_0']) {
        if(config['domain_0'].SUCCESS_ORDER_SMS) {
          result =  config['domain_0'].SUCCESS_ORDER_SMS;
        }
    }
  } 
  else if(config[host]) {
    if(config[host].SUCCESS_ORDER_SMS) {
      result = config[host].SUCCESS_ORDER_SMS;
    }
  }
 
  return result;

}


 
async function getDomainInfoBipCredential(req) {

  let obj = {
    "infobipAuth":infobipAuth,
    "infobip_msg_sender":infobip_msg_sender,
    "infobipURL":infobipURL
  }

  let host = (req.hostname.split('.'))[0];
  let section = 'infobip';
  if (req.hostname.includes(DOMAIN_3)) {
    if(config['domain_3'].infoBipSection)
      section = config['domain_3'].infoBipSection;
  }
  else if(req.hostname.includes(DOMAIN_2))
  {
    if(config['domain_2'].infoBipSection)
     section = config['domain_2'].infoBipSection;
    
  }
  else if (req.hostname.includes(DOMAIN_1)) {     
     if(config['domain_1'].infoBipSection)
      section = config['domain_1'].infoBipSection;
  }
  else if (req.hostname.includes(DOMAIN_0)) {     
    if(config['domain_0'].infoBipSection)
     section = config['domain_0'].infoBipSection;
  }
  else if (config[host]) {    
   if(config[host].infoBipSection)
      section = config[host].infoBipSection;     
  }
  
  if(config[section]) {
    let objTemp = {};
    if(config[section].infobipAuth) {
      objTemp["infobipAuth"] = config[section].infobipAuth;
      
      if(config[section].infobipAuth.length > 5) {
          if(config[section].infobipAuth.substring(0,5) == '!PWD!') {
             objTemp["infobipAuth"] = decrypt_pwd(config[section].infobipAuth.substring(5,config[section].infobipAuth.length),PWD_SECRET_KEY,PWD_IV);
          }
      }
    }
    if(config[section].infobipURL) {
      objTemp["infobipURL"] = config[section].infobipURL;
    }
    if(config[section].sender) {
      objTemp["infobip_msg_sender"] = config[section].sender;
    } else {
      objTemp["infobip_msg_sender"] = "epay";
    }

    if(objTemp["infobipURL"] && objTemp["infobipAuth"] && objTemp["infobip_msg_sender"]) {
        obj = JSON.parse(JSON.stringify(objTemp))
    } else {
      return null;
    }
  }

  return obj;
  
}


async function sendOrderSuccessMessage_ib(response,phone,req,log_prefix,log_suffix)
{

  let product = '';
  let pin = '';
  let serial = '';
  let url = '';

  if(!response.includes('<RESULT>0</RESULT>')) {
        return;
  }

  try {

      let del_mode = getDeliveryMode(req.hostname,null);

      if(!del_mode.includes("SMS")) {
        console.log(log_prefix + "SMS not enabled." +  log_suffix)
        return;
      }

      if(response.includes('<PIN>')) {
        let a = response.split('<PIN>');
        let b = a[1].split('</PIN>');
        pin = b[0];
      }

      if(response.includes('<SERIAL>')) {
        let a = response.split('<SERIAL>');
        let b = a[1].split('</SERIAL>');
        serial = b[0];
      }

      if(response.includes('<PRODUCT>')) {
        let a = response.split('<PRODUCT>');
        let b = a[1].split('</PRODUCT>');
        product = b[0];
      }

      if(response.includes('<DATA name="REDEMPTIONURL">')) {
        let a = response.split('<DATA name="REDEMPTIONURL">');
        let b = a[1].split('</DATA>');
        url = b[0];
      } else if(response.includes('<REDEMPTIONURL>')) {
        let a = response.split('<REDEMPTIONURL>');
        let b = a[1].split('</REDEMPTIONURL>');
        url = b[0];
      } else if(response.includes('<DATA name="ProductDownloadUrl">')) {
        let a = response.split('<DATA name="ProductDownloadUrl">');
        let b = a[1].split('</DATA>');
        url = b[0];
      } else if(response.includes('<URL>')) {
        let a = response.split('<URL>');
        let b = a[1].split('</URL>');
        url = b[0];
      } else if(response.includes('<URLREDEEM>')) {
        let a = response.split('<URLREDEEM>');
        let b = a[1].split('</URLREDEEM>');
        url = b[0];
        if(url.substring((url.length-1) != '=')) {
          url = url + '=';
        }
        url = url + pin;
        if(!url.match(/^https?:\/\//i)) {
          url = 'https://' + url;
        }
        if(url.toLowerCase().includes('appstore')) {
           url = 'https://www.appstore.com/redeem/' + pin;
        }
      }

      

      let smsBody = await getDomainSuccessSMS(req);
      smsBody = smsBody.replace('<articlePlaceholder>',product);
      smsBody = smsBody.replace('<pinPlaceholder>',pin);
      smsBody = smsBody.replace('<serialNumberPlaceholder>',serial);
      smsBody = smsBody.replace('<urlPlaceholder>',url);


      let infoBipCred = await getDomainInfoBipCredential(req);
    
      let infobip_smsbody = '{"messages":[{"destinations":[{"to":"'+ phone +'"}], "from":"'+ infoBipCred.infobip_msg_sender + '","text":"' + smsBody + '"}]}';

      mask_json_data(infobip_smsbody,log_prefix,log_suffix);
      const fetchOptions = {
        method: 'POST',

        body: infobip_smsbody,

        headers: {
          'Authorization': 'App ' + infoBipCred.infobipAuth,  
          'Content-Type': 'application/json',
        },
        
      }

      let infobipSMSURL = infoBipCred.infobipURL;  

      var smsTimeout = setTimeout(() => console.log('SMS send time out'), 30000);
      try {
        console.log(log_prefix + 'Infobip SMS Request:' + infobipSMSURL + log_suffix);
        const response = await fetch(infobipSMSURL, fetchOptions,proxy_url);
        console.log(response.status);
        let jsonResponse = await response.json();
        
        clearTimeout(smsTimeout);
        mask_json_data(JSON.stringify(jsonResponse),log_prefix,log_suffix); 
      } catch(error) {
        console.log(log_prefix + 'SMS send exception' + log_suffix);
        console.log(log_prefix + JSON.stringify(error) + log_suffix);
      }

  } catch(error) {
      console.log(log_prefix + 'SMS processing exception' + log_suffix);
      console.log(log_prefix + JSON.stringify(error) + log_suffix);
  }

}


/////////////////////////INFOBIP NEW END///////////////////////////////////


app.get('/getDomains',  async (req, res) => {

  //Test code

  try{
 //  let result = await getDomainInfoBipCredential(req);
   console.log(result);

 }catch(err){
   console.log(err);
 }

  const clientip = req.headers['incap-client-ip'] ;
  
  console.log(req.headers.campaign + '>>API_CALL:getDomains => clientip: ' + clientip);
  console.log('config._TEST_: ' + isTest);
  console.log('Get domains: ' + JSON.stringify(req.headers));
  try {
  if(isTest){
     //req.headers.referer = 'localhost';
     //req.hostname = DOMAIN_0;
  }

  if(req.headers.referer) {
    console.log('req.headers.referer:'  + req.headers.referer);
    let domainInfo = await getDomainConfig(req);
    if(domainInfo == null) {
      res.send('KO');
    }
    console.log('domainInfo:');
    if (await checkIfRefererAllowed(req.headers.referer,req)) {

      let bVodacom = false; 
      if((await checkIfVodacomFlow(req.hostname)) == 'yes'){
        bVodacom = true;
      }


       let domainList = '';

        
        if(!req.query.version)
       {
        if(req.hostname == DOMAIN_0)
        {
          domainList = DOMAIN_0 + ','+ 'DOMAIN_1' + ',' + 'DOMAIN_2' + ',' + 'DOMAIN_3' + '::::' +
          domainInfo.DOMAIN_TITLE + ',' + 'DOMAIN_1_TITLE' + ',' + 'DOMAIN_2_TITLE' + ',' + 'DOMAIN_3_TITLE'  + '::::' +
          domainInfo.DOMAIN_FOOTER_L_NAME + ',' +  domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' +  domainInfo.DOMAIN_FOOTER_R_LINK  + '::::' +
          'DOMAIN_1_FOOTER_L_NAME' + ',' + 'DOMAIN_1_FOOTER_R_NAME' + ',' + 'DOMAIN_1_FOOTER_L_LINK' + ',' + 'DOMAIN_1_FOOTER_R_LINK'  + '::::' +
          'DOMAIN_2_FOOTER_L_NAME' + ',' + 'DOMAIN_2_FOOTER_R_NAME' + ',' + 'DOMAIN_2_FOOTER_L_LINK' + ',' + 'DOMAIN_2_FOOTER_R_LINK'  + '::::' +
          'DOMAIN_3_FOOTER_L_NAME' + ',' + 'DOMAIN_3_FOOTER_R_NAME' + ',' + 'DOMAIN_3_FOOTER_L_LINK' + ',' + 'DOMAIN_3_FOOTER_R_LINK';
        }
        else if(req.hostname == DOMAIN_1)
        {
          domainList = 'DOMAIN_0' + ','+ DOMAIN_1 + ',' + 'DOMAIN_2' + ',' + 'DOMAIN_3' + '::::' +
          'DOMAIN_0_TITLE' + ',' + domainInfo.DOMAIN_TITLE + ',' + 'DOMAIN_2_TITLE' + ',' + 'DOMAIN_3_TITLE'  + '::::' +
          'DOMAIN_0_FOOTER_L_NAME' + ',' + 'DOMAIN_0_FOOTER_R_NAME' + ',' + 'DOMAIN_0_FOOTER_L_LINK' + ',' + 'DOMAIN_0_FOOTER_R_LINK'  + '::::' +
          domainInfo.DOMAIN_FOOTER_L_NAME + ',' +  domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' +  domainInfo.DOMAIN_FOOTER_R_LINK  + '::::' +
          'DOMAIN_2_FOOTER_L_NAME' + ',' + 'DOMAIN_2_FOOTER_R_NAME' + ',' + 'DOMAIN_2_FOOTER_L_LINK' + ',' + 'DOMAIN_2_FOOTER_R_LINK'  + '::::' +
          'DOMAIN_3_FOOTER_L_NAME' + ',' + 'DOMAIN_3_FOOTER_R_NAME' + ',' + 'DOMAIN_3_FOOTER_L_LINK' + ',' + 'DOMAIN_3_FOOTER_R_LINK';
        }
        else if(req.hostname == DOMAIN_2)
        {
          domainList = 'DOMAIN_0' + ','+ 'DOMAIN_1' + ',' + DOMAIN_2 + ',' + 'DOMAIN_3' + '::::' +
          'DOMAIN_0_TITLE' + ',' + 'DOMAIN_1_TITLE' + ',' + domainInfo.DOMAIN_TITLE + ',' + 'DOMAIN_3_TITLE'  + '::::' +
          'DOMAIN_0_FOOTER_L_NAME' + ',' + 'DOMAIN_0_FOOTER_R_NAME' + ',' + 'DOMAIN_0_FOOTER_L_LINK' + ',' + 'DOMAIN_0_FOOTER_R_LINK'  + '::::' +
          'DOMAIN_1_FOOTER_L_NAME' + ',' + 'DOMAIN_1_FOOTER_R_NAME' + ',' + 'DOMAIN_1_FOOTER_L_LINK' + ',' + 'DOMAIN_1_FOOTER_R_LINK'  + '::::' +
          domainInfo.DOMAIN_FOOTER_L_NAME + ',' +  domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' +  domainInfo.DOMAIN_FOOTER_R_LINK  + '::::' +
          'DOMAIN_3_FOOTER_L_NAME' + ',' + 'DOMAIN_3_FOOTER_R_NAME' + ',' + 'DOMAIN_3_FOOTER_L_LINK' + ',' + 'DOMAIN_3_FOOTER_R_LINK';
        }
        else if(req.hostname == DOMAIN_3)
        {
          domainList = 'DOMAIN_0' + ','+ 'DOMAIN_1' + ',' + 'DOMAIN_2' + ',' + DOMAIN_3 + '::::' +
          'DOMAIN_0_TITLE' + ',' + 'DOMAIN_1_TITLE' + ',' + 'DOMAIN_2_TITLE' + ',' + domainInfo.DOMAIN_TITLE  + '::::' +
          'DOMAIN_0_FOOTER_L_NAME' + ',' + 'DOMAIN_0_FOOTER_R_NAME' + ',' + 'DOMAIN_0_FOOTER_L_LINK' + ',' + 'DOMAIN_0_FOOTER_R_LINK'  + '::::' +
          'DOMAIN_1_FOOTER_L_NAME' + ',' + 'DOMAIN_1_FOOTER_R_NAME' + ',' + 'DOMAIN_1_FOOTER_L_LINK' + ',' + 'DOMAIN_1_FOOTER_R_LINK'  + '::::' +
          'DOMAIN_2_FOOTER_L_NAME' + ',' + 'DOMAIN_2_FOOTER_R_NAME' + ',' + 'DOMAIN_2_FOOTER_L_LINK' + ',' + 'DOMAIN_2_FOOTER_R_LINK'  + '::::' +
          domainInfo.DOMAIN_FOOTER_L_NAME + ',' +  domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' +  domainInfo.DOMAIN_FOOTER_R_LINK;
        } else if(domainInfo) {
            if(bVodacom) {

              domainList = 'DOMAIN_0' + ','+ 'DOMAIN_1' + ',' + req.hostname + ',' + 'DOMAIN_3' + '::::' +
              'DOMAIN_0_TITLE' + ',' + 'DOMAIN_1_TITLE' + ',' + domainInfo.DOMAIN_TITLE + ',' + 'DOMAIN_3_TITLE'  + '::::' +
              'DOMAIN_0_FOOTER_L_NAME' + ',' + 'DOMAIN_0_FOOTER_R_NAME' + ',' + 'DOMAIN_0_FOOTER_L_LINK' + ',' + 'DOMAIN_0_FOOTER_R_LINK'  + '::::' +
              'DOMAIN_1_FOOTER_L_NAME' + ',' + 'DOMAIN_1_FOOTER_R_NAME' + ',' + 'DOMAIN_1_FOOTER_L_LINK' + ',' + 'DOMAIN_1_FOOTER_R_LINK'  + '::::' +
              domainInfo.DOMAIN_FOOTER_L_NAME + ',' +  domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' +  domainInfo.DOMAIN_FOOTER_R_LINK  + '::::' +
              'DOMAIN_3_FOOTER_L_NAME' + ',' + 'DOMAIN_3_FOOTER_R_NAME' + ',' + 'DOMAIN_3_FOOTER_L_LINK' + ',' + 'DOMAIN_3_FOOTER_R_LINK';
       

            } else {

              domainList = 'DOMAIN_0' + ','+ req.hostname + ',' + 'DOMAIN_2' + ',' + 'DOMAIN_3' + '::::' +
              'DOMAIN_0_TITLE' + ',' + domainInfo.DOMAIN_TITLE + ',' + 'DOMAIN_2_TITLE' + ',' + 'DOMAIN_3_TITLE'  + '::::' +
              'DOMAIN_0_FOOTER_L_NAME' + ',' + 'DOMAIN_0_FOOTER_R_NAME' + ',' + 'DOMAIN_0_FOOTER_L_LINK' + ',' + 'DOMAIN_0_FOOTER_R_LINK'  + '::::' +
              domainInfo.DOMAIN_FOOTER_L_NAME + ',' +  domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' +  domainInfo.DOMAIN_FOOTER_R_LINK  + '::::' +
              'DOMAIN_2_FOOTER_L_NAME' + ',' + 'DOMAIN_2_FOOTER_R_NAME' + ',' + 'DOMAIN_2_FOOTER_L_LINK' + ',' + 'DOMAIN_2_FOOTER_R_LINK'  + '::::' +
              'DOMAIN_3_FOOTER_L_NAME' + ',' + 'DOMAIN_3_FOOTER_R_NAME' + ',' + 'DOMAIN_3_FOOTER_L_LINK' + ',' + 'DOMAIN_3_FOOTER_R_LINK';
       

            }
        }
       } else {
        if(req.hostname == DOMAIN_0)
        {
            domainList = DOMAIN_0 + ',0::::' + DOMAIN_0_TITLE + '::::' + 
            DOMAIN_0_FOOTER_L_NAME + ',' + DOMAIN_0_FOOTER_R_NAME + ',' + DOMAIN_0_FOOTER_L_LINK + ',' + DOMAIN_0_FOOTER_R_LINK +
            '::::::::::::';

        } else if(req.hostname == DOMAIN_1) {
          domainList = DOMAIN_1 + ',1::::' + DOMAIN_1_TITLE + '::::::::' + 
          DOMAIN_1_FOOTER_L_NAME + ',' + DOMAIN_1_FOOTER_R_NAME + ',' + DOMAIN_1_FOOTER_L_LINK + ',' + DOMAIN_1_FOOTER_R_LINK +
          '::::::::';

        } else if(req.hostname == DOMAIN_2) {

          domainList = DOMAIN_2 + ',2::::' + DOMAIN_2_TITLE + '::::::::::::' + 
          DOMAIN_2_FOOTER_L_NAME + ',' + DOMAIN_2_FOOTER_R_NAME + ',' + DOMAIN_2_FOOTER_L_LINK + ',' + DOMAIN_2_FOOTER_R_LINK +
          '::::';
          
        } else if(req.hostname == DOMAIN_3) {
          domainList = DOMAIN_3 + ',3::::' + DOMAIN_3_TITLE + '::::::::::::::::' + 
          DOMAIN_3_FOOTER_L_NAME + ',' + DOMAIN_3_FOOTER_R_NAME + ',' + DOMAIN_3_FOOTER_L_LINK + ',' + DOMAIN_3_FOOTER_R_LINK ;
        } else if((config[(req.hostname.split('.'))[0]])) {
          if(await checkIfVodacomFlow(req.hostname) == 'yes') {
          domainList = req.hostname + ',2::::' + domainInfo.DOMAIN_TITLE + '::::::::::::::::' + 
          domainInfo.DOMAIN_FOOTER_L_NAME + ',' + domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' + domainInfo.DOMAIN_FOOTER_R_LINK ;
         } else {
          domainList = req.hostname + ',2::::' + domainInfo.DOMAIN_TITLE + '::::::::::::::::' + 
          domainInfo.DOMAIN_FOOTER_L_NAME + ',' + domainInfo.DOMAIN_FOOTER_R_NAME + ',' + domainInfo.DOMAIN_FOOTER_L_LINK + ',' + domainInfo.DOMAIN_FOOTER_R_LINK ;
        
         }
        }
        

       }

        
        domainList = domainList + '::::' + redeem_option ;
        let domain_logo = await getDomainLogo(req.hostname) ;

        if(TEST_IP_AZURE == clientip) {
          if((req.headers.referer.includes('/akani'))||(req.headers.referer.includes('/alt1')))
          {
              domain_logo = 'https://endlessaisle.epayworldwide.com/static/media/logos/akani.jpg';
          }
          if(req.headers.referer.includes('/samsungcare')) {
            domain_logo = 'https://endlessaisle.epayworldwide.com/static/media/logos/samsungcareplus.jpg';

          }
          if((req.headers.referer.includes('/mcafee'))||(req.headers.referer.includes('/alt'))) {
            domain_logo = 'https://endlessaisle.epayworldwide.com/static/media/logos/mcafee.png';
            domainList = domainList.replace("epay's endless aisle","McAfee redeem code");

          }

        }
        
        domainList = domainList + '::::' + domain_logo;
        let domain_theme = await getDomainTheme(req.hostname) ;

///////////////////////////
//if(TEST_IP_AZURE == clientip) {
  if(req.query.infoJson) { 
    domain_theme = "#0066CC,#E94E1B,#F39200,#F26B40,#F26B40,#FA9600,#F26B40,#E6E6EA,#E6E6EA,#0066CC,#0066CC,6,#242422,#E94E1B,#70C62D,#3D513B,#E6E6EA,#0066CC,0,redeem-account-language-info,0";         

  
  }

  if((req.headers.referer.includes('/carrefour'))||(req.headers.referer.includes('/alt1'))) { 
    domain_theme = "#0E5AA7,black,#F4F4F4,#0E5AA7,#0E5AA7,#0E5AA7,#0E5AA7,#E2EBF4,#E2EBF4,#0E5AA7,#0E5AA7,12,#505050,#9E292A,#319E60,#505050,#F4F4F4,#505050,0,1,1,#FAFAFB,#C7EBF9,#FFFFFF";         

  domainList = domainList.replace("epay's endless aisle","Carrefour's endless aisle");
  }

  if(req.headers.referer.includes('/samsungcare')) { 
    domain_theme = "#0E5AA7,#E30613,#F4F4F4,black,black,black,black,#E6E6EA,#E6E6EA,#0E5AA7,#0E5AA7,4,#505050,#9E292A,#319E60,#505050,#F4F4F4,#505050,0,1,1,#FAFAFB,#C7EBF9,#FFFFFF";
    domainList = domainList.replace("epay's endless aisle","Samsung Care+");

  }

  if(req.headers.referer.includes('/turkey')) {
    domainList = domainList.replace("epay's endless aisle","Turkey's endless aisle");
  }
//}
///////////////////////////

        domainList = domainList + '::::' + domain_theme;
        let domain_country_code = await getCountryCode(req.hostname) ;
////////////////////////////////
       if(TEST_IP_AZURE == clientip) {
        if(req.headers.referer.includes('/akani'))
          {
             domain_country_code = 'ZA';
          }
        }
///////////////////////////////
        domainList = domainList + '::::' + domain_country_code;

        let paysupported = await getPaymentMethods(req.hostname);
        if(TEST_IP_AZURE == clientip) {
        if((req.headers.referer.includes('/akani'))||(req.headers.referer.includes('/alt'))||(req.headers.referer.includes('/carrefour')))
          {
             if(req.headers.referer.includes('/akani'))
               paysupported = 'akani';
             else 
                paysupported = 'checkout,gpay,apay';          
          }
  
  ////////////////////////////////////////
          if(!req.headers.referer.includes('/akani')) { 
            paysupported = paysupported.replace(',akani','')
          }
        }
  ///////////////////////////////////////


        domainList = domainList + '::::' + paysupported;

        let customer = await getCustomerName(req.hostname);
        domainList = domainList + '::::' + customer;

        let font = await getDomainFont(req.hostname);
        domainList = domainList + '::::' + font;

        let sort_order = await getProviderSortOrder(req.hostname);
        domainList = domainList + '::::' + sort_order;

        let google_analytics = await getAnalyticsAllowed(req.hostname);
        domainList = domainList + '::::' + google_analytics;
        

        let apple_pass_allowed = await getApplePassAllowed(req.hostname);
        domainList = domainList + '::::' + apple_pass_allowed;

        let google_pass_allowed = await getGooglePassAllowed(req.hostname);
        domainList = domainList + '::::' + google_pass_allowed;


        let sortInfo = await getSortInfo(req.hostname);
        domainList = domainList + '::::' + sortInfo;
        
        let support_url = await getDomainSupportUrl(req.hostname);
        domainList = domainList + '::::' + support_url;

        let HIGHLIGHT_PROVIDERS = await getDomainHIGHLIGHTProviders(req.hostname);
        domainList = domainList + '::::' + HIGHLIGHT_PROVIDERS;
        
        let IDLE_TIMEOUT = await getDomainIdleTimeout(req.hostname);
        domainList = domainList + '::::' + IDLE_TIMEOUT;

        let promo_sale = await isPromoPeriodApplicable(req);
        domainList = domainList + '::::' + promo_sale;

        let proxy_code = await getProxyCodeAllowed(req.hostname);
        domainList = domainList + '::::' + proxy_code;

        let provider_overrrides = await getProviderOverrrideList(req);
        domainList = domainList + '::::' + provider_overrrides;

        let languages = await getSupportedLanguages(req);
        if(req.headers.referer.includes('/turkey')){
          languages = "tr";
        }
        domainList = domainList + '::::' + languages;
        
        let language_data = '';

        if(req.query.infoJson) {
          language_data = await getLanguagesTranslationDatas(req,languages);          
        }

        domainList = domainList + '::::' + language_data;

         let IncentiveProductList = await getIncentiveProviderProductList(req)
         domainList = domainList + '::::' + IncentiveProductList;

         let IncentiveRetailerList = await getIncentiveRetailerList(req)
         domainList = domainList + '::::' + IncentiveRetailerList;

         let defaultTID =  getDefaultTID(req.hostname,req);
        domainList = domainList + '::::' + defaultTID;

         // console.log('DomainList: ' + domainList );
          
          res.send(domainList);

        } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
      } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } catch (err) {
    console.log(err);
    res.send('Exception in getDomains request');
  }

});

async function getCashierConfig(hostname) {
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    return cashier_allowed_domain0;
  }
  else if(hostname == DOMAIN_1)
  {
    return cashier_allowed_domain1;
  }
  else if(hostname == DOMAIN_2)
  {
    return cashier_allowed_domain2;
  }
  else if(hostname == DOMAIN_3)
  {
    return cashier_allowed_domain3;
  }
  else if(config[host]) {
    if(config[host].CASHIER) {
      return config[host].CASHIER;
    }
  }
  else 
    return '0';
}

function getDeliveryMode(hostname,mode)
{
  let delivery = '';
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0)
  {
    delivery = domain0_delivery_mode;
  }
  else if(hostname == DOMAIN_1)
  {
    delivery = domain1_delivery_mode;
  }
  else if(hostname == DOMAIN_2)
  {
    delivery = domain2_delivery_mode;
  }
  else if(hostname == DOMAIN_3)
  {
    delivery = domain3_delivery_mode;
  } 
  else if(config[host]) {
    if(config[host].DELIVERY_MODE) {
      delivery = config[host].DELIVERY_MODE;
    }
  }
  if(delivery.includes('EMAIL')&&delivery.includes('SMS')&&(mode)) {

    if(mode=='0') {
      delivery = 'EMAIL';
    }
    else if(mode=='1') {
      delivery = 'SMS';      
    }
    else if(mode=='2') {
      delivery = 'EMAIL,SMS';
    }

  }
  return delivery;
}


let g_measurementId = '07WBJJKZL7';
let g_secret_key = 'CToLrZIOT7mbo-mc3FzP0A';

let DOMAIN_0_GOOGLE_ANALYTICS = 'no';
let DOMAIN_1_GOOGLE_ANALYTICS = 'no';
let DOMAIN_2_GOOGLE_ANALYTICS = 'no';
let DOMAIN_3_GOOGLE_ANALYTICS = 'no';

let DOMAIN_0_GOOGLE_MEASUREMENT_ID = 'none';
let DOMAIN_1_GOOGLE_MEASUREMENT_ID = 'none';
let DOMAIN_2_GOOGLE_MEASUREMENT_ID = 'none';
let DOMAIN_3_GOOGLE_MEASUREMENT_ID = 'none';

let DOMAIN_0_GOOGLE_API_SECRET = 'none';
let DOMAIN_1_GOOGLE_API_SECRET = 'none';
let DOMAIN_2_GOOGLE_API_SECRET = 'none';
let DOMAIN_3_GOOGLE_API_SECRET = 'none';

async function getEANProductName(req,ean) {
  let product = ean;
  try {
    let TID = getDefaultTID(req.hostname,req)
    let blockToParse = await getCatalog(req.hostname,TID,ean,0,req);      
            
    if(blockToParse != 'no_data')
    {
        
        let desc_info = await getDescriptionInfo(blockToParse,req.hostname,ean,req);
        if(desc_info.includes('<PRODUCT_INFO>')) {

          let arr = desc_info.split('<PRODUCT_INFO>');
          let arr1 = arr[1].split('</PRODUCT_INFO>');
          product = arr1[0];

        }
    }
  }catch(err) {
    console.log(err);
  }

  return product;
  
}



async function getPurchaseGA4Payload(data,clientId,sessionId,req) {
  let currencycode = 'AED';
   let country_code = await getCountryCode(req.hostname);
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    } else if(country_code == 'TR') {
      currencycode = 'TRY';
    } else if(country_code == 'SA') {
      currencycode = 'SAR';
    }

  let productEAN = data.product;
  if(data.product.length == 0) {
    productEAN = await getEANProductName(req,data.ean);
  }
  let payload_purchase = {
    "client_id": clientId,
    "events": [
      {
        "name": "purchase",
        "params": {
          "items": [
            {
              "item_name": productEAN,// data.product, // Name or ID of the product
              "item_id": data.ean, // SKU or ID of the product
              "price": Number(data.amount), // Price of the product
              "quantity": 1    // Number(data.qty) // Quantity of the product
              
            }
          ],
          "currency": currencycode,// data.currency,
          "transaction_id": data.reference,
          "session_id": sessionId,
          "value": Number(data.amount),
          "product": productEAN,//data.product, // Name or ID of the product
          "ean": data.ean, // SKU or ID of the product
          //"debug_mode": 1
        }
      }
    ]
  }
  return payload_purchase;
}

async function getRefundGA4Payload(data,clientId,sessionId,req) {

  let currencycode = 'AED';
   let country_code = await getCountryCode(req.hostname);
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    } else if(country_code == 'TR') {
      currencycode = 'TRY';
    } else if(country_code == 'SA') {
      currencycode = 'SAR';
    }

  let payload_refund = {
    "client_id": clientId,
    "events": [
      {
        "name": "refund",
        "params": {
          "items": [
            {
              "item_name": data.product, // Name or ID of the product
              "item_id": data.ean, // SKU or ID of the product           
              
            }
          ],
          "currency": currencycode,// data.currency,
          "transaction_id": data.reference,
          "session_id": sessionId,
          "value": Number(data.amount),
          //"debug_mode": 1
        }
      }
    ]
  }
  return payload_refund;
}

async function getViewItemListGA4Payload(data,clientId,sessionId,req) {
  
  let payload_view_item_list = {
    "client_id": clientId,
    "events": [
      {
        "name": "view_item_list",
        "params": {
          "item_id": data.tid,
          "item_name":data.brand,//data.customer,
          "items": [
            {
              "item_id": data.tid, // Name or ID of the product
              "item_name":data.brand,                           
            }
          ],
          "session_id": sessionId,  
        }
      }
    ]
  }
  return payload_view_item_list;
}

async function getViewItemGA4Payload(data,clientId,sessionId,req) {
  let currencycode = 'AED';
   let country_code = await getCountryCode(req.hostname);
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    } else if(country_code == 'TR') {
      currencycode = 'TRY';
    } else if(country_code == 'SA') {
      currencycode = 'SAR';
    }

  let payload_view_item = {
    "client_id": clientId,
    "events": [
      {
        "name": "view_item",
        "params": {
          "currency":currencycode,//data.currency,
          "value":Number(data.amount),
          "product":data.product,
          "ean": data.ean,
          "items": [
            {              
              "item_id": data.ean, // Name or ID of the product
              "item_name":data.product,
              "item_brand":  data.brand, // SKU or ID of the product   
              "price":Number(data.amount),
              "item_category":data.type,           
            }
          ],
          "session_id": sessionId,  
        }
      }
    ]
  }
  return payload_view_item;
}

async function getBeginCheckoutGA4Payload(data,clientId,sessionId,req) {
  let currencycode = 'AED';
   let country_code = await getCountryCode(req.hostname);
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    } else if(country_code == 'TR') {
      currencycode = 'TRY';
    } else if(country_code == 'SA') {
      currencycode = 'SAR';
    }
  let payload_begin_checkout = {
    "client_id": clientId,
    "events": [
      {
        "name": "begin_checkout",
        "params": {
          "currency":currencycode,//data.currency,
          "value":Number(data.amount),
          "ean":data.ean,
          "product":data.product,
          "items": [
            {
              "item_id": data.ean, // Name or ID of the product
              "item_name":data.product,
              "price": Number(data.amount), // SKU or ID of the product              
            }
          ],
          "session_id": sessionId,  
        }
      }
    ]
  }
  return payload_begin_checkout;
}

async function getAddPaymentInfoGA4Payload(data,clientId,sessionId,req) {
  let currencycode = 'AED';
   let country_code = await getCountryCode(req.hostname);
    if(country_code == 'ZA') {
      currencycode = 'ZAR';
    } else if(country_code == 'TR') {
      currencycode = 'TRY';
    } else if(country_code == 'SA') {
      currencycode = 'SAR';
    }
  let payload_add_payment_info = {
    "client_id": clientId,
    "events": [
      {
        "name": "add_payment_info",
        "params": {
          "currency":currencycode,//"AED",
          "value":Number(data.amount),
          "payment_type":data.pay_type,
          "ean":data.ean,
          "product":data.product,
          "items": [
            {
              "item_id": data.ean, // Name or ID of the product
              "item_name":data.product,
              "price": Number(data.amount), // SKU or ID of the product              
            }
          ],
          "session_id": sessionId,  
        }
      }
    ]
  }
  return payload_add_payment_info;
}

async function getGoogleAnalyticsCredentials(hostname,req) {
  let measurement_id = 'none';
  let g_secret = 'none';
  let host = (hostname.split('.'))[0];
  if(hostname == DOMAIN_0) {
    measurement_id = DOMAIN_0_GOOGLE_MEASUREMENT_ID;
    g_secret = DOMAIN_0_GOOGLE_API_SECRET;
  } else if(hostname == DOMAIN_1) {
    measurement_id = DOMAIN_1_GOOGLE_MEASUREMENT_ID;
    g_secret = DOMAIN_1_GOOGLE_API_SECRET;
  } else if(hostname == DOMAIN_2) {
    measurement_id = DOMAIN_2_GOOGLE_MEASUREMENT_ID;
    g_secret = DOMAIN_2_GOOGLE_API_SECRET;
  } else if(hostname == DOMAIN_3) {
    measurement_id = DOMAIN_3_GOOGLE_MEASUREMENT_ID;
    g_secret = DOMAIN_3_GOOGLE_API_SECRET;
  } else if(config[host]) {
    if(config[host].g_measurementId) {
      measurement_id = config[host].g_measurementId;
    }
    if(config[host].g_api_secret) {
      g_secret = config[host].g_api_secret;
    }
  }
  let obj=[];
  obj.push({
    g_measurementId:measurement_id,
    g_secret_key:g_secret
  })

  return obj[0];
}

async function uploadGAnalytics(data,req,log_prefix,log_suffix) {
 try {
  let payload = '';
  let clientId = '';
  let sessionId = '';
  let cookie = req.headers.cookie;
  console.log('Request headers cookies: ' + cookie);
  let cred = await getGoogleAnalyticsCredentials(req.hostname,req)
  if((cred.g_measurementId != 'none')&&(cred.g_measurementId != 'none'))
  {
  let ga_mid_str = '_ga_' + cred.g_measurementId + '=';
  if((cookie.includes('_ga='))&&(cookie.includes(ga_mid_str)))
  {  
      let a = cookie.split(ga_mid_str);
      let a1 = a[1].split('.');
      sessionId = a1[2];
      console.log(log_prefix + 'sessionId: '+ sessionId + log_suffix);
      a = cookie.split('_ga=');
      a1 = a[1].split('.');
      clientId = a1[2]+'.'+a1[3];
      if(clientId.includes(';'))
      {
        clientId = (clientId.split(';'))[0];
      }
      console.log(log_prefix + 'clientId: '+ clientId + log_suffix); 

      if(data.event == 'purchase')
      { 
        payload = await getPurchaseGA4Payload(data,clientId,sessionId,req);  
      }else if(data.event == 'view_item_list') {
        payload = await getViewItemListGA4Payload(data,clientId,sessionId,req);

      }else if(data.event == 'view_item') {
        payload = await getViewItemGA4Payload(data,clientId,sessionId,req);

      }else if(data.event == 'begin_checkout') {
        payload = await getBeginCheckoutGA4Payload(data,clientId,sessionId,req);

      }else if(data.event == 'add_payment_info') {
        payload = await getAddPaymentInfoGA4Payload(data,clientId,sessionId,req);
      }
      else if(data.event == 'refund') {
        payload = await getRefundGA4Payload(data,clientId,sessionId,req);
      }

      console.log(log_prefix + 'Analytics payload: ' + JSON.stringify(payload) + log_suffix);

      let fetchOptions = {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: {
        'Content-Type': 'application/json',
        },

    }


    let gAnalyticsURL = 'https://www.google-analytics.com/mp/collect?api_secret=' + cred.g_secret_key + '&measurement_id=G-' + cred.g_measurementId;
    let gAnalyticsURL_log = 'https://www.google-analytics.com/mp/collect?api_secret=' + 'xxxxxxxxxxxxxxxxxxx' + '&measurement_id=G-' + cred.g_measurementId;

    console.log(log_prefix + 'Payload analytics ' + data.event + ': ' + gAnalyticsURL_log + log_suffix);
    console.log(JSON.stringify(fetchOptions.body));
    const response = await fetch(gAnalyticsURL, fetchOptions,proxy_url);
    console.log(log_prefix + 'Analytics response code: '+ response.status + log_suffix); 
    console.log(log_prefix + 'Analytics response: '+ JSON.stringify(response) + log_suffix);  
    var jsonResponse = await response.text(); 
    
     
  }
} else {
  console.log(log_prefix + 'GA4 credentials not available!'+log_suffix);
}

} catch (err) {
  console.log(log_prefix + err + log_suffix);
}
}

app.get('/getAnalytics', cors(corsOptions), async (req, res) => {
  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getAnalytics => clientip: ' + clientip);
  var txid = getTimeStamp();
  var x = Math.random() * 1000000;      
  var y = x.toString().split('.');      
  txid = txid + y[0];

  let session_id = txid;
  let host_log = req.hostname.split('.');
  let method = 'GOOGLE_ANALYTICS_EVENT';
  let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
  let log_suffix = '\n</LOG></SESSION_LOG>';

  try{
  let data_q = Buffer.from(req.query.data,'base64').toString('utf8');  
  let data = JSON.parse(data_q);
  console.log(log_prefix + JSON.stringify(data) + log_suffix);
   await uploadGAnalytics(data[0],req,log_prefix,log_suffix);
   res.send('OK');
  } catch(err) {
    console.log('Exception while GA event processing');
    res.send('KO');
  }
});


async function checkVariableAmounts(xml,req)
{
  let final_xml = xml;
  if(xml.includes('MAXAMOUNT='))
  {    
    let arr = xml.split('MAXAMOUNT=');
    let int_xml = arr[0];
    for(let m=1; m<arr.length; m++)
    {
        let arr_1 = arr[m].split('>');
        if(arr_1[0] != '"0"') {
          let a = arr_1[1].split('<');
            let fv = a[0];
            if(fv == '0') {
              int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + '1' + arr[m].substring(arr_1[0].length+1+1,arr[m].length);
            } 
            else 
              int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + arr[m].substring(arr_1[0].length+1,arr[m].length);
        }
        else {         
            int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + arr[m].substring(arr_1[0].length+1,arr[m].length);       
         }
        
    }
    final_xml = int_xml;
  }
  return final_xml;
}

async function limitMAXAMOUNT(xml,req)
{
  let host = (req.hostname.split('.'))[0];
  xml = await checkVariableAmounts(xml,req);
  let limit = '';
  if(req.hostname == DOMAIN_0) {
    if(config['domain_0'].MAXAMOUNT_LIMIT){
      limit = config['domain_0'].MAXAMOUNT_LIMIT;
    }
    else 
      return xml;
  } else  if(req.hostname == DOMAIN_1) {
    if(config['domain_1'].MAXAMOUNT_LIMIT){
      limit = config['domain_1'].MAXAMOUNT_LIMIT;
    }
    else 
      return xml;
  } else  if(req.hostname == DOMAIN_2) {
    if(config['domain_2'].MAXAMOUNT_LIMIT){
      limit = config['domain_2'].MAXAMOUNT_LIMIT;
    }
    else 
      return xml;
  } else  if(req.hostname == DOMAIN_3) {
    if(config['domain_3'].MAXAMOUNT_LIMIT){
      limit = config['domain_3'].MAXAMOUNT_LIMIT;
    }
    else 
      return xml;
  } else  if(config[host]) {
    if(config[host].MAXAMOUNT_LIMIT){
      limit = config[host].MAXAMOUNT_LIMIT;
    }
    else 
      return xml;
  }
  else {
    return xml;
  }    

  let final_xml = xml;
  if(xml.includes('MAXAMOUNT='))
  {    
    let arr = xml.split('MAXAMOUNT=');
    let int_xml = arr[0];
    for(let m=1; m<arr.length; m++)
    {
        let arr_1 = arr[m].split('>');
        let maxval = arr_1[0].replaceAll('"','');
       // console.log('Maxval:::::::::'+maxval);
        if((arr_1[0] != '"0"')&&(Number(maxval) > Number(limit))) {
         /* let a = arr_1[1].split('<');
            let fv = a[0];
            if((fv == '0')&&(arr_1[0] != '"0"')) {
              int_xml = int_xml + 'MAXAMOUNT='  + '"' + limit + '"' + '>' + '1' + arr[m].substring(arr_1[0].length+1+1,arr[m].length);
            } else */
          int_xml = int_xml + 'MAXAMOUNT='  + '"' + limit + '"' + '>' + arr[m].substring(arr_1[0].length+1,arr[m].length);
        }
        else {
          let amount = (arr_1[1].split('<'))[0];
          if((arr_1[0] == '"0"')&&(Number(amount) > Number(limit))) {
            int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + '0' + arr[m].substring(arr_1[0].length+1+amount.length,arr[m].length);
          }
          else{
           /* let a = arr_1[1].split('<');
            let fv = a[0];
            if((fv == '0')&&(arr_1[0] != '"0"')) {
              int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + '1' + arr[m].substring(arr_1[0].length+1+1,arr[m].length);
            }else {
              int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + arr[m].substring(arr_1[0].length+1,arr[m].length);
            }*/
            int_xml = int_xml + 'MAXAMOUNT='+ arr_1[0] +'>' + arr[m].substring(arr_1[0].length+1,arr[m].length);
          }
        
        }
        
    }
    final_xml = int_xml;
  }
  
  return final_xml;
}

async function runShellCmd(cmd) {
  const shell = require('shelljs');
  return new Promise((resolve, reject) => {
    
    shell.exec(cmd, async (code, stdout, stderr) => {
      console.log(code);
      console.log(stdout);
      console.log(stderr);
      if (!code) {
        return resolve(stdout);
      }
      return reject(stderr);
    });
  });
}


app.get('/getData', cors(corsOptions), async (req, res) => {

  const clientip = req.headers['incap-client-ip'] ;
  console.log(req.headers.campaign + '>>API_CALL:getData => clientip: ' + clientip);
  req.hostname = 'localhost';//'endlessaisle.epayworldwide.com';  //for test
  req.headers.referer = DOMAIN_0;  //for test
  console.log(req.hostname);
 // console.log(req.headers);
  let ip_allowed = '0';  
  try {
  try {
    let isIpTrusted = await isTrustedIP(clientip,req.hostname,req);
    if(isIpTrusted)
    {
      ip_allowed = '1';
    }

  }catch(err){
    console.log(err);
  }
  if (req.headers.referer) {
    console.log(req.headers.referer);

    if (await checkIfRefererAllowed(req.headers.referer,req)) {

      var clientIp = requestIp.getClientIp(req);
      console.log(clientIp);
      let TID = '';

     let str_tid = Buffer.from(req.query.TID,'base64').toString('utf8');
      var arr = str_tid.toString().split(",");
      console.log(arr);
      let TID_Temp = arr[0];
      catalog =  arr[2];
     
 
      if((TID_Temp == '') || (TID_Temp == 'undefined') || (TID_Temp == 'notid') || (TID_Temp.length != 8))
      {
        
         TID = getDefaultTID(req.hostname,req);
      }
      else 
      {
        TID = TID_Temp;
      }
      
      if(((await checkIfVodacomFlow(req.hostname)) == 'yes'))
      {
        TID = getDefaultTID(req.hostname,req);        
      }
      
    

       if(req.headers.campaign == getcampaignString(req)) {
       
        let defaultTID_temp = getCampaignTID(req.hostname,req);
        if(defaultTID_temp.length == 8) {
          TID = defaultTID_temp;
          let result = await getCampaignHITCount(getcampaignString(req));
          console.log('First Result count:' + result);
           if(result.length) {
            campaignCounter = Number(result);
            campaignCounter = campaignCounter + 1;
            console.log(result + '::' + campaignCounter);            
          
          }
          console.log(getcampaignString(req) + ' CAMPAIGN HIT COUNT:'+ ((campaignCounter == 0) ? 1:campaignCounter ));
          let saveCounterCampaign = (campaignCounter == 0) ? 1:campaignCounter ;         
          await saveCampaignHITCount(saveCounterCampaign.toString(),getcampaignString(req));
        }
      }
      

      let host_name = req.hostname;
      let hostArr = host_name.split('.');
      let hostFileName = TID + '_' + hostArr[0] + '.txt';
      let CatalogFileExpired = true;
      CatalogFileExpired = await checkIfCatalogFileExpired(hostFileName);
      console.log('expired catalog: '+CatalogFileExpired);

      var txid = getTimeStamp();
      var x = Math.random() * 1000000;      
      var y = x.toString().split('.');      
      txid = txid + y[0];

      let session_id = txid;
      let host_log = req.hostname.split('.');
      let method = 'GET_CATALOG';
      let log_prefix = '<SESSION_LOG><REF>' + session_id + '</REF><IP>' + clientip + '</IP><HOST>'+ host_log[0] +'</HOST><METHOD>'+ method +'</METHOD><LOG>\n';
      let log_suffix = '\n</LOG></SESSION_LOG>';

      console.log(log_prefix + req.headers.campaign + '>>API_CALL:getData => clientip: ' + clientip + log_suffix);
  
      let demosDataHost = await getDemoData(req.hostname,req);
     console.log('demosDataHost: '+ demosDataHost);
     fs.writeFileSync(catalogDirectory+ 'screendemo.txt',demosDataHost, 'utf8');

      let bannersDataHost = await getBannersData(req.hostname);
       
      bannersDataHost = bannersDataHost  + demosDataHost ;
       console.log(bannersDataHost);

      let cashier = await getCashierConfig(req.hostname) ; 
     
      let deliver_mode  = 'EMAIL';

      let paysupported = await getPaymentMethods(req.hostname);
      //TEST_IP_AZURE
      if((req.headers.referer.includes('/akani'))||(req.headers.referer.includes('/alt1'))||(req.headers.referer.includes('/carrefour')))
        {
              if(req.headers.referer.includes('/akani'))
                 paysupported = 'akani';
              else 
                paysupported = 'checkout,apay';
        }
      ////////////////////////////////////////
          if(!req.headers.referer.includes('/akani')) { 
            paysupported = paysupported.replace(',akani','')
          }
      ///////////////////////////////////////  


      let payment_methods_element = '<PAYMENT_METHODS_SUPPORTED>' + paysupported + '</PAYMENT_METHODS_SUPPORTED>';
      let xml_interface_tag = '';
        let host = (req.hostname.split('.'))[0];
        if(req.hostname == DOMAIN_0)
          xml_interface_tag = '<XML_GATEWAY>'+ (use_domain_0_xml_interface == '2' ? '1': use_domain_0_xml_interface)+'</XML_GATEWAY>'  ;  
        else if(req.hostname == DOMAIN_1)
          xml_interface_tag = '<XML_GATEWAY>'+ (use_domain_1_xml_interface == '2' ? '1': use_domain_1_xml_interface)+'</XML_GATEWAY>'  ;
        else if(req.hostname == DOMAIN_3)
          xml_interface_tag = '<XML_GATEWAY>'+ (use_domain_3_xml_interface == '2' ? '1': use_domain_3_xml_interface)+'</XML_GATEWAY>'  ;
        else if(req.hostname == DOMAIN_2)
          xml_interface_tag = '<XML_GATEWAY>'+ (use_domain_2_xml_interface == '2' ? '1': use_domain_2_xml_interface) +'</XML_GATEWAY>'  ;  
        else if(config[host]){
          xml_interface_tag = '<XML_GATEWAY>'+ (config[host].use_xml_interface == '2' ? '1': config[host].use_xml_interface) +'</XML_GATEWAY>'  ;  
        }
         else //test
           xml_interface_tag = '<XML_GATEWAY>'+ (use_domain_0_xml_interface == '2' ? '1': use_domain_0_xml_interface)+'</XML_GATEWAY>'  ;
             
          
        let TID_HEAD = '<TIDHEAD>'+ TID +'</TIDHEAD>';

      if ((fs.existsSync(catalogDirectory + hostFileName))&&(!CatalogFileExpired)) {
        var catalogData = fs.readFileSync(catalogDirectory + hostFileName, 'utf8');
        console.log(log_prefix + 'Catalog Data Read from Cache..' + log_suffix);
        catalogData = catalogData.replace('</RESPONSE>',  payment_methods_element +xml_interface_tag + TID_HEAD + '</RESPONSE>');
        catalogData =  catalogData.replace('</RESPONSE>', bannersDataHost + '<REDEEM>' + redeem_option + '</REDEEM>' + '<IP_ALLOWED>' + ip_allowed + '</IP_ALLOWED>' + '<CASHIER>'+ cashier +'</CASHIER>' + '<DELIVERYMODE>' + deliver_mode + '</DELIVERYMODE>' + '</RESPONSE>' ) ;
        catalogData =await convertHTML_BASE64(catalogData) ;
        catalogData =await limitMAXAMOUNT(catalogData,req) ;
        catalogData = await updateCatalogDataDiscountRRP(catalogData,req);
        catalogData = await getUpdateJSONInfoData(catalogData,arr,req);
	      res.send(catalogData);
      }
      else {
        console.log(log_prefix + 'Catalog Data from Server..' + log_suffix);
      currentDate = getFormattedTime();         
      
      let up_cred = await getUPCredentials(req);

      let userIdHost = up_cred.userIdHost;
      let userPaswdHost = up_cred.userPaswdHost;
      console.log('user cred..' + userIdHost + userPaswdHost);
      let tidhead = '<TERMINALID>' + TID + '</TERMINALID>';

      var timeouttext = getMessageIDText('MESSAGEID_170',req);
      if ((await checkIfVodacomFlow(req.hostname)) == 'yes') {      
       
        timeouttext = getMessageIDText('MESSAGEID_171',req);
      }
	

  
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
      console.log(log_prefix + 'CATLOG Request: ' + UPInterfaceURL  + log_suffix);
      mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
      var catalogTimer = setTimeout(() => res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>' + timeouttext + '</RESULTTEXT></RESPONSE>'), (30000 * 4));

      try {
        const response = await fetch(UPInterfaceURL, fetchOptions, proxy_url);

        let jsonResponse = await response.text();
        clearTimeout(catalogTimer);
     
      
        if((!jsonResponse.includes('<RESULT>0</RESULT>'))||(jsonResponse.includes('<CATALOG />'))||(!jsonResponse.includes('<CATALOG>')))
	      {
          let jsonResponse_log = jsonResponse;
          jsonResponse_log = jsonResponse_log.replace(/\r?\n|\r/g, " ");
          console.log(log_prefix + 'Catalog Response (Failed/No Data)' +  log_suffix)
		      mask_xml_data(jsonResponse_log,log_prefix,log_suffix);
        }
               

       
        

        if((jsonResponse.includes('<RESULT>0</RESULT>'))&&(!jsonResponse.includes('<CATALOG />'))&&(jsonResponse.includes('<CATALOG>')))
        {

          if(fs.existsSync(catalogDirectory + hostFileName))
        {
          if(isTest==0) 
           fs.unlinkSync(catalogDirectory+ hostFileName);
          
          console.log('file deleted successfully');
        }
        else console.log('file not exists');                
          fs.writeFileSync(catalogDirectory+ hostFileName,jsonResponse, 'utf8');
          console.log(log_prefix + 'Catalog response sent. Cache file created successfully' + log_suffix);
          jsonResponse = jsonResponse.replace('</RESPONSE>',  payment_methods_element +xml_interface_tag + TID_HEAD + '</RESPONSE>');
          jsonResponse =  jsonResponse.replace('</RESPONSE>', bannersDataHost + '<REDEEM>' + redeem_option + '</REDEEM>'  + '<IP_ALLOWED>' + ip_allowed + '</IP_ALLOWED>' + '<CASHIER>'+ cashier +'</CASHIER>' + '<DELIVERYMODE>' + deliver_mode + '</DELIVERYMODE>' + '</RESPONSE>' ) ;
          jsonResponse =await convertHTML_BASE64(jsonResponse) ;
          jsonResponse =await limitMAXAMOUNT(jsonResponse,req) ;
          jsonResponse = await updateCatalogDataDiscountRRP(jsonResponse,req);
          jsonResponse = await getUpdateJSONInfoData(jsonResponse,arr,req);
          res.send(jsonResponse);
          
        }
  
        else if(!tidhead.includes(getDefaultTID(req.hostname,req)) )
        {
          
          let tid_def = getDefaultTID(req.hostname,req);
          hostFileName = tid_def + '_' + hostArr[0] + '.txt';
          CatalogFileExpired = await checkIfCatalogFileExpired(hostFileName);
          console.log('Retry catalog with default TID.......' + tid_def + '::::' + CatalogFileExpired);
         
          if ((fs.existsSync(catalogDirectory + hostFileName))&&(!CatalogFileExpired)) {
            var catalogData = fs.readFileSync(catalogDirectory + hostFileName, 'utf8');
            console.log(log_prefix + 'Default TID Catalog Data Read from Cache..' + log_suffix);
            catalogData = catalogData.replace('</RESPONSE>',  payment_methods_element +xml_interface_tag + TID_HEAD + '</RESPONSE>');
            catalogData =  catalogData.replace('</RESPONSE>', bannersDataHost + '<REDEEM>' + redeem_option + '</REDEEM>' + '<IP_ALLOWED>' + ip_allowed + '</IP_ALLOWED>' + '<CASHIER>'+ cashier +'</CASHIER>' + '<DELIVERYMODE>' + deliver_mode + '</DELIVERYMODE>' + '</RESPONSE>' ) ;
            catalogData =await convertHTML_BASE64(catalogData) ;
            catalogData =await limitMAXAMOUNT(catalogData,req) ;
            catalogData = await updateCatalogDataDiscountRRP(catalogData,req);
            catalogData = await getUpdateJSONInfoData(catalogData,arr,req);
            res.send(catalogData);
          } else {
          //  console.log('Retry catalog with default TID.......');
          // let tid_def = getDefaultTID(req.hostname,req);
          TID = tid_def;
          TID_HEAD = '<TIDHEAD>' + TID + '</TIDHEAD>';
          tidhead = '<TERMINALID>' + tid_def + '</TERMINALID>';
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
              'Content-Type': 'application/xml',
            },      
    
          }
          console.log(log_prefix + 'CATLOG Request: ' + UPInterfaceURL  + log_suffix);
          mask_xml_data(fetchOptions.body,log_prefix,log_suffix);
          var catalogTimer = setTimeout(() => res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>' + timeouttext + '</RESULTTEXT></RESPONSE>'), (30000 * 4));
    
          try {
            const response = await fetch(UPInterfaceURL, fetchOptions, proxy_url);
    
            jsonResponse = await response.text();
            clearTimeout(catalogTimer);

            
            if((jsonResponse.includes('<RESULT>0</RESULT>'))&&(!jsonResponse.includes('<CATALOG />'))&&(jsonResponse.includes('<CATALOG>')))
            {
              hostFileName = tid_def + '_' + hostArr[0] + '.txt';                
              fs.writeFileSync(catalogDirectory+ hostFileName,jsonResponse, 'utf8');
              console.log(log_prefix + 'Catalog response sent. Cache file created successfully' + log_suffix);
              jsonResponse = jsonResponse.replace('</RESPONSE>',  payment_methods_element +xml_interface_tag + TID_HEAD + '</RESPONSE>');
              jsonResponse =  jsonResponse.replace('</RESPONSE>', bannersDataHost + '<REDEEM>' + redeem_option + '</REDEEM>'  + '<IP_ALLOWED>' + ip_allowed + '</IP_ALLOWED>' + '<CASHIER>'+ cashier +'</CASHIER>' + '<DELIVERYMODE>' + deliver_mode + '</DELIVERYMODE>' + '</RESPONSE>' ) ;
              jsonResponse =await convertHTML_BASE64(jsonResponse) ; 
              jsonResponse =await limitMAXAMOUNT(jsonResponse,req) ;
              jsonResponse = await updateCatalogDataDiscountRRP(jsonResponse,req);   
              jsonResponse = await getUpdateJSONInfoData(jsonResponse,arr,req);        
            }
            res.send(jsonResponse);  

          }catch(err){
            console.log('Retry catalog with default TID failed.......');
            console.log(err);
            let customer = await getCustomerName(req.hostname);
            let support_url = await getDomainSupportUrl(req.hostname);
            let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_107',req) + getMessageIDText('MESSAGEID_148',req)+ customer + getMessageIDText('MESSAGEID_103',req)+ support_url + '</RESULTTEXT></RESPONSE>';;
                    
            res.send(str);
          }
        }
        }
        else{
           jsonResponse = jsonResponse.replace('</RESPONSE>',  payment_methods_element +xml_interface_tag + TID_HEAD + '</RESPONSE>');
           jsonResponse =  jsonResponse.replace('</RESPONSE>', bannersDataHost + '<REDEEM>' + redeem_option + '</REDEEM>'  + '<IP_ALLOWED>' + ip_allowed + '</IP_ALLOWED>' + '<CASHIER>'+ cashier +'</CASHIER>' + '<DELIVERYMODE>' + deliver_mode + '</DELIVERYMODE>' + '</RESPONSE>' ) ;
           jsonResponse =await convertHTML_BASE64(jsonResponse) ;
           jsonResponse =await limitMAXAMOUNT(jsonResponse,req) ;
           jsonResponse = await updateCatalogDataDiscountRRP(jsonResponse,req); 
           jsonResponse = await getUpdateJSONInfoData(jsonResponse,arr,req);
           res.send(jsonResponse);
        }
        

      } catch (error) {
        console.log(error);
        let customer = await getCustomerName(req.hostname);
        let support_url = await getDomainSupportUrl(req.hostname);
        let str = '<RESPONSE><RESULT>102</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_107',req) + getMessageIDText('MESSAGEID_148',req)+ customer + getMessageIDText('MESSAGEID_103',req)+ support_url + '</RESULTTEXT></RESPONSE>';;
        res.send(str);
      }

    }
    } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
  } else { res.statusCode = 404; res.send('<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>') }
} catch (err) {
  console.log(err);
  res.send('<RESPONSE><RESULT>-1</RESULT><RESULTTEXT>'+ getMessageIDText('MESSAGEID_164',req)+'</RESULTTEXT></RESPONSE>')
}
});



async function convertHTML_BASE64(xml)
{
  let final_xml = xml;
  if(xml.includes('<TERMS_AND_CONDITIONS_HTML>'))
  {    
    let arr = xml.split('<TERMS_AND_CONDITIONS_HTML>');
    let int_xml = arr[0];
    for(let m=1; m<arr.length; m++)
    {
        let arr_1 = arr[m].split('</TERMS_AND_CONDITIONS_HTML>');
        let base64_Str = Buffer.from(arr_1[0]).toString('base64');  
      
        int_xml = int_xml + '<TERMS_AND_CONDITIONS_HTML>'  + base64_Str + '</TERMS_AND_CONDITIONS_HTML>' + arr_1[1];
    }
    final_xml = int_xml;
   // console.log(final_xml);
  }
  return final_xml;
}

let translations = {};

async function getLanguagesTranslationDatas(req,languages){
  let translations = {}
  if(languages.includes(',')) {
    languages = languages.split(',');
  }else{
    let lang = [];
    lang.push(languages);
    languages = lang;
  }
  try {
      for(let i=0; i<languages.length; i++){
          console.log(languagesDirectory + languages[i]+'.JSON');
          if(fs.existsSync(languagesDirectory + languages[i]+'.JSON'))
          {
            let result = fs.readFileSync(languagesDirectory + languages[i]+'.JSON', 'utf8');       
            console.log('Language Data Read for ' + languages[i]+'.JSON');
            translations[languages[i]] = JSON.parse(result);
          } else {
            let result = fs.readFileSync('en.JSON', 'utf8');       
            console.log('Language File: ' + languages[i] + '.JSON not exists. Default data from en.JSON used');
            translations[languages[i]] = JSON.parse(result);
          }
      }

      return  JSON.stringify(translations);

    } catch(err) {
      console.log('Exception in language data read!!')
      console.log(JSON.stringify(err));
      return  '';
    }
 

}

async function getLanguageData() {

  return new Promise((resolve, reject) => {

      fs.readdir(languagesDirectory, function (err, files) {
        //handling error
        if (err) {
          console.log('Unable to scan directory: ' + err);
        } else {
        //listing all files using forEach
        console.log(files);
        files.forEach(function (file) {
            // Do whatever you want to do with the file
            file = file.replace('.JSON','');
            language_list.push(file);
            
            console.log(file); 
        });
        console.log(language_list);
        return resolve(language_list.join(','));
      }
      });
  
  });
}

const configureApplication = async () => {
  try{
   
   console.log(process.cwd());
  
  
  //  let PWD_SECRET_KEY = '9b94352577fbc1f12355e1dd6aab15e4';
  //  let PWD_IV = 'd6d1b322f15d28ba' ;
   var configTest = fs.readFileSync(configdir + 'config.ini', 'utf-8');
  
    
  let ini = require('ini');
  config = ini.parse(configTest);
  
  fs.readdir(catalogDirectory, (err, files) => {
      if (err) throw err;  
      for (const file of files) {
        if(isTest==0){
        fs.unlink(path.join(catalogDirectory, file), (err) => {
          if (err) throw err;
        });}
      }
    });


  if(fs.existsSync(configdir + 'campaign.txt'))
  {
      let count = fs.readFileSync(configdir + 'campaign.txt', 'utf8');
      campaignCounter = Number(count);
  }
  else {
    let count = 0;
    fs.writeFileSync(configdir + 'campaign.txt',count.toString(), 'utf8');
    campaignCounter = count.toString();
  }
/////////////////////Language Directory////////////////////////////


  // let langs = 'en';
  // language_list = ['en'];
  // if(config.AVAILABLE_LANGUAGES) {
  //    langs = config.AVAILABLE_LANGUAGES;
  //     if(langs.includes(',')) {
  //        language_list = langs.split(',');
  //     }else{
  //        let lang = [];
  //        lang.push(langs);
  //        language_list = lang;
  //     }
  // }

  console.log('=========Step 1=================');
  let langs = await getLanguageData();
  console.log(langs);
  console.log('=========Step 2=================');

  let translationsSTR = await getLanguagesTranslationDatas('req',langs);
  translations = JSON.parse(translationsSTR);

////////////////////////////////////////////////////////////////////////////////
    if(config._TEST_)
      isTest = config._TEST_;
 //  else
    logopath = '';
  
   if(config.basepath)
      remotebannerlocation = config.basepath;
   else
      remotebannerlocation = null;

   if(config.TESTOTP)
      otpTest = config.TESTOTP;
   else
      otpTest = null;

   if(config.REDEEM)
      redeem_option = config.REDEEM;
   else
      redeem_option = '0';

   if(config.AllowedIPs)
      AllowedIPs = config.AllowedIPs;
   else 
      AllowedIPs = null;

   if(config.BlockedIPs)
      BlockedIPs = config.BlockedIPs;
   else 
      BlockedIPs = null;
  
   refreshCatalogTime = config.refreshCatalogTime;
  
   servicePORT = config.servicePORT;
  
   UPInterfaceURL = config.URL.UPInterfaceURL;
   CheckoutURL = config.URL.CheckoutURL;
   CheckoutURL_Test = config.URL.CheckoutURL_Test;
   XMLInterfaceURL = config.URL.XMLInterfaceURL;
   vodacomValidationPhoneURL = config.URL.vodacomValidationPhoneURL;
   vodacomSMSURL = config.URL.vodacomSMSURL;
   vodacomChargeURL = config.URL.vodacomChargeURL;
   getContractURL = config.URL.getContractURL;
   paymentInfoURL = config.URL.paymentInfoURL;
   infobipURL = config.infobip.infobipURL;


   if(config.CARREFOUR_CRED)
   {
    
      if(config.CARREFOUR_CRED.carrefour_user_access_code) {
        carrefour_user_access_code = config.CARREFOUR_CRED.carrefour_user_access_code;
      }

      if(config.CARREFOUR_CRED.carrefour_source_reference) {
        carrefour_source_reference = config.CARREFOUR_CRED.carrefour_source_reference;
      }

      if(config.CARREFOUR_CRED.carrefour_booking_source) {
        carrefour_booking_source = config.CARREFOUR_CRED.carrefour_booking_source;
      }

      if(config.CARREFOUR_CRED.carrefour_url) {
        carrefour_url = config.CARREFOUR_CRED.carrefour_url;
      }
    
   }

   if(config.PRECISION)
   {
      promoURL = config.PRECISION.precisionURL;
      promoUser = config.PRECISION.precisionUser;
      promoPassword = config.PRECISION.precisionPassword;
      if(promoPassword.substring(0,5) == '!PWD!')
      {
        promoPassword = decrypt_pwd(promoPassword.substring(5,promoPassword.length),PWD_SECRET_KEY,PWD_IV);
      }
   }
   
   if(config.DOMAINS.DOMAIN_0)
   {
      console.log('Domain0 available');
      DOMAIN_0 = config.DOMAINS.DOMAIN_0;
      DOMAIN_0_TITLE = config.DOMAINS.DOMAIN_0_TITLE;
      user_domain_0 = config.domain_0.user_domain_0;
      password_domain_0 = config.domain_0.password_domain_0;
      if(password_domain_0.substring(0,5) == '!PWD!')
      {
        password_domain_0 = decrypt_pwd(password_domain_0.substring(5,password_domain_0.length),PWD_SECRET_KEY,PWD_IV);
        console.log(`password_domain_0:   ${password_domain_0}`);
      }
      defaultTID_domain_0 = config.domain_0.defaultTID;
      if((config.domain_0.campaignTID)&&(config.domain_0.campaign))
      {
        campaignTID_domain_0 = config.domain_0.campaignTID;
        campaign_domain_0 = config.domain_0.campaign;
      }

   
      
      payment_methods_supported_domain_0 =  config.domain_0.payment_methods;
      use_domain_0_xml_interface = config.domain_0.use_xml_interface;
      TestTIDSUBSCRIPTION_DOMAIN_0 = config.domain_0.TestTIDSUBSCRIPTION;
      TestEANSUBSCRIPTION_DOMAIN_0 = config.domain_0.TestEANSUBSCRIPTION;
      sharafTestTID = config.domain_0.defaultTID;

      DOMAIN_0_FOOTER_L_NAME = config.domain_0.DOMAIN_0_FOOTER_L_NAME;
      DOMAIN_0_FOOTER_R_NAME = config.domain_0.DOMAIN_0_FOOTER_R_NAME;
      DOMAIN_0_FOOTER_L_LINK = config.domain_0.DOMAIN_0_FOOTER_L_LINK;
      DOMAIN_0_FOOTER_R_LINK = config.domain_0.DOMAIN_0_FOOTER_R_LINK;

      if(config.domain_0.CUSTOMERNAME)
      {
        customer_name_D0 = config.domain_0.CUSTOMERNAME;
      }

     if(config.domain_0.REFUND)
      refund_allowed_domain0 = config.domain_0.REFUND;
     else
      refund_allowed_domain0 = '0';
  
     if(config.domain_0.CANCEL)
      cancel_allowed_domain0 = config.domain_0.CANCEL;
     else
      cancel_allowed_domain0 = '0';

    if(config.domain_0.CASHIER)
      cashier_allowed_domain0 = config.domain_0.CASHIER;
    else
      cashier_allowed_domain0 = '0';

    if(config.domain_0.DELIVERY_MODE)
    {
      domain0_delivery_mode = config.domain_0.DELIVERY_MODE;
    }
    if(config.domain_0.DOMAIN_0_LOGO)
    {
      domain0_logo = logopath + config.domain_0.DOMAIN_0_LOGO;
    }
    
    if(config.domain_0.APP_THEME)
    {
      domain0_theme = config.domain_0.APP_THEME;
    }
    if(config.domain_0.REDEEM_EAN)
    {
      DOMAIN_0_PAYMENT_EAN = config.domain_0.REDEEM_EAN;
    }

    if(config.domain_0.FONT_NAME)
    {
      DOMAIN_0_FONT_NAME = config.domain_0.FONT_NAME;
    }

    if(config.domain_0.UPLOAD_TXN)
    {
      domain0_upload_txn = config.domain_0.UPLOAD_TXN;
    }

    if(config.domain_0.SORT_ORDER)
    {
      DOMAIN_0_SORT_ORDER = config.domain_0.SORT_ORDER;
    }

    if(config.domain_0.google_analytics)
    {
      DOMAIN_0_GOOGLE_ANALYTICS = config.domain_0.google_analytics;
    }

    if(config.domain_0.g_measurementId)
    {
      DOMAIN_0_GOOGLE_MEASUREMENT_ID = config.domain_0.g_measurementId;
    }

    if(config.domain_0.g_api_secret)
    {
      DOMAIN_0_GOOGLE_API_SECRET = config.domain_0.g_api_secret;
      if(config.domain_0.g_api_secret.includes('!PWD!'))
      {
        DOMAIN_0_GOOGLE_API_SECRET = decrypt_pwd(config.domain_0.g_api_secret.substring(5,config.domain_0.g_api_secret.length),PWD_SECRET_KEY,PWD_IV);
      }
    }

    if(config.domain_0.COUNTRY_CODE) {
      DOMAIN_0_COUNTRY_CODE = config.domain_0.COUNTRY_CODE;
    }

    
    if(config.domain_0.APPLE_PASS) {
      DOMAIN_0_APPLE_PASS = config.domain_0.APPLE_PASS;
    }

    if(config.domain_0.GOOGLE_PASS) {
      DOMAIN_0_GOOGLE_PASS = config.domain_0.GOOGLE_PASS;
    }
    
    let sort_info = '';
    if(config.domain_0.SORT_ORDER_PROVIDER) {
      sort_info = config.domain_0.SORT_ORDER_PROVIDER;
    }

    sort_info = sort_info + '::::';

    if(config.domain_0.SORT_ORDER_PRODUCT) {
      sort_info = sort_info + config.domain_0.SORT_ORDER_PRODUCT;
    }

  /*  sort_info = sort_info + '::::';
    if(config.domain_0.HIGHLIGHT_EAN) {
      sort_info = sort_info + config.domain_0.HIGHLIGHT_EAN;
    } */

    sort_info = sort_info + '::::';
    if(config.domain_0.HIGHLIGHT_EAN) {
      let reverse_str = config.domain_0.HIGHLIGHT_EAN;
      
      if(config.domain_0.HIGHLIGHT_EAN.includes(',')) {        
        let tokens = config.domain_0.HIGHLIGHT_EAN.split( "," );        
        reverse_str = tokens.reverse().join(",");
      }

      sort_info = sort_info + reverse_str;
      
    }

    sort_info = sort_info + '::::';
    if(config.domain_0.HIGHLIGHT_EAN_BACKGROUND) {
      sort_info = sort_info + config.domain_0.HIGHLIGHT_EAN_BACKGROUND;
    }

    DOMAIN_0_SORT_INFO = sort_info;

    if(config.domain_0.CUSTOMERSUPPORT) {
      domain0_support_url = config.domain_0.CUSTOMERSUPPORT;
    }


   }
  else
  {
     DOMAIN_0 = 'DOMAIN_0';
  }
   
   if(config.DOMAINS.DOMAIN_1)
   {
  console.log('Domain1 available');
   DOMAIN_1 = config.DOMAINS.DOMAIN_1;
   DOMAIN_1_TITLE = config.DOMAINS.DOMAIN_1_TITLE;
   user_domain_1 = config.domain_1.user_domain_1;
   password_domain_1 = config.domain_1.password_domain_1;
   if(password_domain_1.substring(0,5) == '!PWD!')
   {
     password_domain_1 = decrypt_pwd(password_domain_1.substring(5,password_domain_1.length),PWD_SECRET_KEY,PWD_IV);
     console.log(`password_domain_1:   ${password_domain_1}`);
   }
   defaultTID_domain_1 = config.domain_1.defaultTID;
   if((config.domain_1.campaignTID)&&(config.domain_1.campaign))
    {
      campaignTID_domain_1 = config.domain_1.campaignTID;
      campaign_domain_1 = config.domain_1.campaign;
    }
   payment_methods_supported_domain_1 =  config.domain_1.payment_methods;
   use_domain_1_xml_interface = config.domain_1.use_xml_interface;
   sharafTestTID = config.domain_1.TestTID;

   DOMAIN_1_FOOTER_L_NAME = config.domain_1.DOMAIN_1_FOOTER_L_NAME;
   DOMAIN_1_FOOTER_R_NAME = config.domain_1.DOMAIN_1_FOOTER_R_NAME;
   DOMAIN_1_FOOTER_L_LINK = config.domain_1.DOMAIN_1_FOOTER_L_LINK;
   DOMAIN_1_FOOTER_R_LINK = config.domain_1.DOMAIN_1_FOOTER_R_LINK;

   if(config.domain_1.CUSTOMERNAME)
   {
    customer_name_D1 = config.domain_1.CUSTOMERNAME;
   }
   if(config.domain_1.REFUND)
      refund_allowed_domain1 = config.domain_1.REFUND;
     else
      refund_allowed_domain1 = '0';
  
     if(config.domain_1.CANCEL)
      cancel_allowed_domain1 = config.domain_1.CANCEL;
     else
      cancel_allowed_domain1 = '0';

    if(config.domain_1.CASHIER)
      cashier_allowed_domain1 = config.domain_1.CASHIER;
    else
      cashier_allowed_domain1 = '0';

    if(config.domain_1.DELIVERY_MODE)
    {
      domain1_delivery_mode = config.domain_1.DELIVERY_MODE;
    }
    if(config.domain_1.DOMAIN_1_LOGO)
    {
      domain1_logo = logopath + config.domain_1.DOMAIN_1_LOGO;
    }
    if(config.domain_1.APP_THEME)
    {
      domain1_theme = config.domain_1.APP_THEME;
    }
    if(config.domain_1.REDEEM_EAN)
    {
      DOMAIN_1_PAYMENT_EAN = config.domain_1.REDEEM_EAN;
    }

    if(config.domain_1.FONT_NAME)
    {
      DOMAIN_1_FONT_NAME = config.domain_1.FONT_NAME;
    }

    if(config.domain_1.UPLOAD_TXN)
    {
      domain1_upload_txn = config.domain_1.UPLOAD_TXN;
    }

    if(config.domain_1.SORT_ORDER)
    {
      DOMAIN_1_SORT_ORDER = config.domain_1.SORT_ORDER;
    }

    if(config.domain_1.google_analytics)
    {
      DOMAIN_1_GOOGLE_ANALYTICS = config.domain_1.google_analytics;
    }

    if(config.domain_1.g_measurementId)
    {
      DOMAIN_1_GOOGLE_MEASUREMENT_ID = config.domain_1.g_measurementId;
    }

    if(config.domain_1.g_api_secret)
    {
      DOMAIN_1_GOOGLE_API_SECRET = config.domain_1.g_api_secret;
      if(config.domain_1.g_api_secret.includes('!PWD!'))
      {
        DOMAIN_1_GOOGLE_API_SECRET = decrypt_pwd(config.domain_1.g_api_secret.substring(5,config.domain_1.g_api_secret.length),PWD_SECRET_KEY,PWD_IV);
      }
    }

    if(config.domain_1.COUNTRY_CODE) {
      DOMAIN_1_COUNTRY_CODE = config.domain_1.COUNTRY_CODE;
    }

    if(config.domain_1.APPLE_PASS) {
      DOMAIN_1_APPLE_PASS = config.domain_1.APPLE_PASS;
    }

    if(config.domain_1.GOOGLE_PASS) {
      DOMAIN_1_GOOGLE_PASS = config.domain_1.GOOGLE_PASS;
    }

    let sort_info = '';
    if(config.domain_1.SORT_ORDER_PROVIDER) {
      sort_info = config.domain_1.SORT_ORDER_PROVIDER;
    }

    sort_info = sort_info + '::::';

    if(config.domain_1.SORT_ORDER_PRODUCT) {
      sort_info = sort_info + config.domain_1.SORT_ORDER_PRODUCT;
    }

  /*  sort_info = sort_info + '::::';
    if(config.domain_1.HIGHLIGHT_EAN) {
      sort_info = sort_info + config.domain_1.HIGHLIGHT_EAN;
    }*/

    sort_info = sort_info + '::::';
    if(config.domain_1.HIGHLIGHT_EAN) {
      let reverse_str = config.domain_1.HIGHLIGHT_EAN;
      
      if(config.domain_1.HIGHLIGHT_EAN.includes(',')) {        
        let tokens = config.domain_1.HIGHLIGHT_EAN.split( "," );        
        reverse_str = tokens.reverse().join(",");
      }

      sort_info = sort_info + reverse_str;
      
    }

    sort_info = sort_info + '::::';
    if(config.domain_1.HIGHLIGHT_EAN_BACKGROUND) {
      sort_info = sort_info + config.domain_1.HIGHLIGHT_EAN_BACKGROUND;
    }

    DOMAIN_1_SORT_INFO = sort_info;

    if(config.domain_1.CUSTOMERSUPPORT) {
      domain1_support_url = config.domain_1.CUSTOMERSUPPORT;
    }

  }
  else
  {
     DOMAIN_1 = 'DOMAIN_1';
  }
  
  if(config.DOMAINS.DOMAIN_2)
  {
   DOMAIN_2 = config.DOMAINS.DOMAIN_2;
   DOMAIN_2_TITLE = config.DOMAINS.DOMAIN_2_TITLE;
   user_domain_2 = config.domain_2.user_domain_2;
   password_domain_2 = config.domain_2.password_domain_2; 
   if(password_domain_2.substring(0,5) == '!PWD!')
   {
    password_domain_2 = decrypt_pwd(password_domain_2.substring(5,password_domain_2.length),PWD_SECRET_KEY,PWD_IV);
    console.log(`password_domain_2:   ${password_domain_2}`);
   }
   defaultTID_domain_2 = config.domain_2.defaultTID;
   if((config.domain_2.campaignTID)&&(config.domain_2.campaign))
      {
        campaignTID_domain_2 = config.domain_2.campaignTID;
        campaign_domain_2 = config.domain_2.campaign;
      }
   payment_methods_supported_domain_2 =  config.domain_2.payment_methods;
   use_domain_2_xml_interface = config.domain_2.use_xml_interface;

   DOMAIN_2_FOOTER_L_NAME = config.domain_2.DOMAIN_2_FOOTER_L_NAME;
      DOMAIN_2_FOOTER_R_NAME = config.domain_2.DOMAIN_2_FOOTER_R_NAME;
      DOMAIN_2_FOOTER_L_LINK = config.domain_2.DOMAIN_2_FOOTER_L_LINK;
      DOMAIN_2_FOOTER_R_LINK = config.domain_2.DOMAIN_2_FOOTER_R_LINK;

   if(config.domain_2.CUSTOMERNAME)
      {
        customer_name_D2 = config.domain_2.CUSTOMERNAME;
      }

      if(config.domain_2.REFUND)
      refund_allowed_domain2 = config.domain_2.REFUND;
     else
      refund_allowed_domain2 = '0';
  
     if(config.domain_2.CANCEL)
      cancel_allowed_domain2 = config.domain_2.CANCEL;
     else
      cancel_allowed_domain2 = '0';

      if(config.domain_2.CASHIER)
        cashier_allowed_domain2 = config.domain_2.CASHIER;
      else
        cashier_allowed_domain2 = '0';

      if(config.domain_2.DELIVERY_MODE)
      {
        domain2_delivery_mode = config.domain_2.DELIVERY_MODE;
      }
      if(config.domain_2.DOMAIN_2_LOGO)
      {
       domain2_logo = logopath + config.domain_2.DOMAIN_2_LOGO;
      }

      if(config.domain_2.APP_THEME)
      {
       domain2_theme = config.domain_2.APP_THEME;
      }

      if(config.domain_2.REDEEM_EAN)
      {
        DOMAIN_2_PAYMENT_EAN = config.domain_2.REDEEM_EAN;
      }

      if(config.domain_2.FONT_NAME)
      {
        DOMAIN_2_FONT_NAME = config.domain_2.FONT_NAME;
      }

      if(config.domain_2.UPLOAD_TXN)
      {
        domain2_upload_txn = config.domain_2.UPLOAD_TXN;
      }

      if(config.domain_2.SORT_ORDER)
      {
        DOMAIN_2_SORT_ORDER = config.domain_2.SORT_ORDER;
      }

      if(config.domain_2.google_analytics)
      {
        DOMAIN_2_GOOGLE_ANALYTICS = config.domain_2.google_analytics;
      }

      if(config.domain_2.g_measurementId)
      {
        DOMAIN_2_GOOGLE_MEASUREMENT_ID = config.domain_2.g_measurementId;
      }

      if(config.domain_2.g_api_secret)
      {
        DOMAIN_2_GOOGLE_API_SECRET = config.domain_2.g_api_secret;
        if(config.domain_2.g_api_secret.includes('!PWD!'))
        {
          DOMAIN_2_GOOGLE_API_SECRET = decrypt_pwd(config.domain_2.g_api_secret.substring(5,config.domain_2.g_api_secret.length),PWD_SECRET_KEY,PWD_IV);
        }
      }    
      
      if(config.domain_2.COUNTRY_CODE) {
        DOMAIN_2_COUNTRY_CODE = config.domain_2.COUNTRY_CODE;
      }

      if(config.domain_2.APPLE_PASS) {
        DOMAIN_2_APPLE_PASS = config.domain_2.APPLE_PASS;
      }
  
      if(config.domain_2.GOOGLE_PASS) {
        DOMAIN_2_GOOGLE_PASS = config.domain_2.GOOGLE_PASS;
      }

      let sort_info = '';
      if(config.domain_2.SORT_ORDER_PROVIDER) {
        sort_info = config.domain_2.SORT_ORDER_PROVIDER;
      }

      sort_info = sort_info + '::::';

      if(config.domain_2.SORT_ORDER_PRODUCT) {
        sort_info = sort_info + config.domain_2.SORT_ORDER_PRODUCT;
      }

   /*   sort_info = sort_info + '::::';
      if(config.domain_2.HIGHLIGHT_EAN) {
        sort_info = sort_info + config.domain_2.HIGHLIGHT_EAN;
      }*/

      sort_info = sort_info + '::::';
    if(config.domain_2.HIGHLIGHT_EAN) {
      let reverse_str = config.domain_2.HIGHLIGHT_EAN;
      
      if(config.domain_2.HIGHLIGHT_EAN.includes(',')) {        
        let tokens = config.domain_2.HIGHLIGHT_EAN.split( "," );        
        reverse_str = tokens.reverse().join(",");
      }

      sort_info = sort_info + reverse_str;
      
    }

      sort_info = sort_info + '::::';
      if(config.domain_2.HIGHLIGHT_EAN_BACKGROUND) {
      	sort_info = sort_info + config.domain_2.HIGHLIGHT_EAN_BACKGROUND;
      }

      DOMAIN_2_SORT_INFO = sort_info;

      if(config.domain_2.CUSTOMERSUPPORT) {
      	domain2_support_url = config.domain_2.CUSTOMERSUPPORT;
    }
  }
  else
  {
     DOMAIN_2 = 'DOMAIN_2';
  }
  
  if(config.DOMAINS.DOMAIN_3)
  {
   DOMAIN_3 = config.DOMAINS.DOMAIN_3;
   DOMAIN_3_TITLE = config.DOMAINS.DOMAIN_3_TITLE;
   user_domain_3 = config.domain_3.user_domain_3;
   password_domain_3 = config.domain_3.password_domain_3;
   if(password_domain_3.substring(0,5) == '!PWD!')
   {
    password_domain_3 = decrypt_pwd(password_domain_3.substring(5,password_domain_3.length),PWD_SECRET_KEY,PWD_IV);
    console.log(`password_domain_3:   ${password_domain_3}`);
   }
   defaultTID_domain_3 = config.domain_3.defaultTID;
   if((config.domain_3.campaignTID)&&(config.domain_3.campaign))
      {
        campaignTID_domain_3 = config.domain_3.campaignTID;
        campaign_domain_3 = config.domain_3.campaign;
      }
   payment_methods_supported_domain_3 =  config.domain_3.payment_methods;
   use_domain_3_xml_interface = config.domain_3.use_xml_interface;

   DOMAIN_3_FOOTER_L_NAME = config.domain_3.DOMAIN_3_FOOTER_L_NAME;
      DOMAIN_3_FOOTER_R_NAME = config.domain_3.DOMAIN_3_FOOTER_R_NAME;
      DOMAIN_3_FOOTER_L_LINK = config.domain_3.DOMAIN_3_FOOTER_L_LINK;
      DOMAIN_3_FOOTER_R_LINK = config.domain_3.DOMAIN_3_FOOTER_R_LINK;

   if(config.domain_3.CUSTOMERNAME)
      {
        customer_name_D3 = config.domain_3.CUSTOMERNAME;
      }

      if(config.domain_3.REFUND)
      refund_allowed_domain3 = config.domain_3.REFUND;
     else
      refund_allowed_domain3 = '0';
  
     if(config.domain_3.CANCEL)
      cancel_allowed_domain3 = config.domain_3.CANCEL;
     else
      cancel_allowed_domain3 = '0';

    if(config.domain_3.CASHIER)
      cashier_allowed_domain3 = config.domain_3.CASHIER;
    else
      cashier_allowed_domain3 = '0';

      if(config.domain_3.DELIVERY_MODE)
      {
        domain3_delivery_mode = config.domain_3.DELIVERY_MODE;
      }

      if(config.domain_3.DOMAIN_3_LOGO)
      {
      	domain3_logo = logopath + config.domain_3.DOMAIN_3_LOGO;
      }
      if(config.domain_3.APP_THEME)
      {
        domain3_theme = config.domain_3.APP_THEME;
      }
      if(config.domain_3.REDEEM_EAN)
      {
        DOMAIN_3_PAYMENT_EAN = config.domain_3.REDEEM_EAN;
      }

      if(config.domain_3.FONT_NAME)
      {
        DOMAIN_3_FONT_NAME = config.domain_3.FONT_NAME;
      }

      if(config.domain_3.UPLOAD_TXN)
      {
        domain3_upload_txn = config.domain_3.UPLOAD_TXN;
      }

      if(config.domain_3.SORT_ORDER)
      {
        DOMAIN_3_SORT_ORDER = config.domain_3.SORT_ORDER;
      }

      if(config.domain_3.google_analytics)
      {
        DOMAIN_3_GOOGLE_ANALYTICS = config.domain_3.google_analytics;
      }

      if(config.domain_3.g_measurementId)
      {
        DOMAIN_3_GOOGLE_MEASUREMENT_ID = config.domain_3.g_measurementId;
      }

      if(config.domain_3.g_api_secret)
      {
        DOMAIN_3_GOOGLE_API_SECRET = config.domain_3.g_api_secret;
        if(config.domain_3.g_api_secret.includes('!PWD!'))
        {
          DOMAIN_3_GOOGLE_API_SECRET = decrypt_pwd(config.domain_3.g_api_secret.substring(5,config.domain_3.g_api_secret.length),PWD_SECRET_KEY,PWD_IV);
        }
        
      }

      if(config.domain_3.COUNTRY_CODE) {
        DOMAIN_3_COUNTRY_CODE = config.domain_3.COUNTRY_CODE;
      }

      if(config.domain_3.APPLE_PASS) {
        DOMAIN_3_APPLE_PASS = config.domain_3.APPLE_PASS;
      }
  
      if(config.domain_3.GOOGLE_PASS) {
        DOMAIN_3_GOOGLE_PASS = config.domain_3.GOOGLE_PASS;
      }

      let sort_info = '';
      if(config.domain_3.SORT_ORDER_PROVIDER) {
        sort_info = config.domain_3.SORT_ORDER_PROVIDER;
      }

      sort_info = sort_info + '::::';

      if(config.domain_3.SORT_ORDER_PRODUCT) {
        sort_info = sort_info + config.domain_3.SORT_ORDER_PRODUCT;
      }

    /*  sort_info = sort_info + '::::';
      if(config.domain_3.HIGHLIGHT_EAN) {
        sort_info = sort_info + config.domain_3.HIGHLIGHT_EAN;
      } */

      sort_info = sort_info + '::::';
    if(config.domain_3.HIGHLIGHT_EAN) {
      let reverse_str = config.domain_3.HIGHLIGHT_EAN;
      
      if(config.domain_3.HIGHLIGHT_EAN.includes(',')) {        
        let tokens = config.domain_3.HIGHLIGHT_EAN.split( "," );        
        reverse_str = tokens.reverse().join(",");
      }

      sort_info = sort_info + reverse_str;
      
    }

      sort_info = sort_info + '::::';
      if(config.domain_3.HIGHLIGHT_EAN_BACKGROUND) {
        sort_info = sort_info + config.domain_3.HIGHLIGHT_EAN_BACKGROUND;
      }

      DOMAIN_3_SORT_INFO = sort_info;

      if(config.domain_3.CUSTOMERSUPPORT) {
      	domain3_support_url = config.domain_3.CUSTOMERSUPPORT;
    }
  }
  else
  {
     DOMAIN_3 = 'DOMAIN_3';
  }
  

  
   user_xml = config.XMLInterface.user_xml;
  
   infobip_msg_sender = "epay";
   if(config.infobip.sender)
   {
    infobip_msg_sender = config.infobip.sender;
   }

   infobipAuth = config.infobip.infobipAuth;
   if(infobipAuth.substring(0,5) == '!PWD!')
   {
    infobipAuth = decrypt_pwd(infobipAuth.substring(5,infobipAuth.length),PWD_SECRET_KEY,PWD_IV);
   }
  
   password_xml = config.XMLInterface.password_xml;
   if(password_xml.substring(0,5) == '!PWD!')
   {
    password_xml = decrypt_pwd(password_xml.substring(5,password_xml.length),PWD_SECRET_KEY,PWD_IV);
   }
  
  //  CheckoutSecretKey = config.Checkout.SecretKey;
  //  if(CheckoutSecretKey.substring(0,5) == '!PWD!')
  //  {
  //   CheckoutSecretKey = decrypt_pwd(CheckoutSecretKey.substring(5,CheckoutSecretKey.length),PWD_SECRET_KEY,PWD_IV);
  //  }
  
  
  //  CheckoutSecretKey_preprod = config.Checkout.SecretKey_preprod;
  //  if(CheckoutSecretKey_preprod.substring(0,5) == '!PWD!')
  //  {
  //   CheckoutSecretKey_preprod = decrypt_pwd(CheckoutSecretKey_preprod.substring(5,CheckoutSecretKey_preprod.length),PWD_SECRET_KEY,PWD_IV);
  //  }
   
  
  //  checkout_protocol = config.Checkout.protocol;
  //  processingchannelid = config.Checkout.processingChannelID;
  
   initVector = config.Encryption.initVector;
   if(initVector.substring(0,5) == '!PWD!')
   {
    initVector = decrypt_pwd(initVector.substring(5,initVector.length),PWD_SECRET_KEY,PWD_IV);
   }
  
  
   Securitykey = config.Encryption.Securitykey;
   if(Securitykey.substring(0,5) == '!PWD!')
   {
    Securitykey = decrypt_pwd(Securitykey.substring(5,Securitykey.length),PWD_SECRET_KEY,PWD_IV);
   }
   
  
   secret = config.Encryption.Securitykey;
   if(secret.substring(0,5) == '!PWD!')
   {
    secret = decrypt_pwd(secret.substring(5,secret.length),PWD_SECRET_KEY,PWD_IV);
   }
   
  


   try { 
    let user_header = config.VodacomService.user_auth_header;
    let password_header = config.VodacomService.password_auth_header;
    if(password_header.substring(0,5) == '!PWD!')
    {
       password_header = decrypt_pwd(password_header.substring(5,password_header.length),PWD_SECRET_KEY,PWD_IV);
    }
//console.log(password_header);
    Auth_vodacom = Buffer.from(user_header + ':' + password_header).toString('base64');
    username_voda_service = config.VodacomService.domain_username;
    password_voda_service = config.VodacomService.domain_password;
    if(password_voda_service.substring(0,5) == '!PWD!')
    {
      password_voda_service = decrypt_pwd(password_voda_service.substring(5,password_voda_service.length),PWD_SECRET_KEY,PWD_IV);
    }
    senderName_voda_service = config.VodacomService.senderName;
    client_application_id_voda_service = config.VodacomService.client_application_id;
    partner_id_voda_service = config.VodacomService.partner_id;
    content_name_voda_service = config.VodacomService.content_name;
  }catch(error)
  {
    console.log(error);
  }
  
   logUpdateFrequency = config.logUpdateFrequency;
   
   if(process.env.HTTP_PROXY)
   {
    delete process.env.HTTP_PROXY;
   }
   console.log(process.env);
   if(config.proxyurl)
   {
     proxy_url = config.proxyurl;
     console.log('Using Proxy: ' + proxy_url);
     process.env.HTTP_PROXY = proxy_url;
     console.log(process.env);
   }
   else
   {
    proxy_url = null;
    console.log('No Proxy!');
   }
  
    fs.mkdirSync(log_directory,{recursive: true});
    if(config.logpath)
    {
        if(!fs.existsSync(config.logpath))
        {
          if(fs.mkdirSync(config.logpath,{recursive: true}))
          {
            log_directory = config.logpath; 
          }
          else
             console.log('LOG directory failed to create from config');
        }
        else
        {
            log_directory = config.logpath;
            console.log(`LOG directory already exists from config: ${log_directory}`);
        }
    }
  
    if(log_directory.charAt(log_directory.length-1) != '/')
    {
      log_directory = log_directory + '/';
    }
  
    console.log('Using current LOG directory: '+log_directory);
  
   } catch(error) {
     console.log(error);
   }
  
  ///////////////////////////
 /* console.log('Extract machine and service name' );
  let machine_name_str = shell.exec('hostname');
  let lines = shell.exec('journalctl _PID=' + process.pid + ' -n 1');
  let last_line = lines.split('\n')[1];
  let str = machine_name_str.split('\n');
  machine_name  = str[0].replace(' ','');
  let lineArr = last_line.split(machine_name);
  let lineArray = lineArr[1].split('[' + process.pid + ']');
  service_name = lineArray[0].replace(' ','');
  console.log('service_name: ' + service_name);
  console.log('machine_name: ' + machine_name);*/


  /*try {
console.log('Extract machine and service name' );
let machine_name_str = shell.exec('hostname');
//let lines = shell.exec('journalctl _PID=' + process.pid + ' -n 1');
console.log( 'machine_name_str: ' + machine_name_str);
//console.log( 'lines: ' + lines);
//let last_line = lines.split('\n')[1];
//console.log( 'last_line: ' + last_line);
let str = machine_name_str.split('\n');
console.log( 'str: ' + str);
machine_name  = str[0].replace(' ','');
console.log( 'machine_name: ' + machine_name);
let lineArr = last_line.split(machine_name);
console.log( 'lineArr: ' + lineArr);
let lineArray = lineArr[1].split('[' + process.pid + ']');
console.log( 'lineArray: ' + lineArray);
service_name = lineArray[0].replace(' ','');
console.log('service_name: ' + service_name);
console.log('machine_name: ' + machine_name);
console.log('no exception!!');
} catch (err){
	console.log(err);
	service_name = 'epaywebservice';
	machine_name = 'demt1-uae-sv1p';
	console.log('service_name: ' + service_name);
	console.log('machine_name: ' + machine_name);
}*/

  //////////////////////////
  if(Os.platform() != 'win32'){
    console.log(`call of updatelogs`); 
   setInterval(()=> updateLogs(), (Number(logUpdateFrequency))*1000);
  }
  
  app.listen(Number(servicePORT), () => { 
    console.log(`Server started ...... ${servicePORT}`);  
  
  });
  } 
   

configureApplication();

