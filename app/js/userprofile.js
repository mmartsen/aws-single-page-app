var myHeaders = new Headers();
myHeaders.set('Cache-Control', 'no-store');
var urlParams = new URLSearchParams(window.location.search);
var tokens;
var domain = "userpooldomain22";
var region = "us-east-1";
var appClientId = "3qcg6gkru07t060v1e6qsl02bp";
var userPoolId = "us-east-1_HJdp7hk04";
var redirectURI = "https://d12yjhtzddnsz5.cloudfront.net/index.html";
var privateBucketName = "single-page-app-via-cloudfront7-d-privates3bucket-1lxo07edtal1w";
var identityPoolId = 'us-east-1:e6b020ae-27c9-4cba-87f0-d02e5f7cb931';


//Convert Payload from Base64-URL to JSON
const decodePayload = payload => {
  const cleanedPayload = payload.replace(/-/g, '+').replace(/_/g, '/');
  const decodedPayload = atob(cleanedPayload)
  const uriEncodedPayload = Array.from(decodedPayload).reduce((acc, char) => {
    const uriEncodedChar = ('00' + char.charCodeAt(0).toString(16)).slice(-2)
    return `${acc}%${uriEncodedChar}`
  }, '')
  const jsonPayload = decodeURIComponent(uriEncodedPayload);

  return JSON.parse(jsonPayload)
}

//Parse JWT Payload
const parseJWTPayload = token => {
  const [header, payload, signature] = token.split('.');
  const jsonPayload = decodePayload(payload)

  return jsonPayload
};

//Parse JWT Header
const parseJWTHeader = token => {
  const [header, payload, signature] = token.split('.');
  const jsonHeader = decodePayload(header)

  return jsonHeader
};

//Generate a Random String
const getRandomString = () => {
  const randomItems = new Uint32Array(28);
  crypto.getRandomValues(randomItems);
  const binaryStringItems = randomItems.map(dec => `0${dec.toString(16).substr(-2)}`)
  return binaryStringItems.reduce((acc, item) => `${acc}${item}`, '');
}

//Encrypt a String with SHA256
const encryptStringWithSHA256 = async str => {
  const PROTOCOL = 'SHA-256'
  const textEncoder = new TextEncoder();
  const encodedData = textEncoder.encode(str);
  return crypto.subtle.digest(PROTOCOL, encodedData);
}

//Convert Hash to Base64-URL
const hashToBase64url = arrayBuffer => {
  const items = new Uint8Array(arrayBuffer)
  const stringifiedArrayHash = items.reduce((acc, i) => `${acc}${String.fromCharCode(i)}`, '')
  const decodedHash = btoa(stringifiedArrayHash)

  const base64URL = decodedHash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return base64URL
}

// Main Function
async function main() {
  var code = urlParams.get('code');

  //If code not present then request code else request tokens
  if (code == null) {

    // Create random "state"
    var state = getRandomString();
    sessionStorage.setItem("pkce_state", state);

    // Create PKCE code verifier
    var code_verifier = getRandomString();
    sessionStorage.setItem("code_verifier", code_verifier);

    // Create code challenge
    var arrayHash = await encryptStringWithSHA256(code_verifier);
    var code_challenge = hashToBase64url(arrayHash);
    sessionStorage.setItem("code_challenge", code_challenge)

    // Redirtect user-agent to /authorize endpoint
    location.href = "https://" + domain + ".auth." + region + ".amazoncognito.com/oauth2/authorize?response_type=code&state=" + state + "&client_id=" + appClientId + "&redirect_uri=" + redirectURI + "&scope=openid&code_challenge_method=S256&code_challenge=" + code_challenge;
  } else {

    // Verify state matches
    state = urlParams.get('state');
    if (sessionStorage.getItem("pkce_state") != state) {
      alert("Invalid state");
    } else {

      // Fetch OAuth2 tokens from Cognito
      code_verifier = sessionStorage.getItem('code_verifier');
      await fetch("https://" + domain + ".auth." + region + ".amazoncognito.com/oauth2/token?grant_type=authorization_code&client_id=" + appClientId + "&code_verifier=" + code_verifier + "&redirect_uri=" + redirectURI + "&code=" + code, {
        method: 'post',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      })
        .then((response) => {
          return response.json();
        })
        .then((data) => {

          // Verify id_token
          tokens = data;
          var idVerified = verifyToken(tokens.id_token);
          Promise.resolve(idVerified).then(function (value) {
            if (value.localeCompare("verified")) {
              alert("Invalid ID Token - " + value);
              return;
            }
          });
          // Display tokens
          document.getElementById("id_token").innerHTML = JSON.stringify(parseJWTPayload(tokens.id_token), null, '\t');
          document.getElementById("access_token").innerHTML = JSON.stringify(parseJWTPayload(tokens.access_token), null, '\t');
        });

      // Fetch from /user_info
      await fetch("https://" + domain + ".auth." + region + ".amazoncognito.com/oauth2/userInfo", {
        method: 'post',
        headers: {
          'authorization': 'Bearer ' + tokens.access_token
        }
      })
        .then((response) => {
          return response.json();
        })
        .then((data) => {
          // Display user information
          document.getElementById("userInfo").innerHTML = JSON.stringify(data, null, '\t');
        });

      // Fetch S3 private info
      AWS.config.region = region;
      console.log(`A TOKEN: ${tokens.id_token}`);
      var identityLogin = {};
      identityLogin[`cognito-idp.${region}.amazonaws.com/${userPoolId}`] = tokens.id_token;
      AWS.config.credentials = new AWS.CognitoIdentityCredentials({
        IdentityPoolId: identityPoolId, 
        Logins: identityLogin,
      });
      //refreshes credentials using AWS.CognitoIdentity.getCredentialsForIdentity()
      AWS.config.credentials.refresh(async error => {
        if (error) {
          console.error(error);
        } else {
          console.log('Successfully logged!');
          // Instantiate aws sdk service objects now that the credentials have been updated.
          var s3 = new AWS.S3();
          await s3.listObjects({ Bucket: privateBucketName }).promise().then(
            data => {
              console.log('Successfully retrieved bucket files list');
              document.getElementById("bucket").innerHTML = JSON.stringify(data, null, '\t');
            },
            error => {
              console.error(error);
            }
          );
        }
      });
    }
  }
}
main();
