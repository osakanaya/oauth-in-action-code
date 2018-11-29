var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var base64url = require('base64url');
var jose = require('jsrsasign');
var jwksrsa = require('jwks-rsa');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

// クライアントアプリケーションに返却するリソースデータ
var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

// 認可サーバの情報
var authServer = {
  jwks_uri: 'https://login.microsoftonline.com/common/discovery/keys'
};

// 認可サーバの公開鍵を取得するためのクライアント
var jwksClient = jwksrsa({
  jwksUri: authServer.jwks_uri
});

// リクエストに含まれるアクセストークンを取得する
var getAccessToken = function(req, res, next) {

  // Authorizationヘッダにアクセストークンが指定されたかをチェック
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
    // フォームパラメータにアクセストークンが指定された場合
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
    // クエリパラメータにアクセストークンが指定された場合
		inToken = req.query.access_token
	}
	
	console.log('クライアントアプリケーションから受信したアクセストークン： %s', inToken);

  /*
    JWT形式のアクセストークンの内容を検証する
  */
  
  // アクセストークンのヘッダとペイロードを抽出し、Base64URLデコードする
  var tokenParts = inToken.split('.');
  var header = JSON.parse(base64url.decode(tokenParts[0]));
  var payload = JSON.parse(base64url.decode(tokenParts[1]));

  console.log('アクセストークンのヘッダ:', JSON.stringify(header, null, 2));
  console.log('アクセストークンのペイロード:', JSON.stringify(payload, null, 2));
  
  jwksClient.getSigningKey(header.kid, function(err, key) {
    // アクセストークンの署名を検証する
    var signatureValid = jose.jws.JWS.verify(inToken, key.publicKey, ['RS256']);
    if (signatureValid) {
      console.log('署名が検証されました');
      
      if (payload.iss == 'https://sts.windows.net/<replace me>/') {
        // アクセストークンが期待される認可サーバから発行されたかをチェック
        console.log('アクセストークンの発行元　＝　OK');
        if ((Array.isArray(payload.aud) && _.contains(payload.aud, 'api://<replace me>')) || 
          payload.aud == 'api://<replace me>') {
          // アクセストークンの発行先が自分であることをチェック
          console.log('アクセストークンの発行先　＝　OK');
          
          // アクセストークンが有効期限切れでないことをチェック
          var now = Math.floor(Date.now() / 1000);
          
          if (payload.iat <= now) {
            console.log('アクセストークンの発行時刻≦現在時刻　＝　OK');
            if (payload.exp >= now) {
              console.log('アクセストークンの有効期限≧現在時刻　＝　OK');
              console.log('アクセストークンはOKです！');
              
              req.access_token = payload;
            }
          }
        }
      }
    }
    
    next();
    return;
  });

};

// アクセストークンの存在を確認する（存在しなければエラー）
var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};


// 保存された単語のリスト
var savedWords = [];

app.options('/words', cors());

app.get('/words', getAccessToken, requireAccessToken, function(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

  var scopes = req.access_token.scp.split(' ');
  
	if (__.contains(scopes, 'read')) {
    res.json({words: savedWords.join(' '), timestamp: Date.now()});
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="read"');
		res.status(403).end();
	}
});

// リストに単語を追加する
app.post('/words', getAccessToken, requireAccessToken, function(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

  var scopes = req.access_token.scp.split(' ');

	if (__.contains(scopes, 'write')) {
		if (req.body.word) {
      // XSS対策：エスケープして保存する
			savedWords.push(querystring.escape(req.body.word));
		}
		res.status(201).end();
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"');
		res.status(403).end();
	}
});

// リストから単語を削除する
app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

  var scopes = req.access_token.scp.split(' ');

	if (__.contains(scopes, 'delete')) {
		savedWords.pop();
		res.status(201).end();
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="delete"');
		res.status(403).end();
	}
});

// 好きな農産物のリストを表示する
app.options('/produce', cors());
app.get('/produce', getAccessToken, requireAccessToken, function(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

  var scopes = req.access_token.scp.split(' ');

	var produce = {fruit: [], veggies: [], meats: []};
	if (__.contains(scopes, 'fruit')) {
		produce.fruit = ['apple', 'banana', 'kiwi'];
	}
	if (__.contains(scopes, 'veggies')) {
		produce.veggies = ['lettuce', 'onion', 'potato'];
	}
	if (__.contains(scopes, 'meats')) {
		produce.meats = ['bacon', 'steak', 'chicken breast'];
	}
	res.json(produce);
});

// 好物を取得
var hideoFavorites = {
	'movies': ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'],
	'foods': ['bacon', 'pizza', 'bacon pizza'],
	'music': ['techno', 'industrial', 'alternative']
};

app.options('/favorites', cors());
app.get('/favorites', getAccessToken, requireAccessToken, function(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

	if (req.access_token.oid == '1cc9d9e3-bf8d-4200-88e3-c16c044fc53b') {
		res.json({user: 'Alice', favorites: hideoFavorites});
	} else {
		var unknown = {user: 'Unknown', favorites: {movies: [], foods: [], music: []}};
		res.json(unknown);
	}
});

// 基本的なデータを取得する
app.options('/resource', cors());
app.post("/resource", cors(), getAccessToken, function(req, res){
  // XSS対策
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // ウェブサイトがHTTPの代わりにHTTPSを用いて通信を行うようにブラウザに指示する
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

  // アクセストークンが指定されたかどうかをチェックする
	if (req.access_token) {
    // アクセストークンがあれば、リソースを返却する
		res.json(resource);
	} else {
		res.status(401).end();
	}
	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
