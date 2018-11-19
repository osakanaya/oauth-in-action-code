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

// 認可サーバの公開鍵
var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

// 保護リソースのリソースIDとリソースシークレット
var protectedResources = {
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
};

// 認可サーバのIntrospection EndpointのURL
var authServer = {
	introspectionEndpoint: 'http://localhost:9001/introspect'
};

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
  
  // 認可サーバの公開鍵
	var pubKey = jose.KEYUTIL.getKey(rsaKey);
  
  // アクセストークンの署名を検証する
	var signatureValid = jose.jws.JWS.verify(inToken, pubKey, ['RS256']);
	if (signatureValid) {
    console.log('署名が検証されました');

    // アクセストークンのペイロードを抽出し、Base64URLエンコードする
		var tokenParts = inToken.split('.');
		var payload = JSON.parse(base64url.decode(tokenParts[1]));
		console.log('アクセストークンのペイロード', payload);
    
		if (payload.iss == 'http://localhost:9001/') {
      // アクセストークンが期待される認可サーバから発行されたかをチェック
			console.log('アクセストークンの発行元　＝　OK');
			if ((Array.isArray(payload.aud) && _.contains(payload.aud, 'http://localhost:9002/')) || 
				payload.aud == 'http://localhost:9002/') {
        // アクセストークンの発行先が自分であることをチェック
				console.log('アクセストークンの発行先　＝　OK');
				
        // アクセストークンが有効期限切れでないことをチェック
				var now = Math.floor(Date.now() / 1000);
				
				if (payload.iat <= now) {
					console.log('アクセストークンの発行時刻≦現在時刻　＝　OK');
					if (payload.exp >= now) {
						console.log('アクセストークンの有効期限≧現在時刻　＝　OK');
						
						console.log('アクセストークンはOKです！');
					} else {
            next();
            return;
          }
				} else {
          next();
          return;
        }
			} else {
        next();
        return;
      }
		} else {
      next();
      return;
    }
	}

  // Introspection Endpointにアクセストークンの情報を問い合わせる
	var form_data = qs.stringify({
		token: inToken
	});
  
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
    // Authorizationヘッダには、保護リソースのリソースIDとリソースシークレットを指定する
		'Authorization': 'Basic ' + new Buffer(querystring.escape(protectedResources.resource_id) + ':' + querystring.escape(protectedResources.resource_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.introspectionEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    // 認可サーバ上でも当該アクセストークンがアクティブであれば、よしとする
    var body = JSON.parse(tokRes.getBody());
	
		console.log('Introspection Endpointからの応答： ', body);
		var active = body.active;
		if (active) {
			req.access_token = body;
		}
	}
  
	next();
	return;
	
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

  var scopes = req.access_token.scope.split(' ');
  
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

  var scopes = req.access_token.scope.split(' ');

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

  var scopes = req.access_token.scope.split(' ');

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

  var scopes = req.access_token.scope.split(' ');

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
var aliceFavorites = {
	'movies': ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'],
	'foods': ['bacon', 'pizza', 'bacon pizza'],
	'music': ['techno', 'industrial', 'alternative']
};

var bobFavories = {
	'movies': ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'],
	'foods': ['bacon', 'kale', 'gravel'],
	'music': ['baroque', 'ukulele', 'baroque ukulele']
};

app.options('/favorites', cors());
app.get('/favorites', getAccessToken, requireAccessToken, function(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');

	if (req.access_token.user == 'Alice') {
		res.json({user: 'Alice', favorites: aliceFavorites});
	} else if (req.access_token.user == 'Bob') {
		res.json({user: 'Bob', favorites: bobFavorites});
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
 
