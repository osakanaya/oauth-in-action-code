var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var base64url = require('base64url');
var __ = require('underscore');
__.string = require('underscore.string');


var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// 認可サーバの情報
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize', // Authorization Endpoint
	tokenEndpoint: 'http://localhost:9001/token',             // Token Endopoint
	revocationEndpoint: 'http://localhost:9001/revoke',       // Revocation Endpoint
	registrationEndpoint: 'http://localhost:9001/register',   // Registration Endpoint
	userInfoEndpoint: 'http://localhost:9001/userinfo'        // Userinfo Endpoint
};

// 認可サーバの公開鍵
var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

// クライアント情報
var client = {
/*
	"client_id": "oauth-client-1",                        // クライアントID
	"client_secret": "oauth-client-secret-1",             // クライアントシークレット
	"redirect_uris": ["http://localhost:9000/callback"],  // リダイレクトURI
	"scope": "foo bar"                                    // 認可サーバに登録したクライアントが要求するスコープ
*/
};

// 保護リソースが効果するAPIのURL
var protectedResource = 'http://localhost:9002/resource';
var wordApi = 'http://localhost:9002/words';
var produceApi = 'http://localhost:9002/produce';
var favoritesApi = 'http://localhost:9002/favorites';

// 認可コードの取得に使用するstateパラメータ
var state = null;

// IDトークンの発行に使用するnonceパラメータ
var nonce = null;

var access_token = null;      // アクセストークン
var refresh_token = null;     // リフレッシュトークン
var scope = null;             // 実際にリソースオーナーによって認可サーバから委譲されたスコープ
var id_token = null;          // IDトークン（ペイロード）
var id_token_raw = null;      // IDトークン

// トップページを表示する
app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
});

// 認可サーバにリダイレクトする
app.get('/authorize', function(req, res){

	if (!client.client_id) {
    // クライアント情報が登録されていなかったら、Registration Endpointを使ってクライアントを登録する
		registerClient();
		if (!client.client_id) {
      // クライアント情報が登録できなかったらエラー
			res.render('error', {error: 'クライアントアプリケーションを登録できませんでした。'});
			return;
		}
	}
	
  // アクセストークンなどをいったんクリアする
	access_token = null;
	refresh_token = null;
	scope = null;
  
  // 認可コードの発行依頼に際し、stateパラメータを生成する
	state = randomstring.generate();
  
  // IDトークンの発行に際し、nonceパラメータを生成する
  nonce = randomstring.generate();
	
  // Authorization Endpointにリダイレクトする
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state,
    nonce: nonce
	});
	
	console.log("リダイレクト先：", authorizeUrl);
	res.redirect(authorizeUrl);
});

// Dynamic Client Registration：クライアントを動的に登録する
var registerClient = function() {
	
  // クライアントアプリケーションの登録情報
	var template = {
		client_name: 'OAuth in Action Dynamic Test Client',   // クライアントの名前
		client_uri: 'http://localhost:9000/',                 // クライアントのURL
    logo_uri: 'http://localhost:9000/logo',               // クライアントのロゴ
		redirect_uris: ['http://localhost:9000/callback'],    // リダイレクトURI
		grant_types: ['authorization_code', 'refresh_token'], // サポートする認可フローの種類
		response_types: ['code'],
		token_endpoint_auth_method: 'secret_basic',           // Token Endpointへクライアントアプリケーションが認証する方法（Authorizationヘッダによる認証）
		scope: 'openid profile email address phone'           // スコープ
	};

  // 登録リクエストを送る
	var headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	};
	
	var regRes = request('POST', authServer.registrationEndpoint, 
		{
			body: JSON.stringify(template),
			headers: headers
		}
	);
	
	if (regRes.statusCode == 201) {
		var body = JSON.parse(regRes.getBody());
		console.log("クライアントアプリケーションが認可サーバに登録されました：", body);
		if (body.client_id) {
			client = body;
		}
	}
};

// 認可サーバでの認可を受け取るコールバック
app.get("/callback", function(req, res){

	if (req.query.error) {
    // 認可の同意画面で拒否された場合や、登録されていないスコープを要求した場合
		res.render('error', {error: req.query.error});
		return;
	}
	
  // リクエスト時に送信したstateパラメータと、認可サーバから受け取ったstateパラメータが等しいことをチェックする
	var resState = req.query.state;
	if (resState == state) {
		console.log('stateパラメータの値がマッチしました。（認可コード発行リクエスト時の値：%s, 認可サーバから受け取った値：%s）', state, resState);
	} else {
		console.log('stateパラメータの値がマッチしません。（認可コード発行リクエスト時の値：%s, 認可サーバから受け取った値：%s）', state, resState);
		res.render('error', {error: 'stateパラメータの値がマッチしません'});
		return;
	}

  // 認可サーバが発行した認可コードを抽出する
	var code = req.query.code;

  // Token Endpointにアクセストークン発行をリクエストする
	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: client.redirect_uris[0]
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
    // クライアントアプリケーションのクライアントIDとクライアントシークレットを設定する
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	console.log('認可コード：%s に対するアクセストークンをリクエストしています...',code);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    // 正常終了した場合
		var body = JSON.parse(tokRes.getBody());

    // 発行されたアクセストークンを取得する
		access_token = body.access_token;
		console.log('アクセストークンが発行されました： %s', access_token);

		if (body.refresh_token) {
      // リフレッシュトークンが発行された場合
      // TODO:リフレッシュトークンの発行を試みる
			refresh_token = body.refresh_token;
			console.log('リフレッシュトークンが発行されました： %s', refresh_token);
		}

		if (body.id_token) {
      // IDトークンが発行された場合
			console.log('IDトークンが発行されました： %s', body.id_token);
      id_token_raw = body.id_token;
			
      /*
        IDトークンが正当性を検証する
      */
      
      // 認可サーバの公開鍵で、IDトークンの署名を検証する
			var pubKey = jose.KEYUTIL.getKey(rsaKey);
			var signatureValid = jose.jws.JWS.verify(body.id_token, pubKey, ['RS256']);
			if (signatureValid) {
        // 署名が正しい場合
				console.log('署名が検証されました。');
        // IDトークンのPayloadを抽出し、Base64URLデコードする
				var tokenParts = body.id_token.split('.');
				var payload = JSON.parse(base64url.decode(tokenParts[1]));
				console.log('IDトークンのペイロード：', payload);

        // nonceがある場合、それを付き合わせる
        if (payload.nonce) {
          if (payload.nonce == nonce) {
            console.log('nonceパラメータの値がマッチしました。（認可コード発行リクエスト時の値：%s, 認可サーバから受け取った値：%s）', nonce, payload.nonce);
          } else {
            console.log('nonceパラメータの値がマッチしません。（認可コード発行リクエスト時の値：%s, 認可サーバから受け取った値：%s）', nonce, payload.nonce);
            res.render('error', {error: 'nonceパラメータの値がマッチしません'});
            return;
          }
        }
        
				if (payload.iss == 'http://localhost:9001/') {
          // IDトークンが期待される認可サーバ（IdP）から発行されたかをチェック
					console.log('IDトークンの発行元　＝　OK');

					if ((Array.isArray(payload.aud) && _.contains(payload.aud, client.client_id)) || 
						payload.aud == client.client_id) {
            // IDトークンの発行先が自分自身であることをチェック
						console.log('IDトークンの発行先　＝　OK');
				
            // IDトークンの有効期限内であることをチェック
						var now = Math.floor(Date.now() / 1000);
				
						if (payload.iat <= now) {
							console.log('IDトークンの発行時刻≦現在時刻　＝　OK');
							if (payload.exp >= now) {
								console.log('IDトークンの有効期限≧現在時刻　＝　OK');
						
								console.log('IDトークンは正しいです！');
		
								id_token = payload;
						
							} else {
                console.log('IDトークンは有効期限切れです');
                res.render('error', {error: 'IDトークンは有効期限切れです'});
                return;
              }
						} else {
              console.log('IDトークンは有効期限切れです');
              res.render('error', {error: 'IDトークンは有効期限切れです'});
              return;
            }
					} else {
            console.log('IDトークンの発行先が正しくありません： %s', payload.aud);
            res.render('error', {error: 'IDトークンの発行先が正しくありません：'});
            return;
          }
				} else {
          console.log('IDトークンの発行元が正しくありません： %s', payload.iss);
          res.render('error', {error: 'IDトークンの発行元が正しくありません'});
          return;
        }
			} else {
        console.log('IDトークンの署名を検証できませんでした');
        res.render('error', {error: 'IDトークンの署名を検証できませんでした'});
        return;
      }
		}
		
    // スコープを抽出する
		scope = body.scope;
		console.log('実際に認可されたスコープ： %s', scope);

    // トップページを表示する
		res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
	} else {
		res.render('error', {error: 'アクセストークンを取得できませんでした。認可サーバのレスポンス：: ' + tokRes.statusCode})
	}
});

// リフレッシュトークンからアクセストークンを再発行する
var refreshAccessToken = function(req, res) {
  // Token Endpointへリクエストする
  // TODO:クライアントIDとクライアントシークレットは、Authorizationヘッダに設定すべきでは？（たぶんバグ）
	var form_data = qs.stringify({
				grant_type: 'refresh_token',
				refresh_token: refresh_token,
				client_id: client.client_id,
				client_secret: client.client_secret,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	console.log('リフレッシュトークンを使ってアクセストークンを再発行します： %s', refresh_token);
	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
  
  // アクセストークンが再発行された場合
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log('アクセストークンが再発行されました： %s', access_token);

    // リフレッシュトークンも受信した場合
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log('リフレッシュトークンが発行されました %s', refresh_token);
		}
    
		scope = body.scope;
		console.log('実際に認可されたスコープ： %s', scope);
	
    // 再度、リダイレクトして保護リソースへのアクセスを試みる
		res.redirect('/fetch_resource');
		return;
	} else {
    // リフレッシュトークンからアクセストークンが再発行できなかった場合
		console.log('リフレッシュトークンが無いため、ユーザに新しいアクセストークンを取得するように要求します');
    
    // 認可サーバの同意画面へ結果的にリダイレクトする
		res.redirect('/authorize');
		return;
	}
};

// 保護リソースにアクセスする
// TODO:他の保護リソースへのアクセスを実現する
// TODO:IDトークンの正当性をチェックする（有効期限）
// TODO:アクセストークンのみのRevocationを試す（リフレッシュトークンによる発行を確認するため）
app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
	console.log('保護リソースへリクエストします。 アクセストークン： %s', access_token);
	
	var headers = {
    // Authorizationヘッダにはアクセストークンを設定する
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
    // 保護リソースへのアクセスが正常終了した場合
		var body = JSON.parse(resource.getBody());
		res.render('data', {resource: body});
		return;
	} else {
    // 保護リソースへのアクセスでエラーがあった場合
    
    // アクセストークンをクリアする
		access_token = null;
		if (refresh_token) {
      // リフレッシュトークンがあれば、アクセストークンを再発行し、再度保護リソースへのアクセスを試みる
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: 'サーバがレスポンスコードを返しました： ' + resource.statusCode});
			return;
		}
	}
	
	
});

app.get('/words', function (req, res) {

	res.render('words', {words: '', timestamp: 0, result: null});
	
});

app.get('/get_words', function (req, res) {

	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('GET', wordApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('words', {words: body.words, timestamp: body.timestamp, result: 'get'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'noget'});
		return;
	}
	
	
	
});

app.get('/add_word', function (req, res) {
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var form_body = qs.stringify({word: req.query.word});
	
	var resource = request('POST', wordApi,
		{headers: headers, body: form_body}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		res.render('words', {words: '', timestamp: 0, result: 'add'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'noadd'});
		return;
	}
	

});

app.get('/delete_word', function (req, res) {

	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('DELETE', wordApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		res.render('words', {words: '', timestamp: 0, result: 'rm'});
		return;
	} else {
		res.render('words', {words: '', timestamp: 0, result: 'norm'});
		return;
	}
	
	
});

app.get('/produce', function(req, res) {
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('GET', produceApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('produce', {scope: scope, data: body});
		return;
	} else {
		res.render('produce', {scope: scope, data: {fruits: [], veggies: [], meats: []}});
		return;
	}
	
});

app.get('/favorites', function(req, res) {
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('GET', favoritesApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		console.log('Got data: ', body);
		res.render('favorites', {scope: scope, data: body});
		return;
	} else {
		res.render('favorites', {scope: scope, data: {user: '', favorites: {movies: [], foods: [], music: []}}});
		return;
	}
	
});

app.get('/revoke', function(req, res) {
	res.render('revoke', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

app.post('/revoke', function(req, res) {
	var form_data = qs.stringify({
		token: access_token
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
 		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};
	console.log('Revoking token %s', access_token);
	var tokRes = request('POST', authServer.revocationEndpoint, 
		{
			body: form_data,
			headers: headers
		}
	);
	
	access_token = null;
	refresh_token = null;
	scope = null;
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		res.render('revoke', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		return;
	} else {
		res.render('error', {error: tokRes.statusCode});
		return;
	}
});

app.get('/userinfo', function(req, res) {
	
	var headers = {
		'Authorization': 'Bearer ' + access_token
	};
	
	var resource = request('GET', authServer.userInfoEndpoint,
		{headers: headers}
	);
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		console.log('Got data: ', body);
	
		userInfo = body;
	
		res.render('userinfo', {userInfo: userInfo, id_token: id_token});
		return;
	} else {
		res.render('error', {error: 'Unable to fetch user information'});
		return;
	}
	
});

app.get('/username_password', function(req, res) {
	res.render('username_password');
	return;
});

app.post('/username_password', function(req, res) {
	
	var username = req.body.username;
	var password = req.body.password;
	
	var form_data = qs.stringify({
				grant_type: 'password',
				username: username,
				password: password
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
	
	
});

app.use('/', express.static('files/client'));

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
