var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var qs = require("qs");
var __ = require('underscore');
__.string = require('underscore.string');
var base64url = require('base64url');
var jose = require('jsrsasign');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
// 認可サーバの情報
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',   // AuthorizationEndpoint
	tokenEndpoint: 'http://localhost:9001/token',               // Token Endpoint
  introspectionEndpoint: 'http://localhost:9001/introspect',  // Introspection Endpoint
	registrationEndpoint: 'http://localhost:9001/register',     // Registration Endpoint
	revocationEndpoint: 'http://localhost:9001/revoke',         // Revocation Endopoint
  // TODO:その他のエンドポイント情報を乗せ、トップページで表示できるようにする
};

// 認可サーバに登録されているクライアントアプリケーションの情報
var clients = [
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "foo bar",
		"logo_uri": "https://images.manning.com/720/960/resize/book/e/14336f9-6493-46dc-938c-11a34c9d20ac/Richer-OAuth2-HI.png",
		"client_name": "OAuth in Action Exercise Client"
	},
	{
		"client_id": "oauth-client-2",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "bar"
	},
	{
		"client_id": "native-client-1",
		"client_secret": "oauth-native-secret-1",
		"redirect_uris": ["mynativeapp://"],
		"scope": "openid profile email phone address"
	}
];

// 共有鍵の情報
// TODO:これ使われているの？
var sharedTokenSecret = "shared token secret!";

// 認可サーバの公開鍵と秘密鍵
var rsaKey = {
  "alg": "RS256",
  "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};

// 保護リソースの情報
// Introspection Endpointに問い合わせる保護リソースを認証するために使用する
var protectedResources = [
	{
		"resource_id": "protected-resource-1",            // リソースID
		"resource_secret": "protected-resource-secret-1"  // リソースシークレット
	}
];

// ユーザ情報（OpenID Connectで認証されるユーザの情報となる）
var userInfo = {

	"alice": {
		"sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"email": "alice.wonderland@example.com",
		"email_verified": true
	},
	
	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"email": "bob.loblob@example.net",
		"email_verified": false
	},

	"carol": {
		"sub": "F5Q1-L6LGG-959FS",
		"preferred_username": "carol",
		"name": "Carol",
		"email": "carol.lewis@example.net",
		"email_verified": true,
		"username" : "clewis",
		"password" : "user password!"
 	}	
};

// 認可コード
var codes = {};

// 認可コード発行時のリクエスト情報
var requests = {};

// クライアントIDをキーに、登録されているクライアントアプリケーションを得る
var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

// リソースIDをキーに、登録されている保護リソースを得る
var getProtectedResource = function(resourceId) {
	return __.find(protectedResources, function(resource) { return resource.resource_id == resourceId; });
};


// usernameからユーザ情報を得る
var getUser = function(username) {
	return userInfo[username];
};

// トップページを表示する
app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

// 認可に関する同意画面を表示する
app.get("/authorize", function(req, res){
	
	var client = getClient(req.query.client_id);
	
	if (!client) {
    // 登録されているクライアントがなければエラー
		console.log('Unknown client %s', req.query.client_id);
		res.render('error', {error: '未知のクライアント'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log('リダイレクトURIがマッチしません（期待されるURI：%s, 指定されたURI：%s', client.redirect_uris, req.query.redirect_uri);
		res.render('error', {error: '不正なリダイレクトURI'});
		return;
	} else {
		// クライアントアプリケーションがリクエストしたスコープ
		var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
    // 登録されたクライアントに設定されたスコープ
		var cscope = client.scope ? client.scope.split(' ') : undefined;

    // 登録されていないスコープをリクエストした場合、エラー
		if (__.difference(rscope, cscope).length > 0) {
			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'invalid_scope'
			});
			res.redirect(urlParsed);
			return;
		}
		
    // リクエストIDを生成する
		var reqid = randomstring.generate(8);
		
    // 生成したリクエストIDをキーに、認可コードの発行リクエストを保存しておく
		requests[reqid] = req.query;
		
    // 同意画面を表示する
		res.render('approve', {client: client, reqid: reqid, scope: rscope});
		return;
	}

});

// Authorization Endpoint：同意画面での認可・拒否を処理する
app.post('/approve', function(req, res) {

  // 同意画面のHIDDENパラメータから受け取ったリクエストID
	var reqid = req.body.reqid;
  // 認可コードの発行リクエスト
	var query = requests[reqid];
  // 発行リクエストは再利用させないので、削除する
	delete requests[reqid];

	if (!query) {
    // 認可コードの発行リクエストがない場合は、エラー
		res.render('error', {error: 'マッチする認可リクエストがありません'});
		return;
	}

	if (req.body.approve) {
    // リソースオーナーがクライアントアプリケーションを認可した場合
		if (query.response_type == 'code') {
      // Authorization Code Grantの場合

      // 認可コードを生成する
			var code = randomstring.generate(8);
			
      // 同意画面で選択したユーザ＝認可サーバで認証したユーザを取得する
			var user = req.body.user;
      
      // リソースオーナーが同意画面で指定したスコープ
			var scope = getScopesFromForm(req.body);

      // クライアントアプリケーションとして登録されたスコープ
			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
      // リソースオーナーが指定したスコープ＞登録されたスコープの場合、エラー
			if (__.difference(scope, cscope).length > 0) {
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

      // 後続のトークン発行リクエストに備えて、認可コードをキーとして、認可コード発行リクエスト、スコープ、認証済みユーザ、クライアントIDを保存しておく
			codes[code] = { request: query, scope: scope, user: user, clientId: query.clientId };

      // クライアントアプリケーションにリダイレクトする
			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
		} else if (query.response_type == 'token') {
			var user = req.body.user;
		
			var scope = getScopesFromForm(req.body);

			var client = getClient(query.client_id);
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				var urlParsed = buildUrl(query.redirect_uri, {
					error: 'invalid_scope'
				});
				res.redirect(urlParsed);
				return;
			}

			var user = userInfo[user];
			if (!user) {		
				console.log('Unknown user %s', user)
				res.status(500).render('error', {error: 'Unknown user ' + user});
				return;
			}
	
			console.log("User %j", user);

			var token_response = generateTokens(req, res, query.clientId, user, cscope);		

			var params = {};
			if (query.state) {
				params.state = query.state;
			} 				
			var urlParsed = buildUrl(query.redirect_uri, params, qs.stringify(token_response));
			res.redirect(urlParsed);
			return;

		} else {
			// we got a response type we don't understand
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
			return;
		}
	} else {
    // リソースオーナーがクライアントアプリケーションを認可しなかった場合
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'アクセスが拒否されました'
		});
    
    // リダイレクトURIへリダイレクトする
		res.redirect(urlParsed);
		return;
	}
	
});

// リフレッシュトークンを生成し、登録する
var generateRefreshToken = function(clientId, user, scope) {
  var refresh_token = randomstring.generate();

  // リフレッシュトークンを登録する
  nosql.insert({ token_type: 'refresh_token', refresh_token: refresh_token, client_id: clientId, scope: scope, user: user });
  console.log('リフレッシュトークンを発行しました： %s', refresh_token);

  return refresh_token;
};

// アクセストークンを生成する
var generateAccessToken = function(clientId, user, scope, refresh_token) {
  // ヘッダ
	var at_header = { 'typ': 'JWT', 'alg': 'RS256', 'kid': rsaKey.kid};

  // ペイロード
	var at_payload = {};
	at_payload.iss = 'http://localhost:9001/';                 // アクセストークンの発行元（認可サーバ）
	at_payload.sub = user;                                     // アクセストークンのサブジェクト（リソースオーナー）
	at_payload.aud = 'http://localhost:9002/';                 // アクセストークンの発行先（保護リソース）
	at_payload.iat = Math.floor(Date.now() / 1000);            // アクセストークンの発行日時
	at_payload.exp = Math.floor(Date.now() / 1000) + (5 * 60); // アクセストークンの有効期限
	at_payload.jti = randomstring.generate();                  // アクセストークンの識別子
	console.log('アクセストークンのペイロード：', at_payload);

  // ヘッダ、ペイロードを文字列にする
	var at_stringHeader = JSON.stringify(at_header);
	var at_stringPayload = JSON.stringify(at_payload);

  // 署名されたアクセストークンを作成する
  // 認可サーバの秘密鍵
	var privateKey = jose.KEYUTIL.getKey(rsaKey);
  // アクセストークンに署名する
	var access_token = jose.jws.JWS.sign('RS256', at_stringHeader, at_stringPayload, privateKey);
  
  // アクセストークンを登録する
	nosql.insert({ token_type: 'access_token', access_token: access_token, refresh_token: refresh_token, client_id: clientId, scope: scope, user: user, iss: at_payload.iss, iat: at_payload.iat, exp: at_payload.exp });
	console.log('アクセストークンを発行しました： %s', access_token);
	console.log('アクセストークンのスコープ： %s', scope);
  
  return access_token;
};

// IDトークンを生成する
var generateIdToken = function(clientId, user, nonce) {

  // ヘッダ
  var it_header = { 'typ': 'JWT', 'alg': 'RS256', 'kid': rsaKey.kid};
  
  // ペイロード
  var it_payload = {};
  it_payload.iss = 'http://localhost:9001/';                    // IDトークンの発行元（IdP）
  it_payload.sub = user.sub;                                    // IDトークンのサブジェクト（ユーザ）
  it_payload.aud = clientId;                                    // IDトークンの発行先（クライアントID）
  it_payload.iat = Math.floor(Date.now() / 1000);               // IDトークンの発行日時
  it_payload.exp = Math.floor(Date.now() / 1000) + (5 * 60);    // IDトークンの有効期限

  // nonceが指定されていればそれを含める
  if (nonce) {
    it_payload.nonce = nonce;
  }

  // ヘッダ、ペイロードを文字列にする
  var it_stringHeader = JSON.stringify(it_header);
  var it_stringPayload = JSON.stringify(it_payload);
  
  // 署名されたIDトークンを作成する
  // 認可サーバの秘密鍵
	var privateKey = jose.KEYUTIL.getKey(rsaKey);

  // IDトークンに署名する
  var id_token = jose.jws.JWS.sign('RS256', it_stringHeader, it_stringPayload, privateKey);

  console.log('IDトークンを発行しました： %s', id_token);
  return id_token;
};

// アクセストークン、リフレッシュトークン、IDトークンを生成する
var generateTokens = function (req, res, clientId, user, scope, nonce, needsRefreshToken) {
  
  // リフレッシュトークンを生成する
  var refresh_token;
  if (needsRefreshToken) {
    refresh_token = generateRefreshToken(clientId, user, scope);
  }
  
  // アクセストークンを生成する
  var access_token = generateAccessToken(clientId, user, scope, refresh_token);

  // スコープに「openid」が含まれていれば、IDトークンを生成する
  var id_token;

  if (__.contains(scope, 'openid') && user) {
    id_token = generateIdToken(clientId, user, nonce);
  }
  
  // レスポンスを返す
	var cscope = null;
	if (scope) {
		cscope = scope.join(' ')
	}

	var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: cscope, id_token: id_token };

	return token_response;
};

// Token Endpoint：アクセストークンを発行する
app.post("/token", function(req, res){

  // AuthorizationヘッダにあるクライアントIDとクライアントシークレットを取得する
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
		var clientId = querystring.unescape(clientCredentials[0]);
		var clientSecret = querystring.unescape(clientCredentials[1]);
	}

	if (req.body.client_id) {
		if (clientId) {
      // Authorizationヘッダとフォームパラメータの両方にクライアントIDがある場合は、エラーとする
			console.log('クライアントが複数の方法で認証しようとしています');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}

	var client = getClient(clientId);
	if (!client) {
    // クライアントアプリケーションが登録されていない場合は、エラー
		console.log('未知のクライアントアプリケーション %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
    // クライアントシークレットが一致していない場合は、エラー
		console.log('クライアントシークレットが一致しません（期待される値： %s, 実際の値： %s）', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		/*
      Authorization Code Grantの場合
    */
    
    // 保存しておいた認可コード発行リクエストを取得する
		var code = codes[req.body.code];
		
		if (code) {
      // 認可コード発行リクエストがあった場合
      
      // 認可コードは1回限りのものなので、発行リクエストを削除する
			delete codes[req.body.code];
			if (code.request.client_id == clientId) {
        // 認可コード発行リクエストと認証情報のクライアントIDが一致する場合

        // アクセストークン、リフレッシュトークン、IDトークンを発行する
				var token_response = generateTokens(req, res, clientId, code.user, code.scope, code.request.nonce, true);

				res.status(200).json(token_response);
				console.log('認可コード： %sに対してアクセストークンを発行しました', req.body.code);
				
				return;
			} else {
        // 認可コード発行リクエストと認証情報のクライアントIDが一致しない場合、エラー
				console.log('クライアントアプリケーションが一致しません（期待されるクライアントID： %s, 実際のクライアントID： %s）', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		} else {
      // 認可コード発行リクエストがない場合
			console.log('未知の認可コード： %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else if (req.body.grant_type == 'client_credentials') {
		var scope = req.body.scope ? req.body.scope.split(' ') : undefined;
		var client = getClient(query.client_id);
		var cscope = client.scope ? client.scope.split(' ') : undefined;
		if (__.difference(scope, cscope).length > 0) {
			// client asked for a scope it couldn't have
			res.status(400).json({error: 'invalid_scope'});
			return;
		}

		var access_token = randomstring.generate();
		var token_response = { access_token: access_token, token_type: 'Bearer', scope: scope.join(' ') };
		nosql.insert({ access_token: access_token, client_id: clientId, scope: scope });
		console.log('Issuing access token %s', access_token);
		res.status(200).json(token_response);
		return;	
		
	} else if (req.body.grant_type == 'refresh_token') {
    // リフレッシュトークンを発行する
    
    // リフレッシュトークンが存在するかを確認する
		nosql.all(function(token) {
			return (token.token_type == 'refresh_token' && token.refresh_token == req.body.refresh_token);
		}, function(err, tokens) {
			if (tokens.length == 1) {
        // すでに発行済みのリフレッシュトークンが見つかった
				var token = tokens[0];
				if (token.client_id != clientId) {
          // リフレッシュトークンの発行先のクライアントIDと、実際のクライアントIDが異なる場合はエラー
					console.log('クライアントが不正です（期待されるクライアントID： %s, 実際のクライアントID： %s）', token.client_id, clientId);
          
          // エラーの場合、リフレッシュトークンを削除してしまう
					nosql.remove(function(found) { return (found == token); }, function () {} );
					res.status(400).end();
					return
				}
        
				console.log("一致するリフレッシュトークンが見つかりました： %s", req.body.refresh_token);
        
        // アクセストークンを再発行する
        var access_token = generateAccessToken(clientId, token.user, token.scope, req.body.refresh_token);
        
        // レスポンスを返す
        var cscope = null;
        if (token.scope) {
          cscope = token.scope.join(' ');
        }
        
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: req.body.refresh_token, scope: cscope };

        console.log('アクセストークンを再発行しました（アクセストークン： %s, リフレッシュトークン： %s）', access_token, req.body.refresh_token);
				res.status(200).json(token_response);
				return;
			} else {
				console.log('マッチするリフレッシュトークンはありませんでした。');
				res.status(401).end();
			}
		});
	} else if (req.body.grant_type == 'password') {
    // TODO: Resource Owner Password Credentials Grant
		var username = req.body.username;
		var user = getUser(username);
		if (!user) {
			console.log('Unknown user %s', user);
			res.status(401).json({error: 'invalid_grant'});
			return;
		}
		console.log("user is %j ", user)
		
		var password = req.body.password;
		if (user.password != password) {
			console.log('Mismatched resource owner password, expected %s got %s', user.password, password);
			res.status(401).json({error: 'invalid_grant'});
			return;
		}

		var scope = req.body.scope;

		var token_response = generateTokens(req, res, clientId, user, scope);
		
		res.status(200).json(token_response);		
		return;
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

// Revocation Endpointの実装
app.post('/revoke', function(req, res) {

  /*
    クライアント認証情報を確認する
  */
  
	var auth = req.headers['authorization'];
	if (auth) {
    // Authorizationヘッダを確認する
		var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
		var clientId = querystring.unescape(clientCredentials[0]);
		var clientSecret = querystring.unescape(clientCredentials[1]);
	}
	
	// フォームパラメータを確認する
	if (req.body.client_id) {
		if (clientId) {
      // Authorizationヘッダとフォームパラメータの両方にクライアントIDがある場合は、エラーとする
			console.log('クライアントが複数の方法で認証しようとしています');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
  // クライアントが登録されているかを確認する
	var client = getClient(clientId);
	if (!client) {
    // クライアントが存在しない場合、エラー
		console.log('未知のクライアント： %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
  // クライアントシークレットが一致しない場合は、エラー
	if (client.client_secret != clientSecret) {
		console.log('クライアントシークレットが一致しません（期待される値： %s, 実際の値： %s）', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

  // token_type_hintが指定されていない場合は、refresh_tokenを設定
  var inTokenType = req.body.token_type_hint;
  
  if (!inTokenType) {
      inTokenType = 'refresh_token';
  }
  // トークンの種類が不正の場合、エラー
  if (inTokenType != 'access_token' && inTokenType != 'refresh_token') {
		console.log('サポートされていないトークンの種類です： %s', inTokenType);
		res.status(400).json({error: 'unsupported_token_type'});
		return;
  }
  
  // アクセストークンの登録を削除する
	nosql.remove(function(token) {
    if (!token) {
      if (inTokenType == 'access_token') {
        if (token.token_type == inTokenType && token.access_token == inToken && token.client_id == clientId) {
          return true;
        }
      } else if (inTokenType == 'refresh_token') {
        if (token.refresh_token == inToken && token.client_id == clientId) {
          return true;	
        }
      }
    }
	}, function(err, count) {
		console.log("トークンを取り消しました。件数: %s件", count);
		res.status(204).end();
		return;
	});
	
});

// Introspection Endpointの実装
app.post('/introspect', function(req, res) {
  // Authorizationヘッダから保護リソースのリソースIDとリソースシークレットを取得する
	var auth = req.headers['authorization'];
	var resourceCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
	var resourceId = querystring.unescape(resourceCredentials[0]);
	var resourceSecret = querystring.unescape(resourceCredentials[1]);

  // 問い合わせてきた保護リソースが認可サーバに登録されているかをチェックする
	var resource = getProtectedResource(resourceId);
	if (!resource) {
		console.log('未知の保護リソース： %s', resourceId);
		res.status(401).end();
		return;
	}
	
  // リソースシークレットが登録された情報とマッチするかを確認する
	if (resource.resource_secret != resourceSecret) {
		console.log('リソースシークレットが一致しません（期待される値： %s, 実際の値： %s', resource.resource_secret, resourceSecret);
		res.status(401).end();
		return;
	}
	
  // 問い合わせてきたアクセストークンが登録されているかをチェックする
	var inToken = req.body.token;
	console.log('問い合わせ対応のアクセストークン： %s', inToken);

  // DBを検索する
	nosql.one(function(token) {
    var now = Math.floor(Date.now() / 1000);
		if (token.access_token == inToken && now >= token.iat && token.exp >= now) {
			return token;	
		}
	}, function(err, token) {
		if (token) {
      // 登録されたトークンがあれば、アクティブであると回答する
			console.log("一致するトークンがありました： %s", inToken);
			
			var introspectionResponse = {};
			introspectionResponse.active = true;
			introspectionResponse.iss = token.iss;
			introspectionResponse.sub = token.user;
			introspectionResponse.scope = token.scope.join(' ');
			introspectionResponse.client_id = token.client_id;
      introspectionResponse.iat = token.iat;
      introspectionResponse.exp = token.exp;
						
			res.status(200).json(introspectionResponse);
			return;
		} else {
      // 登録されたトークンがなければ、アクティブでないと回答する
			console.log('一致するトークンがありませんでした。');

			var introspectionResponse = {};
			introspectionResponse.active = false;
			res.status(200).json(introspectionResponse);
			return;
		}
	});
	
	
});

// 登録対象のクライアントアプリケーション情報をチェックする
// 登録対象のクライアントアプリケーションは、Authorization Code Grantによる認可を受けるものを前提とする
var checkClientMetadata = function (req, res) {
	var reg = {};

  // クライアントアプリケーションの認証方法が指定されていない場合、Authorizationヘッダによる認証が必要とみなす
	if (!req.body.token_endpoint_auth_method) {
		reg.token_endpoint_auth_method = 'secret_basic';	
	} else {
		reg.token_endpoint_auth_method = req.body.token_endpoint_auth_method;
	}
	
  // クライアントアプリケーションの認証方法が不正な場合、エラー
  // secret_basic＝AuthorizationヘッダでクライアントIDとクライアントシークレットを指定
  // secret_post＝フォームパラメータでクライアントIDとクライアントシークレットを指定
  // none＝クライアントシークレットによる認証を必要としない
	if (!__.contains(['secret_basic', 'secret_post', 'none'], reg.token_endpoint_auth_method)) {
		res.status(400).json({error: 'invalid_client_metadata'});
		return;
	}
	
	if (!req.body.grant_types) {
    // grant_typeが指定されていない場合
		if (!req.body.response_types) {
      // response_typeも指定されていない場合
      
      // Authorization Code Grantとする
			reg.grant_types = ['authorization_code'];
			reg.response_types = ['code'];
		} else {
      // response_typeのみが指定されている場合
			reg.response_types = req.body.response_types;
			if (__.contains(req.body.response_types, 'code')) {
        // response_type＝codeの場合、Authorization Code Grantとする
				reg.grant_types = ['authorization_code'];
			} else {
				reg.grant_types = [];
			}
		}
	} else {
    // grant_typeが指定されている場合
		if (!req.body.response_types) {
      // response_typeが指定されていない場合

			reg.grant_types = req.body.grant_types;
			if (__.contains(req.body.grant_types, 'authorization_code')) {
        // grant_type＝authorization_codeの場合、response_type=codeとする（Authorization Code Grant）
				reg.response_types =['code'];
			} else {
				reg.response_types = [];
			}
		} else {
      // response_typeが指定されている場合

			reg.grant_types = req.body.grant_types;
			reg.response_types = req.body.response_types;
			if (__.contains(req.body.grant_types, 'authorization_code') && !__.contains(req.body.response_types, 'code')) {
        // grant_type＝authorization_codeで、response_type≠codeでない場合、response_typeにcodeを追加する
				reg.response_types.push('code');
			}
			if (!__.contains(req.body.grant_types, 'authorization_code') && __.contains(req.body.response_types, 'code')) {
        // grant_type≠authorization_codeで、response_type＝codeの場合、grant_typeにauthorization_codeを追加する
				reg.grant_types.push('authorization_code');
			}
		}
	}

  // grant_typeにauthorization_code/refresh_token以外のものが含まれる場合、または、repsonse_typeにcode以外のものが含まれる場合、エラー
	if (!__.isEmpty(__.without(reg.grant_types, 'authorization_code', 'refresh_token')) ||
		!__.isEmpty(__.without(reg.response_types, 'code'))) {
		res.status(400).json({error: 'invalid_client_metadata'});
		return;
	}

  // リダイレクトURIがない場合、エラー
	if (!req.body.redirect_uris || !__.isArray(req.body.redirect_uris) || __.isEmpty(req.body.redirect_uris)) {
		res.status(400).json({error: 'invalid_redirect_uri'});
		return;
	} else {
		reg.redirect_uris = req.body.redirect_uris;
	}
	
  // クライアント名
	if (typeof(req.body.client_name) == 'string') {
		reg.client_name = req.body.client_name;
	}
	
  // クライアントのURL
	if (typeof(req.body.client_uri) == 'string') {
		reg.client_uri = req.body.client_uri;
	}
	
  // クライアントのロゴのURL
	if (typeof(req.body.logo_uri) == 'string') {
		reg.logo_uri = req.body.logo_uri;
	}
	
  // クライアントのスコープ
	if (typeof(req.body.scope) == 'string') {
		reg.scope = req.body.scope;
	}
	
	return reg;
};

//  Registration Endpointの実装
app.post('/register', function (req, res){

  // 受信したクライアントアプリケーション情報をチェックする
	var reg = checkClientMetadata(req, res);
	if (!reg) {
		return;
	}

  // クライアントIDをランダムな文字列として生成する
	reg.client_id = randomstring.generate();

  // アクセストークンの発行時のクライアントアプリケーションの認証で、クライアントシークレットを必要とするクライアントアプリケーション場合、クライアントシークレットを生成する
	if (__.contains(['client_secret_basic', 'client_secret_post']), reg.token_endpoint_auth_method) {
		reg.client_secret = randomstring.generate();
	}

  // 登録日時
	reg.client_id_created_at = Math.floor(Date.now() / 1000);
  
  // クライアントアプリケーションの有効期限（0＝無期限）
	reg.client_secret_expires_at = 0;

  // 登録済みクライアントアプリケーションの管理（更新、削除）に必要なアクセストークン
	reg.registration_access_token = randomstring.generate();

  // 登録済みのクライアントアプリケーションの管理（更新、削除）を行うAPIのURI
	reg.registration_client_uri = 'http://localhost:9001/register/' + reg.client_id;

  // 認可サーバにクライアントアプリケーション情報を登録する
	clients.push(reg);
	
	res.status(201).json(reg);
	return;
});

var validateConfigurationEndpointRequest = function (req, res, next) {
	var clientId = req.params.clientId;
	var client = getClient(clientId);
	if (!client) {
		res.status(404).end();
		return;
	}

	var auth = req.headers['authorization'];
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		var regToken = auth.slice('bearer '.length);

		if (regToken == client.registration_access_token) {
			req.client = client;
			next();
			return;
		} else {
			res.status(403).end();
			return;
		}
		
	} else {
		res.status(401).end();
		return;
	}

};

app.get('/register/:clientId', validateConfigurationEndpointRequest, function(req, res) {
	res.status(200).json(client);
});

app.put('/register/:clientId', validateConfigurationEndpointRequest, function(req, res) {

	if (req.body.client_id != client.client_id) {
		res.status(400).json({error: 'invalid_client_metadata'});
		return;
	}
	
	if (req.body.client_secret && req.body.client_secret != client.client_secret) {
		res.status(400).json({error: 'invalid_client_metadata'});
	}

	var reg = checkClientMetadata(req, res);
	if (!reg) {
		return;
	}

	__.each(client, function(value, key, list) {
		client[key] = reg[key];
	});
	__.each(reg, function(value, key, list) {
		client[key] = reg[key];
	});

	res.status(200).json(client);
	
});

app.delete('/register/:clientId', validateConfigurationEndpointRequest, function(req, res) {
	clients = __.reject(clients, __.matches({client_id: client.client_id}));

	nosql.remove(function(token) {
		if (token.client_id == clientId) {
			return true;	
		}
	}, function(err, count) {
		console.log("Removed %s tokens", count);
	});
	
	res.status(204).end();
	return;

	
});

var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);
	nosql.one(function(token) {
		if (token.access_token == inToken) {
			return token;	
		}
	}, function(err, token) {
		if (token) {
			console.log("We found a matching token: %s", inToken);
		} else {
			console.log('No matching token was found.');
		}
		req.access_token = token;
		next();
		return;
	});
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

var userInfoEndpoint = function(req, res) {
	
	if (!__.contains(req.access_token.scope, 'openid')) {
		res.status(403).end();
		return;
	}
	
	var user = userInfo[req.access_token.user];
	if (!user) {
		res.status(404).end();
		return;
	}
	
	var out = {};
	__.each(req.access_token.scope, function (scope) {
		if (scope == 'openid') {
			__.each(['sub'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'profile') {
			__.each(['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'email') {
			__.each(['email', 'email_verified'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'address') {
			__.each(['address'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		} else if (scope == 'phone') {
			__.each(['phone_number', 'phone_number_verified'], function(claim) {
				if (user[claim]) {
					out[claim] = user[claim];
				}
			});
		}
	});
	
	res.status(200).json(out);
	return;
};

app.get('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);
app.post('/userinfo', getAccessToken, requireAccessToken, userInfoEndpoint);

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

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
