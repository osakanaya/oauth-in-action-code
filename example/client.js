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
var crypto = require('crypto');
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

var code_verifier = null;     // Code Verifier（PKCE）

// トップページを表示する
app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
});

// クライアントアプリケーションの登録管理画面を表示する
app.get('/client_mgmt', function (req, res) {
  // クライアントが登録されていない場合は、エラー
	if (!client.client_id) {
    res.render('error', {error: 'クライアントアプリケーションがまだ登録されていません。'});
    return;
	}

  // 認可サーバからクライアントの登録情報を削除する
  var headers = {
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + client.registration_access_token
  };
  
  var regRes = request('GET', client.registration_client_uri, {
    headers: headers
  });
  
  if (regRes.statusCode == 200) {
    var client_info = JSON.parse(regRes.getBody());
    console.log('取得したクライアント登録情報： %s', regRes.getBody());
    
    res.render('client_mgmt', {client: client_info});
    return;
  } else {
    res.render('error', {error: 'クライアント情報を取得することができませんでした。 ' + regRes.statusCode});
    return;
  }
});

// クライアントアプリケーションの登録情報（クライアント名）を更新する
app.post('/update_client', function(req, res) {

  // クライアントが登録されていない場合は、エラー
	if (!client.client_id) {
    res.render('error', {error: 'クライアントアプリケーションがまだ登録されていません。'});
    return;
	}

  // 認可サーバに登録されたクライアント情報を更新する
  var headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Bearer ' + client.registration_access_token
  };
  
  var reg = __.clone(client);
  delete reg['client_id_issued_at'];
  delete reg['client_secret_expires_at'];
  delete reg['registration_client_uri'];
  delete reg['registration_access_token'];
  
  reg.client_name = req.body.client_name;
  
  console.log("クライアントアプリケーションの更新情報を送信します: " + JSON.stringify(reg));
  
  var regRes = request('PUT', client.registration_client_uri, {
    body: JSON.stringify(reg),
    headers: headers
  });
  
  if (regRes.statusCode == 200) {
    client = JSON.parse(regRes.getBody());
    // トップページに戻る
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
    return;
  } else {
    res.render('error', {error: 'クライアントアプリケーションの登録情報を更新できませんでした： ' + regRes.statusCode});
    return;
  }

  // 認可サーバからクライアントの登録情報を削除する
  var headers = {
    'Authorization': 'Bearer ' + client.registration_access_token
  };
  
  var regRes = request('DELETE', client.registration_client_uri, {
    headers: headers
  });
  
  if (regRes.statusCode == 204) {
    // クライアントで保持するクライアント情報、トークン情報（アクセストークン、リフレッシュトークン、IDトークン）をクリアする
    client = {};

    access_token = null;
    refresh_token = null;
    scope = null;
    
    id_token = null;
    id_token_raw = null;

    // トップページに戻る
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
    return;
  } else {
    res.render('error', {error: 'クライアントアプリケーションの登録を解除できませんでした： ' + regRes.statusCode});
  }
});

// クライアントアプリケーションの登録を解除する
app.get('/unregister_client', function(req, res) {

  // クライアントが登録されていない場合は、エラー
	if (!client.client_id) {
    res.render('error', {error: 'クライアントアプリケーションがまだ登録されていません。'});
    return;
	}

  // 認可サーバからクライアントの登録情報を削除する
  var headers = {
    'Authorization': 'Bearer ' + client.registration_access_token
  };
  
  var regRes = request('DELETE', client.registration_client_uri, {
    headers: headers
  });
  
  if (regRes.statusCode == 204) {
    // クライアントで保持するクライアント情報、トークン情報（アクセストークン、リフレッシュトークン、IDトークン）をクリアする
    client = {};

    access_token = null;
    refresh_token = null;
    scope = null;
    
    id_token = null;
    id_token_raw = null;

    // トップページに戻る
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
    return;
  } else {
    res.render('error', {error: 'クライアントアプリケーションの登録を解除できませんでした： ' + regRes.statusCode});
  }
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
	
  // PKCEのためのCode Verifier/Code Challengeを生成する
  code_verifier = randomstring.generate(80);
  var code_challenge = base64url.fromBase64(crypto.createHash('sha256').update(code_verifier).digest('base64'));
  
  console.log('Code Verifier： %sとCode Challenge： %sを生成しました。', code_verifier, code_challenge);

  // Authorization Endpointにリダイレクトする
	var authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state,
    nonce: nonce,
    code_challenge: code_challenge, // PKCE
    code_challenge_method: 'S256'   // PKCE
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
		scope: 'openid profile email address phone read write delete fruit veggies meats'           // スコープ
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
				redirect_uri: client.redirect_uris[0],
        code_verifier: code_verifier
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
        
        // IDトークンの有効性を検証する
        if (validateIdToken(payload)) {
          id_token = payload;
        } else {
          res.render('error', {error: 'IDトークンは有効ではありません'});
        }
			} else {
        console.log('IDトークンの署名を検証できませんでした');
        res.render('error', {error: 'IDトークンは有効ではありません'});
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

// IDトークンの有効性を検証する
var validateIdToken = function(id_token) {
  // そもそもIDトークンがない場合は無効
  if (!id_token) {
    return false;
  }
  
  if (id_token.iss == 'http://localhost:9001/') {
    // IDトークンが期待される認可サーバ（IdP）から発行されたかをチェック
    console.log('IDトークンの発行元　＝　OK');

    if ((Array.isArray(id_token.aud) && _.contains(id_token.aud, client.client_id)) || 
      id_token.aud == client.client_id) {
      // IDトークンの発行先が自分自身であることをチェック
      console.log('IDトークンの発行先　＝　OK');
  
      // IDトークンの有効期限内であることをチェック
      var now = Math.floor(Date.now() / 1000);
  
      if (id_token.iat <= now) {
        console.log('IDトークンの発行時刻≦現在時刻　＝　OK');
        if (id_token.exp >= now) {
          console.log('IDトークンの有効期限≧現在時刻　＝　OK');
          console.log('IDトークンは正しいです！');

          return true;
        } else {
          console.log('IDトークンは有効期限切れです');
          return false;
        }
      } else {
        console.log('IDトークンは有効期限切れです');
        return false;
      }
    } else {
      console.log('IDトークンの発行先が正しくありません： %s', id_token.aud);
      return false;
    }
  } else {
    console.log('IDトークンの発行元が正しくありません： %s', id_token.iss);
    return false;
  }
};

// リフレッシュトークンからアクセストークンを再発行する
// 認可サーバでの認可を受け取るコールバック
app.get("/refresh_token", function(req, res){
  // リフレッシュトークンがない場合はエラー
  if (!refresh_token) {
			res.render('error', {error: 'リフレッシュトークンがありません'});
			return;
  }

  // リフレッシュトークンを発行する
  refreshAccessToken(req, res);
	
});

// リフレッシュトークンからアクセストークンを再発行する
var refreshAccessToken = function(req, res) {
  // Token Endpointへリクエストする
	var form_data = qs.stringify({
				grant_type: 'refresh_token',
				refresh_token: refresh_token,
				redirect_uri: client.redirect_uri
	});

	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
    // クライアントアプリケーションのクライアントIDとクライアントシークレットを設定する
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
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
		res.redirect('/');
		return;
	} else {
    // リフレッシュトークンからアクセストークンが再発行できなかった場合
		console.log('リフレッシュトークンが無いため、ユーザに新しいアクセストークンを取得するように要求します');
    
    access_token = null;
    scope = null;
    refresh_token = null;
    
    // 認可サーバの同意画面へ結果的にリダイレクトする
		res.redirect('/authorize');
		return;
	}
};

// 保護リソースにアクセスする
app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
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
      // リフレッシュトークンがあれば、アクセストークンを再発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
			res.render('error', {error: 'サーバがレスポンスコードを返しました： ' + resource.statusCode});
			return;
		}
	}
});

// Words APIにアクセスするための画面を表示する
app.get('/words', function (req, res) {

	res.render('words', {words: '', timestamp: 0, result: null});
	
});

// リストにある単語数を取得する
app.get('/get_words', function (req, res) {

	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
  }
  
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

// リストに単語を追加する
app.get('/add_word', function (req, res) {
	
	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
  }
  
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

// リストから単語を削除する
app.get('/delete_word', function (req, res) {
	
	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
  }
  
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

// Produce APIにアクセスする
app.get('/produce', function(req, res) {
	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
  }
  
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

// Favorites APIにアクセスする
app.get('/favorites', function(req, res) {
	if (!access_token) {
    // アクセストークンがない場合
		if (refresh_token) {
      // リフレッシュトークンがある場合は、アクセストークンを新規に発行する（再発行後、トップページへ移動）
			refreshAccessToken(req, res);
			return;
		} else {
      // リフレッシュトークンがない場合＝アクセストークンも無いので、保護リソースへのアクセスは拒否する
			res.render('error', {error: 'アクセストークンがありません'});
			return;
		}
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
  }
  
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('GET', favoritesApi,
		{headers: headers}
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		res.render('favorites', {scope: scope, data: body});
		return;
	} else {
		res.render('favorites', {scope: scope, data: {user: '', favorites: {movies: [], foods: [], music: []}}});
		return;
	}
	
});

// アクセストークン・リフレッシュトークンを取り消すページを表示する
app.get('/revoke', function(req, res) {
	res.render('revoke', {access_token: access_token, refresh_token: refresh_token, scope: scope});
});

// アクセストークン・リフレッシュトークンを取り消す
app.post('/revoke', function(req, res) {
  // フォームデータを生成する
  var form_data;
  if (req.body.token_type == 'access_token') {
    form_data = qs.stringify({
      token: access_token,
      token_type_hint: req.body.token_type
    });
  } else if (req.body.token_type == 'refresh_token') {
    form_data = qs.stringify({
      token: refresh_token,
      token_type_hint: req.body.token_type
    });
  } else {
		res.render('error', {error: 'サポートされていないトークンの種類です： ' + req.body.token_type});
		return;
  }
  
  // Revocation Endopointにリクエストを送信する
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
 		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};
  
  if (req.body.token_type == 'access_token') {
    console.log('アクセストークンを取り消しています： %s', access_token);
  } else if (req.body.token_type == 'refresh_token') {
    console.log('リフレッシュトークンを取り消しています： %s', refresh_token);
  }
	var tokRes = request('POST', authServer.revocationEndpoint, 
		{
			body: form_data,
			headers: headers
		}
	);

	// クライアントアプリケーションで持っているトークン情報をクリアする
	access_token = null;
	scope = null;
  if (req.body.token_type == 'refresh_token') {
    refresh_token = null;
  }
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		res.render('revoke', {access_token: access_token, refresh_token: refresh_token, scope: scope});
		return;
	} else {
		res.render('error', {error: tokRes.statusCode});
		return;
	}
});

// ユーザ情報を取得する
app.get('/userinfo', function(req, res) {

  // アクセストークンがあることを確認する
	if (!access_token) {
    // アクセストークンがない場合
    res.render('error', {error: 'アクセストークンがありません'});
    return;
	}
	
  // IDトークンの正当性をチェックする
  if (!validateIdToken(id_token)) {
    res.render('error', {error: 'IDトークンは有効ではありません'});
    return;
  }
  
	
  // 認可サーバ（IdP）へユーザ情報を問い合わせる
	console.log('ユーザ情報を取得します。 アクセストークン： %s', access_token);

	var headers = {
		'Authorization': 'Bearer ' + access_token
	};
	
	var resource = request('GET', authServer.userInfoEndpoint,
		{headers: headers}
	);
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		var body = JSON.parse(resource.getBody());
		console.log('ユーザ情報を取得しました： ', body);
	
		userInfo = body;
	
		res.render('userinfo', {userInfo: userInfo, id_token: id_token});
		return;
	} else {
		res.render('error', {error: 'ユーザ情報を取得することができませんでした'});
		return;
	}
	
});

// ログイン画面を表示する（Resource Owner Password Credentails Grant）
app.get('/username_password', function(req, res) {
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
  
  id_token = null;
  id_token_raw = null;

	res.render('username_password');
	return;
});

// アクセストークンを取得する（Resource Owner Password Credentails Grant）
app.post('/username_password', function(req, res) {
	
	var username = req.body.username;
	var password = req.body.password;
	
  // IDトークンの発行に際し、nonceパラメータを生成する
  nonce = randomstring.generate();

	var form_data = qs.stringify({
				grant_type: 'password',
				username: username,
				password: password,
        scope: client.scope,
        nonce: nonce
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
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    // 正常終了した場合
		var body = JSON.parse(tokRes.getBody());

    // 発行されたアクセストークンを取得する
		access_token = body.access_token;
		console.log('アクセストークンが発行されました： %s', access_token);

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
        
        // IDトークンの有効性を検証する
        if (validateIdToken(payload)) {
          id_token = payload;
        } else {
          res.render('error', {error: 'IDトークンは有効ではありません'});
        }
			} else {
        console.log('IDトークンの署名を検証できませんでした');
        res.render('error', {error: 'IDトークンは有効ではありません'});
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
 
