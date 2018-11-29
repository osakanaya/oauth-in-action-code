var express = require("express");
var bodyParser = require('body-parser');
var request = require("sync-request");
var proxy = require('request').defaults({
  'proxy': 'http://cache1.primagest.co.jp:8080'
});
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");
var jose = require('jsrsasign');
var jwksrsa = require('jwks-rsa');
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
  authorizationEndpoint: 'https://login.microsoftonline.com/<replace me>/oauth2/v2.0/authorize', // Authorization Endpoint
  tokenEndpoint: 'https://login.microsoftonline.com/<replace me>/oauth2/v2.0/token',             // Token Endopoint
  userInfoEndpoint: 'https://login.microsoftonline.com/<replace me>/openid/userinfo',            // Userinfo Endpoint
  jwks_uri: 'https://login.microsoftonline.com/common/discovery/keys'
};

// 認可サーバの公開鍵を取得するためのクライアント
var jwksClient = jwksrsa({
  jwksUri: authServer.jwks_uri
});

// クライアント情報
var client = {
  // クライアントID
	"client_id": "<replace me>",
  // クライアントシークレット
	"client_secret": "<replace me>",
  // リダイレクトURI
	"redirect_uris": ["http://localhost:9000/callback"],
  // 認可サーバに登録したクライアントが要求するスコープ
  // リフレッシュトークンを得るにはoffline_accessを指定する必要がある
	"scope": "offline_access openid profile email address phone api://<replace me>/read api://<replace me>/write api://<replace me>/delete api://<replace me>/fruit api://<replace me>/veggies api://<replace me>/meats",
  // テナント
  "tenant": "<replace me>",
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

// 認可サーバにリダイレクトする
app.get('/authorize', function(req, res){

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
    tenant: client.tenant,
    client_id: client.client_id,
    response_type: 'code',
    redirect_uri: client.redirect_uris[0],
    response_mode: 'query',
    state: state,
    scope: client.scope,
    nonce: nonce,
    code_challenge: code_challenge, // PKCE
    code_challenge_method: 'S256'   // PKCE
	});
	
	console.log("リダイレクト先：", authorizeUrl);
	res.redirect(authorizeUrl);
});

// 認可サーバでの認可を受け取るコールバック
app.get("/callback", function(req, res){

	if (req.query.error) {
    // 認可の同意画面で拒否された場合や、登録されていないスコープを要求した場合
		res.render('error', {error: req.query.error});
		return;
	}
	
  console.log('認可サーバから渡されたパラメータ：', JSON.stringify(req.query, null, 2));
  
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
	var form_data = {
    tenant: client.tenant,
    client_id: client.client_id,
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: client.redirect_uris[0],
    client_secret: client.client_secret,
    code_verifier: code_verifier
  };
      
	console.log('認可コード：%s に対するアクセストークンをリクエストしています...', JSON.stringify(form_data, null, 2));
	
  proxy.post({ url: authServer.tokenEndpoint, form: form_data }, function(err, httpResponse, body) {
    if (!err && httpResponse.statusCode >= 200 && httpResponse.statusCode < 300) {
      // 正常終了した場合
      body = JSON.parse(body);
      
      console.log('レスポンス：', JSON.stringify(body, null, 2));

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

        // IDトークンのヘッダとペイロードを抽出し、Base64URLデコードする
        var tokenParts = body.id_token.split('.');
        var header = JSON.parse(base64url.decode(tokenParts[0]));
        var payload = JSON.parse(base64url.decode(tokenParts[1]));

        console.log('IDトークンのヘッダ:', JSON.stringify(header, null, 2));
        console.log('IDトークンのペイロード:', JSON.stringify(payload, null, 2));
        
        id_token_raw = body.id_token;
        
        jwksClient.getSigningKey(header.kid, function(err, key) {
          /*
            IDトークンの正当性を検証する
          */

          // 認可サーバの公開鍵で、IDトークンの署名を検証する
          var signatureValid = jose.jws.JWS.verify(body.id_token, key.publicKey, ['RS256']);
          if (signatureValid) {
            // 署名が正しい場合
            console.log('署名が検証されました。');

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
              return;
            }
          } else {
            console.log('IDトークンの署名を検証できませんでした');
            res.render('error', {error: 'IDトークンは有効ではありません'});
            return;
          }
        
          // スコープを抽出する
          scope = body.scope;
          console.log('実際に認可されたスコープ： %s', scope);

          // トップページを表示する
          res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
        });
      } else {
      // スコープを抽出する
      scope = body.scope;
      console.log('実際に認可されたスコープ： %s', scope);

      // トップページを表示する
      res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
      }
    } else {
      res.render('error', {error: 'アクセストークンを取得できませんでした。認可サーバのレスポンス：: ' + tokRes.statusCode})
    }
  });
});

// IDトークンの有効性を検証する
var validateIdToken = function(id_token) {
  // そもそもIDトークンがない場合は無効
  if (!id_token) {
    return false;
  }
  
  if (id_token.iss == 'https://login.microsoftonline.com/<replace me>/v2.0') {
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

	var form_data = {
    tenant: client.tenant,
    client_id: client.client_id,
    grant_type: 'refresh_token',
    refresh_token: refresh_token,
    client_secret: client.client_secret,
  };
  
  console.log('リフレッシュトークンを使ってアクセストークンを再発行します： %s', refresh_token);

  proxy.post({ url: authServer.tokenEndpoint, form: form_data }, function(err, httpResponse, body) {
    if (!err && httpResponse.statusCode >= 200 && httpResponse.statusCode < 300) {
      // アクセストークンが再発行された場合
      var body = JSON.parse(body);
      console.log('トークンエンドポイントからのレスポンス：', JSON.stringify(body, null, 2));

      access_token = body.access_token;
      console.log('アクセストークンが再発行されました： %s', access_token);

      scope = body.scope;
      console.log('実際に認可されたスコープ： %s', scope);
    
      // リフレッシュトークンも受信した場合
      if (body.refresh_token) {
        refresh_token = body.refresh_token;
        console.log('リフレッシュトークンが再発行されました %s', refresh_token);
      }
      
      // IDトークンも受信した場合
      if (body.id_token) {
        // IDトークンが発行された場合
        console.log('IDトークンが発行されました： %s', body.id_token);

        // IDトークンのヘッダとペイロードを抽出し、Base64URLデコードする
        var tokenParts = body.id_token.split('.');
        var header = JSON.parse(base64url.decode(tokenParts[0]));
        var payload = JSON.parse(base64url.decode(tokenParts[1]));

        console.log('IDトークンのヘッダ:', JSON.stringify(header, null, 2));
        console.log('IDトークンのペイロード:', JSON.stringify(payload, null, 2));
        
        id_token_raw = body.id_token;
        
        jwksClient.getSigningKey(header.kid, function(err, key) {
          /*
            IDトークンの正当性を検証する
          */

          // 認可サーバの公開鍵で、IDトークンの署名を検証する
          var signatureValid = jose.jws.JWS.verify(body.id_token, key.publicKey, ['RS256']);
          if (signatureValid) {
            // 署名が正しい場合
            console.log('署名が検証されました。');

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
              return;
            }
          } else {
            console.log('IDトークンの署名を検証できませんでした');
            res.render('error', {error: 'IDトークンは有効ではありません'});
            return;
          }
        
          // 再度、リダイレクトして保護リソースへのアクセスを試みる
          res.redirect('/');
          return;
        });
        
      } else {
        // 再度、リダイレクトして保護リソースへのアクセスを試みる
        res.redirect('/');
        return;
      }
    } else {
    // リフレッシュトークンからアクセストークンが再発行できなかった場合
      console.log('リフレッシュトークンが無いため、ユーザに新しいアクセストークンを取得するように要求します');
      
      access_token = null;
      scope = null;
      refresh_token = null;
      id_token = null;
      id_token_raw = null;
      
      // 認可サーバの同意画面へ結果的にリダイレクトする
      res.redirect('/authorize');
      return;
    }
  });
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
 
