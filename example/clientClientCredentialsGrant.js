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
app.set('views', 'files/clientClientCredentailsGrant');

// 認可サーバの情報
var authServer = {
	tokenEndpoint: 'http://localhost:9001/token',             // Token Endopoint
};

// クライアント情報
var client = {
	"client_id": "oauth-client-2",                        // クライアントID
	"client_secret": "oauth-client-secret-1",             // クライアントシークレット
	"redirect_uris": ["http://localhost:9000/callback"],  // リダイレクトURI
	"scope": "bar"                                        // 認可サーバに登録したクライアントが要求するスコープ
};

// 保護リソースが効果するAPIのURL
var protectedResource = 'http://localhost:9002/resource';

// 認可コードの取得に使用するstateパラメータ
var state = null;

var access_token = null;      // アクセストークン
var refresh_token = null;     // リフレッシュトークン
var scope = null;             // 実際にリソースオーナーによって認可サーバから委譲されたスコープ
var id_token = null;          // IDトークン（ペイロード）
var id_token_raw = null;      // IDトークン

// トップページを表示する
app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
});

// 認可サーバからアクセストークンを取得する
app.get('/authorize', function(req, res){

  // アクセストークンなどをいったんクリアする
	access_token = null;
	scope = null;

  var form_data = qs.stringify({
    grant_type: 'client_credentials',
    scope: client.scope
  });
  
  var headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
  };
  
  var tokRes = request('POST', authServer.tokenEndpoint, {
    body: form_data,
    headers: headers
  });
  
  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    var body = JSON.parse(tokRes.getBody());
    
    access_token = body.access_token;
    scope = body.scope;
    
    res.render('index', {access_token: access_token, refresh_token: refresh_token, scope: scope, id_token_raw: id_token_raw});
  } else {
    res.render('error', {error: 'アクセストークンを取得できませんでした。　認可サーバのレスポンス： ' + tokRes.statusCode});
  }
});

// 保護リソースにアクセスする
app.get('/fetch_resource', function(req, res) {

	if (!access_token) {
    res.render('error', {error: 'アクセストークンがありません'});
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
    res.render('error', {error: 'サーバがレスポンスコードを返しました： ' + resource.statusCode});
    return;
	}
});

app.use('/', express.static('files/clientClientCredentailsGrant'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
