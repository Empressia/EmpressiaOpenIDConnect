package jp.empressia.enterprise.security.oidc;

import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.security.enterprise.identitystore.IdentityStoreHandler;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;

/**
 * Microsoft identity platform OpenID Connect用のMechanismです。
 * 
 * Authorization Code Flowもサポートしてそうに見えるけど、
 * Implicit Flowが紹介されているからそっちを初期設定にしています。
 * アクセストークンも欲しい場合は、Hybrid Flowになるように設定してください。
 * 
 * 今のところ、シングル サインアウトには対応していません。必要に応じて個別に実装してください。
 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-protocols-oidc#single-sign-out
 * 
 * プロトコル：
 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-protocols-oidc
 * トークン：
 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/access-tokens
 * 
 * @author すふぃあ
 */
@ApplicationScoped
@Alternative
public class MicrosoftAuthenticationMechanism extends OpenIDConnectAuthenticationMechanism {

	/** アプリの署名キー情報をポイントするURLです。 */
	private URI jwks_uri;
	/** アプリの署名キー情報をポイントするURLです。 */
	protected URI jwks_uri() { return this.jwks_uri; }

	/** 公開鍵の取得を支援するインスタンス。 */
	private PublicKeyHelper PublicKeyHelper;

	/** コンストラクタ。 */
	@Inject
	public MicrosoftAuthenticationMechanism(Settings settings, IdentityStoreHandler IdentityStoreHandler, ExecutorService executorService, PublicKeyHelper PublicKeyHelper) {
		super(settings, IdentityStoreHandler, executorService);
		this.PublicKeyHelper = PublicKeyHelper;
		this.jwks_uri = settings.jwks_uri();
	}

	/** 必須じゃないけど、呼ぶと、ある程度の設定を確認します。 */
	@PostConstruct
	@Override
	protected void validateSettings() {
		super.validateSettings();
	}

	/** IDToken解析用です。 */
	private ObjectMapper ObjectMapper = new ObjectMapper();
	/**
	 * IDトークンの妥当性を確認します（署名の確認も行います）。
	 * headerのkidを見て、jwks_uriから鍵を使ってきて署名を確認します。
	 * RSA固定で確認します。
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/v2-protocols-oidc#validate-the-id-token
	 */
	@Override
	public Jws<Claims> parseIDToken(String id_token, OpenIDConnectCredential credential) {
		Key key;
		{
			String header = id_token.split("\\.")[0];
			byte[] headerBytes = Base64.getUrlDecoder().decode(header);
			JsonNode node;
			try {
				node = this.ObjectMapper.readTree(headerBytes);
			} catch(IOException ex) {
				throw new IllegalStateException("トークンレスポンスの検証用キーの取得に失敗しました。", ex);
			}
			String kid = node.has("kid") ? node.get("kid").asText() : null;
			try {
				key = this.PublicKeyHelper.getPubliKey(this.jwks_uri(), kid);
			} catch(IOException | NoSuchAlgorithmException | InvalidKeySpecException | InterruptedException ex) {
				throw new IllegalStateException("id_tokenの署名の確認に必要な鍵の取得に失敗しました。", ex);
			}
		}
		Jws<Claims> jws;
		{
			JwtParser parser = Jwts.parserBuilder()
				.deserializeJsonWith(new JacksonDeserializer<Map<String, ?>>(this.ObjectMapper))
				.setSigningKey(key)
				.build();
			jws = parser.parseClaimsJws(id_token);
		}
		return jws;
	}

	/**
	 * id_tokenの妥当性を確認します。
	 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/id-tokens#validating-an-id_token
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public void validateIDToken(Jws<Claims> id_token, String requestedNonce, OpenIDConnectCredential credential) {
		super.validateIDToken(id_token, requestedNonce, credential);
		Claims payload = id_token.getBody();
		// Microsoft専用ここから。
		{
			int ndf = payload.get("nbf", Integer.class);
			if((ndf <= OpenIDConnectUtilities.currentUNIXTime()) == false) {
				throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
			}
		}
		// Micorosoft専用ここまで。
	}

	/**
	 * access_tokenを検証します。
	 * 問題がある場合は例外が投げられます。
	 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/access-tokens#validating-tokens
	 * @param access_token
	 * @param requestedScope 参考に渡されます。
	 * @param requestedNonce 参考に渡されます。リフレッシュされた場合とかは渡されません。
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public void validateAccessToken(String access_token, String token_type, Jws<Claims> id_token, String requestedScope, String requestedNonce, OpenIDConnectCredential credential) {
		// 個人アカウントを対象にしている場合は、不透明な文字列らしい。
		if(this.getIssuer().equals(Settings.DEFAULT_Issuer)) { return; }
		Key key;
		{
			String header = access_token.split("\\.")[0];
			byte[] headerBytes = Base64.getUrlDecoder().decode(header);
			JsonNode node;
			try {
				node = this.ObjectMapper.readTree(headerBytes);
			} catch(IOException ex) {
				throw new IllegalStateException("トークンレスポンスの検証用キーの取得に失敗しました。", ex);
			}
			String kid = node.has("kid") ? node.get("kid").asText() : null;
			try {
				key = this.PublicKeyHelper.getPubliKey(this.jwks_uri(), kid);
			} catch(IOException | NoSuchAlgorithmException | InvalidKeySpecException | InterruptedException ex) {
				throw new IllegalStateException("access_tokenの署名の確認に必要な鍵の取得に失敗しました。", ex);
			}
		}
		JwtParser parser = Jwts.parserBuilder()
			.deserializeJsonWith(new JacksonDeserializer<Map<String, ?>>(this.ObjectMapper))
			.setSigningKey(key)
			.build();
		Jws<Claims> jws = parser.parseClaimsJws(access_token);
		JwsHeader<?> header = jws.getHeader();
		{
			String nonce = (String)header.get("nonce");
			if(nonce.equals(requestedNonce) == false) {
				throw new IllegalStateException("アクセストークンが期待した形式ではありませんでした。");
			}
		}
		Claims claims = jws.getBody();
		{
			String scp = claims.get("scp", String.class);
			if(scp.equals(requestedScope) == false) {
				throw new IllegalStateException("アクセストークンが期待した形式ではありませんでした。");
			}
		}
	}

	/**
	 * id_token の要求。
	 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/id-tokens#claims-in-an-id_token
	 * @author すふぃあ
	 */
	@SuppressWarnings("unused")
	private static class IDTokenPayload {
		/** トークンの受信者を示します。 */
		public String aud;
		/** トークンを作成して返したセキュリティ トークン サービス (STS)、およびユーザーが認証された Azure AD テナントを示します。 */
		public String iss;
		/** "Issued At" は、このトークンの認証がいつ行われたのかを示します。 */
		public long iat;
		/** トークンのサブジェクトを認証した ID プロバイダーを記録します。 */
		public String idp;
		/** "nbf" (指定時刻よりも後) 要求では、指定した時刻よりも後に JWT の処理を受け入れることができるようになります。 */
		public long ndf;
		/** "exp" (有効期限) 要求は、JWT の処理を受け入れることができなくなる時刻を指定します。 */
		public long exp;
		/** コード ハッシュは、ID トークンが OAuth 2.0 認証コードと共に発行される場合にのみ、ID トークンに含まれます。 */
		public String c_hash;
		/** アクセス トークン ハッシュは、ID トークンが OAuth 2.0 アクセス トークンと共に発行される場合にのみ、ID トークンに含まれます。 */
		public String at_hash;
		/** Azure AD がトークン再利用のためにデータの記録に使用する内部の要求。無視してください。 */
		public String aio;
		/** ユーザーを表すプライマリ ユーザー名です。 */
		public String preferred_username;
		/** email 要求は、電子メール アドレスを持つゲスト アカウントに対して既定で使用されます。 アプリでは、オプション要求 email を使用して、管理対象ユーザー (リソースと同じテナントのユーザー) の電子メール要求を要求できます。 v2.0 エンドポイントでは、アプリで email OpenID Connect スコープを要求することもできます (要求を取得するためにオプション要求とスコープの両方を要求する必要はありません)。 */
		public String email;
		/** name要求は、トークンのサブジェクトを識別する、人が認識できる値を示します。 この値は、一意であるとは限らず、変更可能であり、表示目的でのみ使用するように設計されています。 この要求を受け取るには、 profile スコープが必要です。 */
		public String name;
		/** nonce は、IDP に対する元の要求または承認要求に含まれるパラメーターと一致します。 */
		public String nonce;
		/** Microsoft ID システム (ここではユーザー アカウント) のオブジェクトに対する変更不可の識別子です。 */
		public String oid;
		/** ログインしているユーザーに割り当てられた一連のロール。 */
		public String roles;
		/** Azure がトークンの再検証に使用する内部の要求。無視してください。 */
		public String rh;
		/** トークンが情報をアサートするプリンシパルです (アプリのユーザーとか)。 */
		public String sub;
		/** ユーザーが属している Azure AD テナントを表す GUID です。この要求を受け取るには profile スコープが必要です。 */
		public String tid;
		// /** トークンのサブジェクトを識別する、人が判読できる値を提供します。v1.0 id_tokens のみで発行されます。 */
		// public String unique_name;
		/** Azure がトークンの再検証に使用する内部の要求。 無視してください。 */
		public String uti;
		/** id_token のバージョンを示します。 */
		public String ver;
	}

	/**
	 * アクセス トークン内のクレーム。
	 * https://docs.microsoft.com/ja-jp/azure/active-directory/develop/access-tokens#claims-in-access-tokens
	 * @author すふぃあ
	 */
	@SuppressWarnings("unused")
	private static class AccessTokenPayload {
		/** トークンの受信者を示します。 */
		public String aud;
		/** トークンを作成して返したセキュリティ トークン サービス (STS)、およびユーザーが認証された Azure AD テナントを示します。 */
		public String iss;
		/** トークンのサブジェクトを認証した ID プロバイダーを記録します。 */
		public String idp;
		/** "Issued At" は、このトークンの認証がいつ行われたのかを示します。 */
		public long iat;
		/** "nbf" (not before) 要求は JWT が有効になる日時を示します。これ以前にその JWT を受け入れて処理することはできません。 */
		public long ndf;
		/** "exp" (expiration time) 要求は、JWT の有効期限を示します。これ以降は、その JWT を受け入れて処理することはできません。 */
		public long exp;
		/** Azure AD がトークン再利用のためにデータの記録に使用する内部の要求。 リソースでこの要求を使用しないでください。 */
		public String aio;
		/** V2.0 トークンにのみ存在します。appid に代わるものです。 */
		public String azp;
		/** V2.0 トークンにのみ存在します。appidacr に代わるものです。 */
		public String azpacr;
		/** ユーザーを表すプライマリ ユーザー名です。 電子メール アドレス、電話番号、または指定された書式のない一般的なユーザー名を指定できます。 */
		public String preferred_username;
		/** トークンのサブジェクトを識別する、人間が判読できる値を提供します。 */
		public String name;
		/** クライアント アプリケーションが同意を要求し、同意を得た、アプリケーションによって公開されているスコープのセット。 */
		public String scp;
		/** 要求元のアプリケーションに呼び出しのアクセス許可が付与されている、アプリケーションまたはユーザーによって公開されているアクセス許可のセット。 */
		public String roles;
		/** 管理者ロール ページに存在するロールのセクションから、このユーザーに割り当てられたテナント全体のロールを示します。 */
		public String wids;
		/** サブジェクトのグループ メンバーシップを表すオブジェクト ID です。 */
		public String groups;
		/** 存在する場合、常に true であり、ユーザーが 1 つ以上のグループに属していることを示します。 */
		public boolean hasgroups;
		// groups:src1？
		/** トークンが情報をアサートするプリンシパルです (アプリのユーザーなど)。 この値は変更不可で、再割り当ても再利用もできません。 */
		public String sub;
		/** Microsoft ID プラットフォーム (ここではユーザー アカウント) におけるオブジェクトの変更不可の識別子です。 */
		public String oid;
		/** ユーザーが属している Azure AD テナントを表します。職場または学校アカウントの場合、GUID はユーザーが属している組織の不変のテナント ID です。 個人アカウントでは、この値は 9188040d-6c67-4c5b-b112-36a304b66dad です。 この要求を受け取るには、 profile スコープが必要です。 */
		public String tid;
		/** Azure がトークンの再検証に使用する内部要求。 リソースでこの要求を使用しないでください。 */
		public String uti;
		/** Azure がトークンの再検証に使用する内部要求。 リソースでこの要求を使用しないでください。 */
		public String rh;
		/** アクセス トークンのバージョンを示します。 */
		public String ver;
	}

	/**
	 * 設定用のクラス。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	@Typed(Settings.class)
	public static class Settings extends OpenIDConnectAuthenticationMechanism.Settings {

		/** アプリの署名キー情報をポイントするURLです。 */
		private URI jwks_uri;
		/** アプリの署名キー情報をポイントするURLです。 */
		public URI jwks_uri() { return this.jwks_uri; }
		/** アプリの署名キー情報をポイントするURLです。 */
		public void jwks_uri(URI jwks_uri) { this.jwks_uri = jwks_uri; }

		/** IssuerのMicrosoft用の初期値です。 */
		public static final String DEFAULT_Issuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";
		/** AuthorizationEndpointのMicrosoft用の初期値です。 */
		public static final String DEFAULT_AuthorizationEndpoint = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
		/** TokenEndpointのMicrosoft用の初期値です。 */
		public static final String DEFAULT_TokenEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
		/** response_typeのMicrosoft用の初期値です。 */
		public static final String DEFAULT_response_type = "id_token";
		/** response_modeのMicrosoft用の初期値です。 */
		public static final String DEFAULT_response_mode = "form_post";
		/** アプリの署名キー情報をポイントするURLのMicrosoft用の初期値です。 */
		public static final String DEFAULT_jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys";

		/** コンストラクタ。 */
		@Inject
		public Settings(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.Issuer", defaultValue="") Optional<String> Issuer,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.AuthorizationEndpoint", defaultValue="") Optional<String> AuthorizationEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.TokenEndpoint", defaultValue="") Optional<String> TokenEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.RevocationEndpoint", defaultValue="") Optional<String> RevocationEndpoint,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.response_type", defaultValue="") Optional<String> response_type,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.response_mode", defaultValue="") Optional<String> response_mode,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.scope", defaultValue="") Optional<String> scope,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.client_id") Optional<String> client_id,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.ClientAuthenticaitonMethod", defaultValue="") Optional<String> ClientAuthenticaitonMethod,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.client_secret", defaultValue="") Optional<String> client_secret,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.UseSecureCookie", defaultValue="") Optional<String> UseSecureCookie,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.TokenCookieMaxAge", defaultValue="") Optional<String> TokenCookieMaxAge,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.scopeCookieName", defaultValue="") Optional<String> scopeCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.redirect_uriCookieName", defaultValue="") Optional<String> redirect_uriCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.stateCookieName", defaultValue="") Optional<String> stateCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.nonceCookieName", defaultValue="") Optional<String> nonceCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.request_pathCookieName", defaultValue="") Optional<String> request_pathCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.form_postParameterCookiePrefixName", defaultValue="") Optional<String> form_postParameterCookiePrefixName,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.AllowedIssuanceDuration", defaultValue="") Optional<String> AllowedIssuanceDuration,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.UseProxy", defaultValue="") Optional<String> UseProxy,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.ProxyHost", defaultValue="") Optional<String> ProxyHost,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.ProxyPort", defaultValue="") Optional<String> ProxyPort,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.ConnectTimeout", defaultValue="") Optional<String> ConnectTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.ReadTimeout", defaultValue="") Optional<String> ReadTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.UseThreadPool", defaultValue="") Optional<String> UseThreadPool,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.AuthenticatedURLPath") Optional<String> AuthenticatedURLPath,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPaths", defaultValue="") Optional<String> IgnoreAuthenticationURLPaths,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPathRegex", defaultValue="") Optional<String> IgnoreAuthenticationURLPathRegex,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.CreateAuthorizationRequestOnlyWhenProtected", defaultValue="") Optional<String> CreateAuthorizationRequestOnlyWhenProtected,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Microsoft.jwks_uri", defaultValue="") Optional<String> jwks_uri
		) {
			this(
				((Issuer != null) && (Issuer.isEmpty() == false)) ? Issuer.get() : null,
				((AuthorizationEndpoint != null) && (AuthorizationEndpoint.isEmpty() == false)) ? AuthorizationEndpoint.get() : null,
				((TokenEndpoint != null) && (TokenEndpoint.isEmpty() == false)) ? TokenEndpoint.get() : null,
				((RevocationEndpoint != null) && (RevocationEndpoint.isEmpty() == false)) ? RevocationEndpoint.get() : null,
				((response_type != null) && (response_type.isEmpty() == false)) ? response_type.get() : null,
				((response_mode != null) && (response_mode.isEmpty() == false)) ? response_mode.get() : null,
				((scope != null) && (scope.isEmpty() == false)) ? scope.get() : null,
				client_id.get(),
				((ClientAuthenticaitonMethod != null) && (ClientAuthenticaitonMethod.isEmpty() == false)) ? ClientAuthenticaitonMethod.get() : null,
				((client_secret != null) && (client_secret.isEmpty() == false)) ? client_secret.get() : null,
				((UseSecureCookie != null) && (UseSecureCookie.isEmpty() == false)) ? UseSecureCookie.get() : null,
				((TokenCookieMaxAge != null) && (TokenCookieMaxAge.isEmpty() == false)) ? TokenCookieMaxAge.get() : null,
				((scopeCookieName != null) && (scopeCookieName.isEmpty() == false)) ? scopeCookieName.get() : null,
				((redirect_uriCookieName != null) && (redirect_uriCookieName.isEmpty() == false)) ? redirect_uriCookieName.get() : null,
				((stateCookieName != null) && (stateCookieName.isEmpty() == false)) ? stateCookieName.get() : null,
				((nonceCookieName != null) && (nonceCookieName.isEmpty() == false)) ? nonceCookieName.get() : null,
				((request_pathCookieName != null) && (request_pathCookieName.isEmpty() == false)) ? request_pathCookieName.get() : null,
				((form_postParameterCookiePrefixName != null) && (form_postParameterCookiePrefixName.isEmpty() == false)) ? form_postParameterCookiePrefixName.get() : null,
				((AllowedIssuanceDuration != null) && (AllowedIssuanceDuration.isEmpty() == false)) ? AllowedIssuanceDuration.get() : null,
				((UseProxy != null) && (UseProxy.isEmpty() == false)) ? UseProxy.get() : null,
				((ProxyHost != null) && (ProxyHost.isEmpty() == false)) ? ProxyHost.get() : null,
				((ProxyPort != null) && (ProxyPort.isEmpty() == false)) ? ProxyPort.get() : null,
				((ConnectTimeout != null) && (ConnectTimeout.isEmpty() == false)) ? ConnectTimeout.get() : null,
				((ReadTimeout != null) && (ReadTimeout.isEmpty() == false)) ? ReadTimeout.get() : null,
				((UseThreadPool != null) && (UseThreadPool.isEmpty() == false)) ? UseThreadPool.get() : null,
				AuthenticatedURLPath.get(),
				((IgnoreAuthenticationURLPaths != null) && (IgnoreAuthenticationURLPaths.isEmpty() == false)) ? IgnoreAuthenticationURLPaths.get() : null,
				((IgnoreAuthenticationURLPathRegex != null) && (IgnoreAuthenticationURLPathRegex.isEmpty() == false)) ? IgnoreAuthenticationURLPathRegex.get() : null,
				((CreateAuthorizationRequestOnlyWhenProtected != null) && (CreateAuthorizationRequestOnlyWhenProtected.isEmpty() == false)) ? CreateAuthorizationRequestOnlyWhenProtected.get() : null,
				((jwks_uri != null) && (jwks_uri.isEmpty() == false)) ? jwks_uri.get() : null
			);
		}

		/** コンストラクタ。 */
		public Settings(
			String Issuer,
			String AuthorizationEndpoint,
			String TokenEndpoint,
			String RevocationEndpoint,

			String response_type,
			String response_mode,

			String scope,

			String client_id,
			String ClientAuthenticaitonMethod,
			String client_secret,

			String UseSecureCookie,
			String TokenCookieMaxAge,
			String scopeCookieName,
			String redirect_uriCookieName,
			String stateCookieName,
			String nonceCookieName,
			String request_pathCookieName,
			String form_postParameterCookiePrefixName,

			String AllowedIssuanceDuration,

			String UseProxy,
			String ProxyHost,
			String ProxyPort,
			String ConnectTimeout,
			String ReadTimeout,
			String UseThreadPool,

			String AuthenticatedURLPath,
			String IgnoreAuthenticationURLPaths,
			String IgnoreAuthenticationURLPathRegex,
			String CreateAuthorizationRequestOnlyWhenProtected,

			String jwks_uri
		) {
			super(
				((Issuer != null) && (Issuer.isEmpty() == false)) ? Issuer : DEFAULT_Issuer,
				((AuthorizationEndpoint != null) && (AuthorizationEndpoint.isEmpty() == false)) ? AuthorizationEndpoint : DEFAULT_AuthorizationEndpoint,
				((TokenEndpoint != null) && (TokenEndpoint.isEmpty() == false)) ? TokenEndpoint : DEFAULT_TokenEndpoint,
				((RevocationEndpoint != null) && (RevocationEndpoint.isEmpty() == false)) ? RevocationEndpoint : null,
				((response_type != null) && (response_type.isEmpty() == false)) ? response_type : DEFAULT_response_type,
				((response_mode != null) && (response_mode.isEmpty() == false)) ? response_mode : DEFAULT_response_mode,
				scope,
				client_id, ClientAuthenticaitonMethod, client_secret,
				UseSecureCookie, TokenCookieMaxAge, scopeCookieName, redirect_uriCookieName, stateCookieName, nonceCookieName, request_pathCookieName, form_postParameterCookiePrefixName,
				AllowedIssuanceDuration,
				UseProxy, ProxyHost, ProxyPort, ConnectTimeout, ReadTimeout, UseThreadPool,
				AuthenticatedURLPath, IgnoreAuthenticationURLPaths, IgnoreAuthenticationURLPathRegex, CreateAuthorizationRequestOnlyWhenProtected
			);
			this.jwks_uri = ((jwks_uri != null) && (jwks_uri.isEmpty() == false)) ? URI.create(jwks_uri) : URI.create(DEFAULT_jwks_uri);
		}

	}

}
