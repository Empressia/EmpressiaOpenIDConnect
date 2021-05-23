package jp.empressia.enterprise.security.oidc;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.authentication.mechanism.http.RememberMe;
import javax.security.enterprise.credential.RememberMeCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.security.enterprise.identitystore.CredentialValidationResult.Status;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;

/**
 * OpenID Connect用の基本実装です。
 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html
 * 
 * 制限：
 * stateとnonceを必ず使用します。
 * Issuerからの認証結果は、決まったURLにリクエストされる必要があります。
 * 認証後にアクセスしたいアドレスへは、認証後にリダイレクトします。
 * 各種パラメーターの維持にクッキーを使用します。
 * form_postされた場合は、Cookieにフォーム内容を設定して自身にredirectすることで値を取得しようとします。
 * Client Authentication Methodは、client_secret_postにだけ対応しています。
 * 
 * リダイレクトは、実際には、RememberMeWithRedirectInterceptorを参照してください。
 * 
 * @author すふぃあ
 */
@RememberMe(cookieSecureOnlyExpression="#{self.useSecureCookie()}", cookieMaxAgeSecondsExpression="#{self.getTokenCookieMaxAge()}")
public abstract class OpenIDConnectAuthenticationMechanism implements IOpenIDConnectAuthenticationMechanism {

	/** Issuer。 */
	private final String Issuer;
	/** Issuer。 */
	@Override
	public String getIssuer() { return this.Issuer; }
	/** AuthorizationEndpoint。 */
	private final String AuthorizationEndpoint;
	/** AuthorizationEndpoint。 */
	protected String getAuthorizationEndpoint() { return this.AuthorizationEndpoint; }
	/** TokenEndpoint。ない場合はnullで。初期値はnullです。 */
	private final URI TokenEndpoint;
	/** TokenEndpoint。ない場合はnullで。初期値はnullです。 */
	protected URI getTokenEndpoint() { return this.TokenEndpoint; }
	/** RevocationEndpoint。ない場合はnullで。初期値はnullです。 */
	private final URI RevocationEndpoint;
	/** RevocationEndpoint。ない場合はnullで。初期値はnullです。 */
	protected URI getRevocationEndpoint() { return this.RevocationEndpoint; }

	/** response_typeです。初期値はcodeです。 */
	private final String response_type;
	/** response_typeです。初期値はcodeです。 */
	public String response_type() { return this.response_type; }
	/** response_modeです。初期値はqueryです。from_postもサポートしています。その場合は、form_postCookiePrefixNameの設定を確認してください。 */
	private final String response_mode;
	/** response_modeです。初期値はqueryです。from_postもサポートしています。その場合は、form_postCookiePrefixNameの設定を確認してください。 */
	public String response_mode() { return this.response_mode; }

	/** scope。初期値はopenidです。 */
	private final String scope;
	/** scope。初期値はopenidです。 */
	public String scope() { return this.scope; }

	/** client_id。 */
	private final String client_id;
	/** client_id。 */
	public String client_id() { return this.client_id; }
	/** Client Authentication Method。client_secret_postにだけ対応しています。 */
	private final String ClientAuthenticaitonMethod;
	/** Client Authentication Method。client_secret_postにだけ対応しています。 */
	public String getClientAuthenticaitonMethod() { return this.ClientAuthenticaitonMethod; }
	/** client_secret。 */
	private final String client_secret;
	/** client_secret。 */
	public String client_secret() { return this.client_secret; }

	/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
	private final boolean UseSecureCookie;
	/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
	@Override
	public boolean useSecureCookie() { return this.UseSecureCookie; }
	/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
	private int TokenCookieMaxAge;
	/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
	public int getTokenCookieMaxAge() { return this.TokenCookieMaxAge; }
	/** scopeを保存するクッキーの名前です。初期値はscopeです。 */
	private final String scopeCookieName;
	/** scopeを保存するクッキーの名前です。初期値はscopeです。 */
	public String scopeCookieName() { return this.scopeCookieName; }
	/** redirect_uriを保存するクッキーの名前です。初期値はredirect_uriです。 */
	private final String redirect_uriCookieName;
	/** redirect_uriを保存するクッキーの名前です。初期値はredirect_uriです。 */
	public String redirect_uriCookieName() { return this.redirect_uriCookieName; }
	/** stateを保存するクッキーの名前です。初期値はstateです。 */
	private final String stateCookieName;
	/** stateを保存するクッキーの名前です。初期値はstateです。 */
	public String stateCookieName() { return this.stateCookieName; }
	/** nonceを保存するクッキーの名前です。初期値はnonceです。 */
	private final String nonceCookieName;
	/** nonceを保存するクッキーの名前です。初期値はnonceです。 */
	public String nonceCookieName() { return this.nonceCookieName; }
	/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はrequest_pathです。 */
	private final String request_pathCookieName;
	/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はrequest_pathです。 */
	@Override
	public String request_pathCookieName() { return this.request_pathCookieName; }
	/** このライブラリ専用のresponse_modeがform_postの場合に使用するパラメーター用のPrefixです。初期値は『form_post_』です。 */
	private final String form_postParameterCookiePrefixName;
	/**
	 * このライブラリ専用のresponse_modeがform_postの場合に使用するパラメーター用のPrefixです。初期値は『form_post_』です。
	 * このライブラリでは、認証されたときにCookieを必要とするので、
	 * form_postの場合は、受信したパラメーターをCookieにセットしてリダイレクトします。
	 * そのときに、パラメーター名にこのPrefixをつけます。
	 */
	public String form_postParameterCookiePrefixName() { return this.form_postParameterCookiePrefixName; }

	/** IssuedAtを許容する期間です。0でスルーします。初期値は0です。 */
	private final int AllowedIssuanceDuration;
	/** IssuedAtを許容する期間です。0でスルーします。初期値は0です。 */
	public int allowedIssuanceDuration() { return this.AllowedIssuanceDuration; }

	/** TokenEndpointとかへの接続でProxyを使用するかどうかを表現します。初期値はfalseです。 */
	private final boolean UseProxy;
	/** TokenEndpointとかへの接続でProxyを使用するかどうかを表現します。初期値はfalseです。 */
	public boolean useProxy() { return this.UseProxy; }
	/** TokenEndpointとかへの接続でProxyを使用する場合のホスト名です。初期値はnullです。nullでデフォルトProxyを探しに行きます。 */
	private final String ProxyHost;
	/** TokenEndpointとかへの接続でProxyを使用する場合のホスト名です。初期値はnullです。nullでデフォルトProxyを探しに行きます。 */
	public String proxyHost() { return this.ProxyHost; }
	/** TokenEndpointとかへの接続でProxyを使用する場合のポートです。初期値は80です。 */
	private final int ProxyPort;
	/** TokenEndpointとかへの接続でProxyを使用する場合のポートです。初期値は80です。 */
	public int proxyPort() { return this.ProxyPort; }
	/** TokenEndpointとかへの接続で接続を待機する秒数です。初期値は3です。 */
	private final int ConnectTimeout;
	/** TokenEndpointとかへの接続で接続を待機する秒数です。初期値は3です。 */
	public int connectTimeout() { return this.ConnectTimeout; }
	/** TokenEndpointとかへの接続で読み込みを待機する秒数です（実際にはConnectTimeoutと合計されてリクエストタイムアウトとして扱われます）。初期値は5です。 */
	private final int ReadTimeout;
	/** TokenEndpointとかへの接続で読み込みを待機する秒数です（実際にはConnectTimeoutと合計されてリクエストタイムアウトとして扱われます）。初期値は5です。 */
	public int readTimeout() { return this.ReadTimeout; }
	/** TokenEndpointとかへの接続でスレッドプールを使用するかどうかを表現します。初期値はtrueです。 */
	private boolean UseThreadPool;
	/** TokenEndpointとかへの接続でスレッドプールを使用するかどうかを表現します。初期値はtrueです。 */
	public boolean useThreadPool() { return this.UseThreadPool; }

	/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
	private final String AuthenticatedURLPath;
	/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
	@Override
	public String getAuthenticatedURLPath() { return this.AuthenticatedURLPath; }
	/** 『/』で始まる、認証をしないURLパスです。 */
	private String[] IgnoreAuthenticationURLPaths;
	/** 『/』で始まる、認証をしないURLパスです。 */
	public String[] getIgnoreAuthenticationURLPaths() { return this.IgnoreAuthenticationURLPaths; }
	/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
	private Pattern IgnoreAuthenticationURLPathRegex;
	/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
	public Pattern getIgnoreAuthenticationURLPathRegex() { return this.IgnoreAuthenticationURLPathRegex; }
	/** handleMechanismNotSelectedをHttpMessageContext#isProtectedがtrueの時だけ呼ぶかどうかです。初期値はtrueです。 */
	private boolean CreateAuthorizationRequestOnlyWhenProtected;
	/** handleMechanismNotSelectedをHttpMessageContext#isProtectedがtrueの時だけ呼ぶかどうかです。初期値はtrueです。 */
	public boolean getCreateAuthorizationRequestOnlyWhenProtected() { return this.CreateAuthorizationRequestOnlyWhenProtected; }

	/**
	 * Authorization Requestを作成して適用します。
	 * 必要なパラメーターの生成や保存も行い、レスポンスを設定します。
	 * レスポンスは引数に対して設定を行います。
	 */
	protected void handleAuthorizationRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		String scope = this.scope();
		String URLBase = request.getRequestURL().substring(0, request.getRequestURL().lastIndexOf(request.getRequestURI()));
		String redirect_uri = this.handleAuthenticatedURL(URLBase + this.getAuthenticatedURLPath());
		String state = this.generateState();
		String nonce = this.generateNonce(request, response, httpMessageContext);
		String url = this.createAuthorizationRequestURL(scope, redirect_uri, state, nonce);
		Cookie scopeCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.scopeCookieName(), scope, this.getAuthenticatedURLPath(), this.useSecureCookie());
		response.addCookie(scopeCookie);
		Cookie redirect_uriCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.redirect_uriCookieName(), redirect_uri, this.getAuthenticatedURLPath(), this.useSecureCookie());
		response.addCookie(redirect_uriCookie);
		Cookie stateCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.stateCookieName(), state, this.getAuthenticatedURLPath(), this.useSecureCookie());
		response.addCookie(stateCookie);
		Cookie nonceCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.nonceCookieName(), nonce, this.getAuthenticatedURLPath(), this.useSecureCookie());
		response.addCookie(nonceCookie);
		response.setStatus(303);
		response.setHeader("Location", url);
	}

	/**
	 * Authorization Requestに使用するQueryParameterを調整します。
	 * state、response_mode、nonceを除く、Optionalなパラメーターの設定用です。
	 * 例えば、login_hint、prompt、とかを設定します。
	 * 実装時には、引数を直接変更してもかまいません。
	 * scope、state、nonce、redirect_uriを書き換えたい場合は、それぞれ、設定や専用のメソッドを使ってください。
	 * scope……scope()
	 * state……generateState()
	 * nonce……generateNonce()
	 * redirect_uri……getAuthenticatedURLPath()
	 */
	protected LinkedHashMap<String, String> handleAuthorizationRequestParameters(LinkedHashMap<String, String> parameters) { return parameters; }
	/** Token Requestに使用するParameterを調整します。実装時には、引数を直接変更してもかまいません。 */
	protected LinkedHashMap<String, String> handleTokenRequestParameters(LinkedHashMap<String, String> parameters) { return parameters; }
	/** Refresh Requestに使用するParameterを調整します。実装時には、引数を直接変更してもかまいません。 */
	protected LinkedHashMap<String, String> handleRefreshRequestParameters(LinkedHashMap<String, String> parameters) { return parameters; }
	/** Revocation Requestに使用するParameterを調整します。実装時には、引数を直接変更してもかまいません。 */
	protected LinkedHashMap<String, String> handleRevocationRequestParameters(LinkedHashMap<String, String> parameters) { return parameters; }
	/** redirect_uriを調整します。初期の実装は、単に引数を返すだけです。通常、オーバーライドすることはありません。 */
	protected String handleAuthenticatedURL(String URL) { return URL; }
	/** access_tokenのexpires_inを調整します。トークンと一緒に送られてこない場合とかのためのものです。初期の実装は、単にexpires_inパラメーターをそのまま返すだけです。 */
	protected int handleExpiresIn(int expires_in) { return expires_in; }
	/** OpenID Connectでの認証に失敗した時に呼ばれます。初期の実装は、単に認証失敗を返すだけです。 */
	protected AuthenticationStatus handleNotAuthenticated(HttpServletRequest request, HttpServletResponse response) { return AuthenticationStatus.SEND_FAILURE; }
	/** OpenID Connectでトークンエラーとして400が返ってきたときに呼ばれます。初期の実装は、単に認証失敗としてnullを返すだけです。未認可以外に、リクエストが不正である可能性がある点に注意してください。 */
	protected TokenResponse handleTokenErrorResponse(HttpRequest request, HttpResponse<InputStream> response) { return null; }
	/** OpenID Connectでリフレッシュエラーとして400が返ってきたときに呼ばれます。初期の実装は、単に認証失敗としてnullを返すだけです。未認可以外に、リクエストが不正である可能性がある点に注意してください。 */
	protected TokenResponse handleRefreshErrorResponse(HttpRequest request, HttpResponse<InputStream> response) { return null; }
	/** OpenID Connectでトークンの失効通信で400か503が返ってきたときに呼ばれます。初期の実装は、単に失敗としてfalseを返すだけです。 */
	protected boolean handleRevocationErrorResponse(HttpRequest request, HttpResponse<InputStream> response) { return false; }

	/** Tokenを発行するときのリクエストを書き換えます。引数のbuilderを変更してしまって構いません。変更した結果はreturnしてください。 */
	protected HttpRequest.Builder modifyTokenRequest(HttpRequest.Builder builder) { return builder; }
	protected HttpRequest.Builder modifyRefreshRequest(HttpRequest.Builder builder) { return builder; }

	/** Java EE Security API（Jakarta Security）で管理されるストアへのHandler。 */
	private IdentityStoreHandler IdentityStoreHandler;

	/** トークンエンドポイントへアクセスするためのHTTPクライアント。 */
	private HttpClient HTTPClient;
	/** トークンエンドポイントへの接続でリクエストを待機する秒数です。基本は、ConnectTimeoutとReadTimeoutの合計です。 */
	private Duration RequestTimeout;

	/** トークンに使用するクッキーの名前です。 */
	private String TokenCookieName;

	/** コンストラクタ。 */
	public OpenIDConnectAuthenticationMechanism(Settings settings, IdentityStoreHandler IdentityStoreHandler, ExecutorService executorService) {
		{
			this.Issuer = settings.getIssuer();
			this.AuthorizationEndpoint = settings.getAuthorizationEndpoint();
			this.TokenEndpoint = settings.getTokenEndpoint();
			this.RevocationEndpoint = settings.getRevocationEndpoint();
			this.response_type = settings.response_type();
			this.response_mode = settings.response_mode();
			this.scope = settings.scope();
			this.client_id = settings.client_id();
			this.ClientAuthenticaitonMethod = settings.getClientAuthenticaitonMethod();
			this.client_secret = settings.client_secret();
			this.UseSecureCookie = settings.useSecureCookie();
			this.TokenCookieMaxAge = settings.getTokenCookieMaxAge();
			this.scopeCookieName = settings.scopeCookieName();
			this.redirect_uriCookieName = settings.redirect_uriCookieName();
			this.stateCookieName = settings.stateCookieName();
			this.nonceCookieName = settings.nonceCookieName();
			this.request_pathCookieName = settings.request_pathCookieName();
			this.form_postParameterCookiePrefixName = settings.form_postParameterCookiePrefixName();
			this.AllowedIssuanceDuration = settings.allowedIssuanceDuration();
			this.UseProxy = settings.useProxy();
			this.ProxyHost = settings.proxyHost();
			this.ProxyPort = settings.proxyPort();
			this.ConnectTimeout = settings.connectTimeout();
			this.ReadTimeout = settings.readTimeout();
			this.AuthenticatedURLPath = settings.getAuthenticatedURLPath();
			this.IgnoreAuthenticationURLPaths = settings.getIgnoreAuthenticationURLPaths();
			this.IgnoreAuthenticationURLPathRegex = settings.getIgnoreAuthenticationURLPathRegex();
			this.CreateAuthorizationRequestOnlyWhenProtected = settings.getCreateAuthorizationRequestOnlyWhenProtected();
		}
		{
			this.IdentityStoreHandler = IdentityStoreHandler;
			var builder = HttpClient.newBuilder();
			if(this.useProxy()) {
				if(this.proxyHost() == null) {
					builder.proxy(ProxySelector.getDefault());
				} else {
					builder.proxy(ProxySelector.of(new InetSocketAddress(this.proxyHost(), this.proxyPort())));
				}
			}
			builder.connectTimeout(Duration.ofSeconds(this.ConnectTimeout));
			if(executorService != null) {
				builder.executor(executorService);
			}
			this.HTTPClient = builder.build();
			this.RequestTimeout = Duration.ofSeconds(this.ConnectTimeout + this.ReadTimeout);
			this.TokenCookieName = this.getClass().getAnnotation(RememberMe.class).cookieName();
		}
	}

	/** 必須じゃないけど、呼ぶと、ある程度の設定を確認します。 */
	protected void validateSettings() {
		if(this.client_id() == null) { throw new IllegalStateException("client_idが設定されていません。"); }
		if(ResponseTypeUtilities.containsIDToken(this.response_type()) || ResponseTypeUtilities.containsToken(this.response_type())) {
			if(this.response_mode().equals("query")) {
				throw new IllegalStateException("response_typeとresponse_modeの組み合わせを確認してください。");
			}
		}
		if((this.getClientAuthenticaitonMethod().equals("client_secret_post") && (this.client_secret() != null)) == false) {
			throw new IllegalStateException("Client Authenticaiton Methodがclient_secret_postの場合は、client_secretを設定設定してください。");
		}
	}

	/**
	 * RememberMeのキャッシュ確認で回収しきれなかった（クッキーがないとかの）場合に、
	 * Java EE Security API（Jakarta Security）から呼び出されます。
	 * リクエストされたパスがAuthenticatedURLPathの場合は、検証します。
	 * それ以外の場合は、認証状態をストアで確認して、未認証の場合は、認証要求（リダイレクト）をします。
	 */
	@Override
	public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
		String requestURI = request.getRequestURI();
		String[] ignoreURLPaths = this.getIgnoreAuthenticationURLPaths();
		if(ignoreURLPaths != null) {
			for(String ignoreURLPath : ignoreURLPaths) {
				if(requestURI.equals(ignoreURLPath)) {
					return AuthenticationStatus.NOT_DONE;
				}
			}
		}
		Pattern ignoreURLPathRegex = this.getIgnoreAuthenticationURLPathRegex();
		if(ignoreURLPathRegex != null) {
			if(ignoreURLPathRegex.matcher(requestURI).matches()) {
				return AuthenticationStatus.NOT_DONE;
			}
		}
		if(requestURI.equals(this.getAuthenticatedURLPath())) {
			if(this.response_mode().equals("form_post")) {
				if(request.getMethod().equals("POST")) {
					StringBuilder builder = new StringBuilder(requestURI);
					boolean containsQ = (requestURI.contains("?"));
					for(Map.Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
						String name = entry.getKey();
						String encodedName = URLEncoder.encode(name, StandardCharsets.UTF_8);
						String[] values = entry.getValue();
						for(String value : values) {
							String form_postCookiePrefixName = this.form_postParameterCookiePrefixName();
							if((form_postCookiePrefixName != null) && (form_postCookiePrefixName.isEmpty() == false)) {
								Cookie cookie = IOpenIDConnectAuthenticationMechanism.createCookie(form_postCookiePrefixName + name, value, this.getAuthenticatedURLPath(), this.useSecureCookie());
								response.addCookie(cookie);
							} else {
								builder.append(containsQ ? "&" : "?");
								String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
								builder.append(encodedName).append("=").append(encodedValue);
							}
						}
					}
					String url = builder.toString();
					response.setStatus(303);
					response.setHeader("Location", url);
					return AuthenticationStatus.SEND_CONTINUE;
				}
			}
			Map<String, String> cookies;
			{
				Cookie[] cs = request.getCookies();
				cookies = (cs != null) ? Arrays.stream(cs).collect(Collectors.toMap(c -> c.getName(), c -> c.getValue())) : Collections.emptyMap();
			}
			// from_postされたパラメーターは、エラーで維持されないように、すぐに破棄を登録しておく。
			for(Map.Entry<String, String> cookie : cookies.entrySet()) {
				if(
					cookie.getKey().startsWith(this.form_postParameterCookiePrefixName())
				) {
					Cookie c = IOpenIDConnectAuthenticationMechanism.createCookie(cookie.getKey(), cookie.getValue(), this.getAuthenticatedURLPath(), this.useSecureCookie());
					c.setMaxAge(0);
					response.addCookie(c);
				}
			}
			String scopeCookie = cookies.get(this.scopeCookieName());
			String redirect_uriCookie = cookies.get(this.redirect_uriCookieName());
			String stateCookie = cookies.get(this.stateCookieName());
			String nonceCookie = cookies.get(this.nonceCookieName());
			if(scopeCookie == null) { throw new IllegalStateException("scopeを確認するための値が取得できませんでした。"); }
			if(redirect_uriCookie == null) { throw new IllegalStateException("redirect_uriを確認するための値が取得できませんでした。"); }
			if(stateCookie == null) { throw new IllegalStateException("stateを確認するための値が取得できませんでした。"); }
			if(nonceCookie == null) { throw new IllegalStateException("nonceを確認するための値が取得できませんでした。"); }
			String error = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "error") : request.getParameter("error");
			if(error != null) {
				AuthenticationStatus result = this.handleNotAuthenticated(request, response);
				return result;
			}
			String state = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "state") : request.getParameter("state");
			if((state == null) || (state.equals(stateCookie) == false)) {
				throw new IllegalStateException("stateの検証に失敗しました。");
			}
			String response_type = this.response_type();
			Flow flow = ResponseTypeUtilities.detectFlow(response_type);
			CredentialValidationResult result;
			{
				String code;
				String id_token;
				String access_token;
				String token_type;
				String refresh_token;
				int expires_in;
				LocalDateTime createdAt;
				String scope;
				switch(flow) {
					case AuthorizationCode: {
						code = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "code") : request.getParameter("code");
						if(code == null) {
							throw new IllegalStateException("codeが含まれていません。");
						}
						TokenResponse tokenResponse = this.issueToken(code, redirect_uriCookie);
						if(tokenResponse == null) { return AuthenticationStatus.SEND_FAILURE; }
						id_token = tokenResponse.id_token();
						access_token = tokenResponse.access_token();
						refresh_token = tokenResponse.refresh_token();
						token_type = tokenResponse.token_type();
						expires_in = this.handleExpiresIn(tokenResponse.expires_in());
						createdAt = LocalDateTime.now();
						scope = tokenResponse.scope();
						break;
					}
					case Implicit: {
						// Implicit Flowでは認証コードはない。
						code = null;
						id_token = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "id_token") : request.getParameter("id_token");
						// Implicit Flowではリフレッシュトークンはない。
						if(ResponseTypeUtilities.containsToken(response_type)) {
							access_token = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "access_token") : request.getParameter("access_token");
							refresh_token = null;
							token_type = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "token_type") : request.getParameter("token_type");
							String expires_inString = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "expires_in") : request.getParameter("expires_in");
							expires_in = this.handleExpiresIn((expires_inString != null) ? Integer.parseInt(expires_inString) : OpenIDConnectCredential.UNDEFINED_EXPIRES_IN);
							createdAt = LocalDateTime.now();
							scope = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "scope") : request.getParameter("scope");;
						} else {
							access_token = null;
							refresh_token = null;
							token_type = null;
							expires_in = OpenIDConnectCredential.UNDEFINED_EXPIRES_IN;
							createdAt = null;
							scope = null;
						}
						break;
					}
					case Hybird: {
						code = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "code") : request.getParameter("code");
						if(code == null) {
							throw new IllegalStateException("codeが含まれていません。");
						}
						if(ResponseTypeUtilities.containsIDToken(response_type)) {
							id_token = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "id_token") : request.getParameter("id_token");
							Jws<Claims> id_tokenJws;
							try {
								id_tokenJws = this.parseIDToken(id_token, null);
							} catch(JwtException ex) {
								throw new IllegalStateException("不正なIDトークンでした。", ex);
							}
							if(ResponseTypeUtilities.containsCode(response_type) && ResponseTypeUtilities.containsIDToken(response_type)) {
								try {
									this.validateCode(code, id_tokenJws);
								} catch(Exception ex) {
									throw new IllegalStateException("不正な認証コードでした。", ex);
								}
							}
						}
						// https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#HybridTokenEndpoint
						TokenResponse tokenResponse = this.issueToken(code, redirect_uriCookie);
						if(tokenResponse == null) { return AuthenticationStatus.SEND_FAILURE; }
						id_token = tokenResponse.id_token();
						if(ResponseTypeUtilities.containsToken(response_type)) {
							access_token = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "access_token") : request.getParameter("access_token");
							refresh_token = null;
							token_type = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "token_type") : request.getParameter("token_type");
							String expires_inString = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "expires_in") : request.getParameter("expires_in");
							expires_in = this.handleExpiresIn((expires_inString != null) ? Integer.parseInt(expires_inString) : OpenIDConnectCredential.UNDEFINED_EXPIRES_IN);
							createdAt = LocalDateTime.now();
							scope = this.response_mode().equals("form_post") ? cookies.get(this.form_postParameterCookiePrefixName() + "scope") : request.getParameter("scope");;
						} else {
							access_token = tokenResponse.access_token();
							refresh_token = tokenResponse.refresh_token();
							token_type = tokenResponse.token_type();
							expires_in = this.handleExpiresIn(tokenResponse.expires_in());
							createdAt = LocalDateTime.now();
							scope = tokenResponse.scope();
						}
						break;
					}
					default: { throw new IllegalStateException("サポートされていないFlowが指定されました。"); }
				}
				Jws<Claims> id_tokenJws;
				try {
					id_tokenJws = this.parseIDToken(id_token, null);
				} catch(JwtException ex) {
					throw new IllegalStateException("不正なIDトークンでした。", ex);
				}
				try {
					this.validateIDToken(id_tokenJws, nonceCookie, null);
				} catch(Exception ex) {
					throw new IllegalStateException("不正なIDトークンでした。", ex);
				}
				if(ResponseTypeUtilities.containsToken(response_type)) {
					try {
						this.validateAccessToken(access_token, token_type, id_tokenJws, scopeCookie, nonceCookie, null);
					} catch(Exception ex) {
						throw new IllegalStateException("不正なアクセストークンでした。", ex);
					}
				}
				Claims id_tokenBody = id_tokenJws.getBody();
				String issuer = id_tokenBody.getIssuer();
				String subject = id_tokenBody.getSubject();
				long expirationTime = id_tokenBody.getExpiration().toInstant().toEpochMilli() / 1000;
				long issuedAt = id_tokenBody.getIssuedAt().toInstant().toEpochMilli() / 1000;
				OpenIDConnectCredential credential = this.createCredential(issuer, subject, id_token, expirationTime, issuedAt, access_token, refresh_token, expires_in, createdAt, (scope != null) ? scope : scopeCookie, id_tokenBody);
				result = this.IdentityStoreHandler.validate(credential);
			}
			if(result.getStatus() == Status.VALID) {
				// 成功したのでクッキーを削除する。
				// 失敗した場合は、そのセッションの間だけだしそのままにしておく。どうせダメダメな値の組み合わせだし、必要なら、一部は再利用するかもしれないから。
				for(Map.Entry<String, String> cookie : cookies.entrySet()) {
					if(
						cookie.getKey().equals(this.stateCookieName()) ||
						cookie.getKey().equals(this.scopeCookieName()) ||
						cookie.getKey().equals(this.redirect_uriCookieName()) ||
						cookie.getKey().equals(this.nonceCookieName())
					) {
						Cookie c = IOpenIDConnectAuthenticationMechanism.createCookie(cookie.getKey(), cookie.getValue(), this.getAuthenticatedURLPath(), this.useSecureCookie());
						c.setMaxAge(0);
						response.addCookie(c);
					}
				}
			}
			return httpMessageContext.notifyContainerAboutLogin(result.getCallerPrincipal(), result.getCallerGroups());
		}
		{
			// クッキーがあったら、キャッシュにはないと思うのだけど、復元やリフレッシュ可能かを確認する。
			Cookie tokenCookie = IOpenIDConnectAuthenticationMechanism.extractCookie(this.TokenCookieName, request);
			if(tokenCookie != null) {
				CredentialValidationResult result = this.IdentityStoreHandler.validate(new RememberMeCredential(tokenCookie.getValue()));
				if(result.getStatus() == CredentialValidationResult.Status.VALID) {
					return httpMessageContext.notifyContainerAboutLogin(result.getCallerPrincipal(), result.getCallerGroups());
				}
			}
		}
		AuthenticationStatus result;
		if(httpMessageContext.isProtected() || (this.getCreateAuthorizationRequestOnlyWhenProtected() == false)) {
			this.handleAuthorizationRequest(request, response, httpMessageContext);
			result = AuthenticationStatus.SEND_CONTINUE;
		} else {
			result = AuthenticationStatus.NOT_DONE;
		}
		return result;
	}

	/**
	 * トークンを発行してもらいます。
	 */
	protected TokenResponse issueToken(String code, String redirect_uri) {
		String requestBody = this.createTokenRequestBody(code, redirect_uri);
		HttpRequest.Builder builder = HttpRequest.newBuilder(this.getTokenEndpoint());
		builder = this.modifyTokenRequest(builder);
		HttpRequest request = builder
			.timeout(this.RequestTimeout)
			.setHeader("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString(requestBody))
			.build();
		HttpResponse<InputStream> response;
		if(this.useThreadPool() == false) {
			try {
				response = this.HTTPClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
			} catch(InterruptedException | IOException ex) {
				throw new IllegalStateException("アクセストークンの取得に失敗しました。", ex);
			}
		} else {
			var task = this.HTTPClient.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
			try {
				response = task.get();
			} catch(InterruptedException | ExecutionException ex) {
				throw new IllegalStateException("アクセストークンの取得に失敗しました。", ex);
			}
		}
		if(response.statusCode() == 400) {
			return this.handleTokenErrorResponse(request, response);
		}
		// Validate Token Response.
		// https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#TokenResponseValidation
		if(response.statusCode() != 200) {
			String body;
			try {
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				response.body().transferTo(out);
				body = out.toString(StandardCharsets.UTF_8);
			} catch(IOException ex) {
				body = MessageFormat.format("Bodyの読み込みに失敗しました{0}。", ex.getMessage());
			}
			String message = MessageFormat.format("アクセストークンの取得に失敗しました（{0}:{1}）。", response.statusCode(), body);
			throw new IllegalStateException(message);
		}
		InputStream responseBody = response.body();
		// 定数にしよう。
		TokenResponse tokenResponse = this.createTokenResponse(responseBody, "authorization_code");
		return tokenResponse;
	}

	/**
	 * トークンをリフレッシュします。
	 * @param refresh_token
	 * @param credential リフレッシュする場合に、以前のCredentialが指定されます。
	 */
	@Override
	public TokenResponse refreshToken(String refresh_token, OpenIDConnectCredential credential) {
		String requestBody = this.createRefreshRequestBody(refresh_token);
		HttpRequest.Builder builder = HttpRequest.newBuilder(this.getTokenEndpoint());
		builder = this.modifyRefreshRequest(builder);
		HttpRequest request = builder
			.timeout(this.RequestTimeout)
			.setHeader("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString(requestBody))
			.build();
		HttpResponse<InputStream> response;
		if(this.useThreadPool() == false) {
			try {
				response = this.HTTPClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
			} catch(InterruptedException | IOException ex) {
				throw new IllegalStateException("アクセストークンの取得に失敗しました。", ex);
			}
		} else {
			var task = this.HTTPClient.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
			try {
				response = task.get();
			} catch(InterruptedException | ExecutionException ex) {
				throw new IllegalStateException("アクセストークンの取得に失敗しました。", ex);
			}
		}
		if(response.statusCode() == 400) {
			return this.handleRefreshErrorResponse(request, response);
		}
		// Validate Token Response.
		// https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#TokenResponseValidation
		if(response.statusCode() != 200) {
			String message = MessageFormat.format("アクセストークンの取得に失敗しました（{0}）。", response.statusCode());
			throw new IllegalStateException(message);
		}
		InputStream responseBody = response.body();
		TokenResponse tokenResponse = this.createTokenResponse(responseBody, "refresh_token");
		return tokenResponse;
	}

	/**
	 * トークンを失効させます。
	 * 失効した場合はtrue。それ以外はfalseを返します。
	 * @param credential 破棄する場合に、以前のCredentialが指定されます。
	 */
	@Override
	public boolean revokeToken(String token, String token_type_hint, OpenIDConnectCredential credential) {
		if(this.getRevocationEndpoint() == null) { return false; }
		String requestBody = this.createRevocationRequestBody(token, token_type_hint);
		HttpRequest.Builder builder = HttpRequest.newBuilder(this.getRevocationEndpoint());
		builder = this.modifyRefreshRequest(builder);
		HttpRequest request = builder
			.timeout(this.RequestTimeout)
			.setHeader("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString(requestBody))
			.build();
		HttpResponse<InputStream> response;
		if(this.useThreadPool() == false) {
			try {
				response = this.HTTPClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
			} catch(InterruptedException | IOException ex) {
				throw new IllegalStateException("アクセストークンの取得に失敗しました。", ex);
			}
		} else {
			var task = this.HTTPClient.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream());
			try {
				response = task.get();
			} catch(InterruptedException | ExecutionException ex) {
				throw new IllegalStateException("アクセストークンの取得に失敗しました。", ex);
			}
		}
		if(response.statusCode() == 400) {
			return this.handleRevocationErrorResponse(request, response);
		}
		if(response.statusCode() == 503) {
			return this.handleRevocationErrorResponse(request, response);
		}
		if(response.statusCode() != 200) {
			String message = MessageFormat.format("アクセストークンの取得に失敗しました（{0}）。", response.statusCode());
			throw new IllegalStateException(message);
		}
		return true;
	}

	/**
	 * 
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#AuthRequest
	 */
	protected String createAuthorizationRequestURL(String scope, String redirect_uri, String state, String nonce) {
		LinkedHashMap<String, String> parameters = new LinkedHashMap<String, String>();
		parameters.put("scope", scope);
		parameters.put("response_type", this.response_type());
		parameters.put("client_id", this.client_id());
		parameters.put("redirect_uri", redirect_uri);
		parameters.put("state", state);
		if(ResponseTypeUtilities.defaultResponseMode(this.response_type()).equals(this.response_mode()) == false) {
			parameters.put("response_mode", this.response_mode());
		}
		parameters.put("nonce", nonce);
		parameters = this.handleAuthorizationRequestParameters(parameters);
		String url = this.getAuthorizationEndpoint() + "?" + OpenIDConnectAuthenticationMechanism.convertToParameterString(parameters);
		return url;
	}

	/**
	 * トークンを発行するためのリクエストのBodyを作成します。
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#TokenRequest
	 * https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.3
	 * 初期実装ではclient_secret_postの場合にclient_secretも送ります。
	 */
	protected String createTokenRequestBody(String code, String redirect_uri) {
		LinkedHashMap<String, String> parameters = new LinkedHashMap<String, String>();
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", code);
		// ここでは、認可リクエストにredirect_uriを含むので必須。
		parameters.put("redirect_uri", redirect_uri);
		parameters.put("client_id", this.client_id());
		if(this.getClientAuthenticaitonMethod().equals("client_secret_post")) {
			parameters.put("client_secret", this.client_secret());
		}
		parameters = this.handleTokenRequestParameters(parameters);
		String requestBody = OpenIDConnectAuthenticationMechanism.convertToParameterString(parameters);
		return requestBody;
	}

	/**
	 * トークンをリフレッシュするためのリクエストのBodyを作成します。
	 * 初期実装では、scopeは付与しません。
	 * 初期実装ではclient_secret_postの場合にclient_idとclient_secretも送ります。
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#RefreshTokens
	 * https://www.rfc-editor.org/rfc/rfc6749.html#section-6
	 */
	protected String createRefreshRequestBody(String refreshToken) {
		LinkedHashMap<String, String> parameters = new LinkedHashMap<String, String>();
		parameters.put("grant_type", "refresh_token");
		parameters.put("refresh_token", refreshToken);
		// scopeの変更がある場合、ここではもう、ない前提で設定しない。
		// "scope" + "=" + scope + "&" +
		if(this.getClientAuthenticaitonMethod().equals("client_secret_post")) {
			parameters.put("client_id", this.client_id());
			parameters.put("client_secret", this.client_secret());
		}
		parameters = this.handleRefreshRequestParameters(parameters);
		String requestBody = OpenIDConnectAuthenticationMechanism.convertToParameterString(parameters);
		return requestBody;
	}

	/**
	 * トークンを破棄するためのリクエストのBodyを作成します。
	 * https://openid-foundation-japan.github.io/rfc7009.ja.html
	 */
	protected String createRevocationRequestBody(String token, String token_type_hint) {
		LinkedHashMap<String, String> parameters = new LinkedHashMap<String, String>();
		parameters.put("token", token);
		parameters.put("token_type_hint", token_type_hint);
		parameters = this.handleRevocationRequestParameters(parameters);
		String requestBody = OpenIDConnectAuthenticationMechanism.convertToParameterString(parameters);
		return requestBody;
	}

	/**
	 * トークンのレスポンスを読み込みます。
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#RefreshTokenResponse
	 */
	protected TokenResponse createTokenResponse(InputStream responseBody, String grant_type) {
		JsonNode node;
		ObjectMapper mapper = new ObjectMapper();
		try {
			node = mapper.readTree(responseBody);
		} catch(IOException ex) {
			throw new IllegalStateException("Token Responseの解析に失敗しました。", ex);
		}
		String access_token = node.get("access_token").asText();
		String token_type = node.get("token_type").asText();
		int expires_in = node.has("expires_in") ? node.get("expires_in").asInt() : OpenIDConnectCredential.UNDEFINED_EXPIRES_IN;
		String refresh_token = node.has("refresh_token") ? node.get("refresh_token").asText() : null;
		String scope = node.has("scope") ? node.get("scope").asText() : null;
		String id_token;
		// grated_typeでid_tokenの必須を区別する。
		switch(grant_type) {
			case "authorization_code": { id_token = node.get("id_token").asText(); break; }
			case "refresh_token": { id_token = node.has("id_token") ? node.get("id_token").asText(): null; break; }
			default: { throw new IllegalArgumentException("grant_typeが不正です。"); }
		}
		TokenResponse tokenResponse = new TokenResponse(access_token, token_type, expires_in, refresh_token, scope, id_token);
		return tokenResponse;
	}

	/**
	 * IDトークンの文字列を解析して署名を確認します。
	 * https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-5.2
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public abstract Jws<Claims> parseIDToken(String id_tokenString, OpenIDConnectCredential credential);

	/**
	 * codeを検証します。
	 * 可能な範囲でc_hashを検証します。
	 * Access Token Validation
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#CodeValidation
	 * 問題がある場合は例外が投げられます。
	 */
	public void validateCode(String code, Jws<Claims> id_token) {
		String c_hash = id_token.getBody().get("c_hash", String.class);
		if(c_hash == null) {
			if((ResponseTypeUtilities.detectFlow(this.response_type()) == Flow.Hybird) && ResponseTypeUtilities.containsCode(this.response_type())) {
				throw new IllegalStateException("c_hashがありません。Hybird Flowでcodeが一緒に渡ってくる場合は必須です。");
			} else {
				// 正常ルートです。
			}
		} else {
			String alg = id_token.getHeader().getAlgorithm();
			if(alg.equals("RS256")) {
				MessageDigest sha256;
				try {
					sha256 = MessageDigest.getInstance("SHA-256");
				} catch(NoSuchAlgorithmException ex) {
					throw new IllegalStateException("この環境ではSHA-256はサポートされていません。", ex);
				}
				byte[] hash = sha256.digest(code.getBytes(StandardCharsets.UTF_8));
				byte[] left_half = new byte[hash.length / 2];
				System.arraycopy(hash, 0, left_half, 0, left_half.length);
				String c_hashComputed = Base64.getUrlEncoder().withoutPadding().encodeToString(left_half);
				if(c_hash.equals(c_hashComputed) == false) {
					String message = MessageFormat.format("c_hash[{0}]の値が計算値[{1}]と一致しませんでした。", c_hash, c_hashComputed);
					throw new IllegalStateException(message);
				} else {
					// 正常ルートです。
				}
			} else {
				String message = MessageFormat.format("認証コードの検証に失敗しました。RS256以外のアルゴリズム[{0}]は未サポートです。", alg);
				throw new IllegalStateException(message);
			}
		}
	}

	/**
	 * id_tokenを検証します。
	 * Payload（Claims）を検証します。
	 * audienceは単一のもののみ対応しています。
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#IDTokenValidation
	 * 問題がある場合は例外が投げられます。
	 * @param requestedNonce 指定がある場合は確認をします。
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public void validateIDToken(Jws<Claims> id_token, String requestedNonce, OpenIDConnectCredential  credential) {
		Claims claims = id_token.getBody();
		{
			String iss = claims.getIssuer();
			if(iss.equals(this.getIssuer()) == false) {
				throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
			}
		}
		{
			String aud = claims.getAudience();
			if(aud.equals(this.client_id()) == false) {
				throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
			}
		}
		if(claims.containsKey("azp")) {
			String azp = claims.get("azp", String.class);
			if(azp.equals(this.client_id()) == false) {
				throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
			}
		}
		long current = OpenIDConnectUtilities.currentUNIXTime();
		{
			long exp = claims.get("exp", Integer.class).longValue();
			if((current < exp) == false) {
				throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
			}
		}
		{
			long iat = claims.get("iat", Integer.class).longValue();
			int allowedDuration = this.allowedIssuanceDuration();
			if(allowedDuration != 0) {
				if(iat < (current - allowedDuration)) {
					throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
				}
			}
		}
		if(requestedNonce != null) {
			if(claims.get("nonce", String.class).equals(requestedNonce) == false) {
				throw new IllegalStateException("IDトークンが期待した形式ではありませんでした。");
			}
		}
	}

	/**
	 * access_tokenを検証します。
	 * 問題がある場合は例外が投げられます。
	 * 可能な範囲でat_hashを検証します。
	 * Access Token Validation
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#CodeFlowTokenValidation
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#ImplicitTokenValidation
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#HybridTokenValidation2
	 * @param access_token
	 * @param requestedScope 参考に渡されます。
	 * @param requestedNonce 参考に渡されます。リフレッシュされた場合とかは渡されません。
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public void validateAccessToken(String access_token, String token_type, Jws<Claims> id_token, String requestedScope, String requestedNonce, OpenIDConnectCredential credential) {
		if(access_token == null) { return; }
		String at_hash = id_token.getBody().get("at_hash", String.class);
		if(at_hash == null) {
			if((ResponseTypeUtilities.detectFlow(this.response_type()) == Flow.Implicit) && ResponseTypeUtilities.containsToken(this.response_type())) {
				throw new IllegalStateException("at_hashがありません。Implicit Flowでtokenが一緒に渡ってくる場合は必須です。");
			} else {
				// 正常ルートです。
			}
		} else {
			String alg = id_token.getHeader().getAlgorithm();
			if(alg.equals("RS256")) {
				MessageDigest sha256;
				try {
					sha256 = MessageDigest.getInstance("SHA-256");
				} catch(NoSuchAlgorithmException ex) {
					throw new IllegalStateException("この環境ではSHA-256はサポートされていません。", ex);
				}
				byte[] hash = sha256.digest(access_token.getBytes(StandardCharsets.UTF_8));
				byte[] left_half = new byte[hash.length / 2];
				System.arraycopy(hash, 0, left_half, 0, left_half.length);
				String at_hashComputed = Base64.getUrlEncoder().withoutPadding().encodeToString(left_half);
				if(at_hash.equals(at_hashComputed) == false) {
					String message = MessageFormat.format("at_hash[{0}]の値が計算値[{1}]と一致しませんでした。", at_hash, at_hashComputed);
					throw new IllegalStateException(message);
				} else {
					// 正常ルートです。
				}
			} else {
				String message = MessageFormat.format("アクセストークンの検証に失敗しました。RS256以外のアルゴリズム[{0}]は未サポートです。", alg);
				throw new IllegalStateException(message);
			}
		}
	}

	/** stateを生成します。 */
	protected String generateState() {
		String state = OpenIDConnectUtilities.generateState();
		return state;
	}

	/** nonceを生成します。 */
	protected String generateNonce(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		String nonce = OpenIDConnectUtilities.generateNonce();
		return nonce;
	}

	/** パラメーターをエンコード済みの文字列に変換します。 */
	private static String convertToParameterString(Map<String, String> parameters) {
		StringBuilder builder = new StringBuilder();
		String separator = "";
		for(Map.Entry<String, String> entry : parameters.entrySet()) {
			builder.append(separator);
			separator = "&";
			builder.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8));
			builder.append("=");
			builder.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
		}
		String parameterString = builder.toString();
		return parameterString;
	}

	/**
	 * response_typeの諸々のUtilitiesです。
	 * @author すふぃあ
	 */
	private static class ResponseTypeUtilities {
		/** 単語としてのcodeを含んでいるかどうか。 */
		public static boolean containsCode(String response_type) {
			boolean result;
			switch(response_type) {
				case "code": { result = true; break; }
				case "id_token":
				case "id_token token": { result = false; break; }
				case "code id_token":
				case "code token":
				case "code id_token token": { result = true; break; }
				default: {
					String message = MessageFormat.format("サポートしていないresponse_type[{0}]が指定されました。", response_type);
					throw new IllegalArgumentException(message);
				}
			}
			return result;
		}
		/** 単語としてのid_tokenを含んでいるかどうか。 */
		public static boolean containsIDToken(String response_type) {
			boolean result;
			switch(response_type) {
				case "code": { result = false; break; }
				case "id_token":
				case "id_token token": { result = true; break; }
				case "code id_token": { result = true; break; }
				case "code token": { result = false; break; }
				case "code id_token token": { result = true; break; }
				default: {
					String message = MessageFormat.format("サポートしていないresponse_type[{0}]が指定されました。", response_type);
					throw new IllegalArgumentException(message);
				}
			}
			return result;
		}
		/** 単語としてのtokenを含んでいるかどうか。 */
		public static boolean containsToken(String response_type) {
			boolean result;
			switch(response_type) {
				case "code": { result = false; break; }
				case "id_token": { result = false; break; }
				case "id_token token": { result = true; break; }
				case "code id_token": { result = false; break; }
				case "code token": { result = true; break; }
				case "code id_token token": { result = true; break; }
				default: {
					String message = MessageFormat.format("サポートしていないresponse_type[{0}]が指定されました。", response_type);
					throw new IllegalArgumentException(message);
				}
			}
			return result;
		}
		/** response_typeに対応するFlowを返します。 */
		public static Flow detectFlow(String response_type) {
			Flow result;
			switch(response_type) {
				case "code": { result = Flow.AuthorizationCode; break; }
				case "id_token":
				case "id_token token": { result = Flow.Implicit; break; }
				case "code id_token":
				case "code token":
				case "code id_token token": { result = Flow.Hybird; break; }
				default: {
					String message = MessageFormat.format("サポートしていないresponse_type[{0}]が指定されました。", response_type);
					throw new IllegalArgumentException(message);
				}
			}
			return result;
		}
		/** response_typeに対応するresponse_modeの初期値を返します。 */
		public static String defaultResponseMode(String response_type) {
			String result;
			switch(response_type) {
				case "code": { result = "query"; break; }
				case "id_token":
				case "id_token token":
				case "code id_token":
				case "code token":
				case "code id_token token": { result = "fragment"; break; }
				default: {
					String message = MessageFormat.format("サポートしていないresponse_type[{0}]が指定されました。", response_type);
					throw new IllegalArgumentException(message);
				}
			}
			return result;
		}
	}

	/** Flow。 */
	private static enum Flow {
		/** Authorization Code Flow。 */
		AuthorizationCode,
		/** Implicit Flow。 */
		Implicit,
		/** Hybird Flow。 */
		Hybird,
		;
	}

	/**
	 * 設定用のクラス。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	@Typed(Settings.class)
	public static class Settings {
		/** Issuer。 */
		private String Issuer;
		/** Issuer。 */
		public String getIssuer() { return this.Issuer; }
		/** Issuer。 */
		public void setIssuer(String Issuer) { this.Issuer = Issuer; }
		/** AuthorizationEndpoint。 */
		private String AuthorizationEndpoint;
		/** AuthorizationEndpoint。 */
		public String getAuthorizationEndpoint() { return this.AuthorizationEndpoint; }
		/** AuthorizationEndpoint。 */
		public void setAuthorizationEndpoint(String AuthorizationEndpoint) { this.AuthorizationEndpoint = AuthorizationEndpoint; }
		/** TokenEndpoint。ない場合はnullで。初期値はnullです。 */
		private URI TokenEndpoint;
		/** TokenEndpoint。ない場合はnullで。初期値はnullです。 */
		public URI getTokenEndpoint() { return this.TokenEndpoint; }
		/** TokenEndpoint。ない場合はnullで。初期値はnullです。 */
		public void setTokenEndpoint(URI TokenEndpoint) { this.TokenEndpoint = TokenEndpoint; }
		/** RevocationEndpoint。ない場合はnullで。初期値はnullです。 */
		private URI RevocationEndpoint;
		/** RevocationEndpoint。ない場合はnullで。初期値はnullです。 */
		public URI getRevocationEndpoint() { return this.RevocationEndpoint; }
		/** RevocationEndpoint。ない場合はnullで。初期値はnullです。 */
		public void setRevocationEndpoint(URI RevocationEndpoint) { this.RevocationEndpoint = RevocationEndpoint; }

		/** response_typeです。初期値はcodeです。 */
		private String response_type;
		/** response_typeです。初期値はcodeです。 */
		public String response_type() { return this.response_type; }
		/** response_typeです。初期値はcodeです。 */
		public void response_type(String response_type) { this.response_type = response_type; }
		/** response_modeです。初期値はqueryです。from_postもサポートしています。その場合は、form_postCookiePrefixNameの設定を確認してください。 */
		private String response_mode;
		/** response_modeです。初期値はqueryです。from_postもサポートしています。その場合は、form_postCookiePrefixNameの設定を確認してください。 */
		public String response_mode() { return this.response_mode; }
		/** response_modeです。初期値はqueryです。from_postもサポートしています。その場合は、form_postCookiePrefixNameの設定を確認してください。 */
		public void response_mode(String response_mode) { this.response_mode = response_mode; }

		/** scope。初期値はopenidです。 */
		private String scope;
		/** scope。初期値はopenidです。 */
		public String scope() { return this.scope; }
		/** scope。初期値はopenidです。 */
		public void scope(String scope) {this.scope = scope; }

		/** client_id。 */
		private String client_id;
		/** client_id。 */
		public String client_id() { return this.client_id; }
		/** client_id。 */
		public void client_id(String client_id) {this.client_id = client_id; }
		/** Client Authentication Method。client_secret_postにだけ対応しています。 */
		private String ClientAuthenticaitonMethod;
		/** Client Authentication Method。client_secret_postにだけ対応しています。 */
		public String getClientAuthenticaitonMethod() { return this.ClientAuthenticaitonMethod; }
		/** Client Authentication Method。client_secret_postにだけ対応しています。 */
		public void setClientAuthenticaitonMethod(String ClientAuthenticaitonMethod) { this.ClientAuthenticaitonMethod = ClientAuthenticaitonMethod; }
		/** client_secret。 */
		private String client_secret;
		/** client_secret。 */
		public String client_secret() { return this.client_secret; }
		/** client_secret。 */
		public void client_secret(String client_secret) { this.client_secret = client_secret; }

		/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
		private boolean UseSecureCookie;
		/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
		public boolean useSecureCookie() { return this.UseSecureCookie; }
		/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
		public void useSecureCookie(boolean UseSecureCookie) { this.UseSecureCookie = UseSecureCookie; }
		/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
		private int TokenCookieMaxAge;
		/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
		public int getTokenCookieMaxAge() { return this.TokenCookieMaxAge; }
		/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
		public void setTokenCookieMaxAge(int TokenCookieMaxAge) { this.TokenCookieMaxAge = TokenCookieMaxAge; }
		/** scopeを保存するクッキーの名前です。初期値はscopeです。 */
		private String scopeCookieName;
		/** scopeを保存するクッキーの名前です。初期値はscopeです。 */
		public String scopeCookieName() { return this.scopeCookieName; }
		/** scopeを保存するクッキーの名前です。初期値はscopeです。 */
		public void scopeCookieName(String scopeCookieName) { this.scopeCookieName = scopeCookieName; }
		/** redirect_uriを保存するクッキーの名前です。初期値はredirect_uriです。 */
		private String redirect_uriCookieName;
		/** redirect_uriを保存するクッキーの名前です。初期値はredirect_uriです。 */
		public String redirect_uriCookieName() { return this.redirect_uriCookieName; }
		/** redirect_uriを保存するクッキーの名前です。初期値はredirect_uriです。 */
		public void redirect_uriCookieName(String redirect_uriCookieName) { this.redirect_uriCookieName = redirect_uriCookieName; }
		/** stateを保存するクッキーの名前です。初期値はstateです。 */
		private String stateCookieName;
		/** stateを保存するクッキーの名前です。初期値はstateです。 */
		public String stateCookieName() { return this.stateCookieName; }
		/** stateを保存するクッキーの名前です。初期値はstateです。 */
		public void stateCookieName(String stateCookieName) { this.stateCookieName = stateCookieName; }
		/** nonceを保存するクッキーの名前です。初期値はnonceです。 */
		private String nonceCookieName;
		/** nonceを保存するクッキーの名前です。初期値はnonceです。 */
		public String nonceCookieName() { return this.nonceCookieName; }
		/** nonceを保存するクッキーの名前です。初期値はnonceです。 */
		public void nonceCookieName(String nonceCookieName) { this.nonceCookieName = nonceCookieName; }
		/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はrequest_pathです。 */
		private String request_pathCookieName;
		/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はrequest_pathです。 */
		public String request_pathCookieName() { return this.request_pathCookieName; }
		/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はrequest_pathです。 */
		public void request_pathCookieName(String request_pathCookieName) { this.request_pathCookieName = request_pathCookieName; }
		/** このライブラリ専用のresponse_modeがform_postの場合に使用するパラメーター用のPrefixです。初期値は『form_post_』です。 */
		private String form_postParameterCookiePrefixName;
		/**
		 * このライブラリ専用のresponse_modeがform_postの場合に使用するパラメーター用のPrefixです。初期値は『form_post_』です。
		 * このライブラリでは、認証されたときにCookieを必要とするので、
		 * form_postの場合は、受信したパラメーターをCookieにセットしてリダイレクトします。
		 * そのときに、パラメーター名にこのPrefixをつけます。
		 */
		public String form_postParameterCookiePrefixName() { return this.form_postParameterCookiePrefixName; }
		/** このライブラリ専用のresponse_modeがform_postの場合に使用するパラメーター用のPrefixです。初期値は『form_post_』です。 */
		public void form_postParameterCookiePrefixName(String form_postParameterCookiePrefixName) { this.form_postParameterCookiePrefixName = form_postParameterCookiePrefixName; }

		/** IssuedAtを許容する期間です。0でスルーします。初期値は0です。 */
		private int AllowedIssuanceDuration;
		/** IssuedAtを許容する期間です。0でスルーします。初期値は0です。 */
		public int allowedIssuanceDuration() { return this.AllowedIssuanceDuration; }
		/** IssuedAtを許容する期間です。0でスルーします。初期値は0です。 */
		public void allowedIssuanceDuration(int AllowedIssuanceDuration) { this.AllowedIssuanceDuration = AllowedIssuanceDuration; }

		/** TokenEndpointとかへの接続でProxyを使用するかどうかを表現します。初期値はfalseです。 */
		private boolean UseProxy;
		/** TokenEndpointとかへの接続でProxyを使用するかどうかを表現します。初期値はfalseです。 */
		public boolean useProxy() { return this.UseProxy; }
		/** TokenEndpointとかへの接続でProxyを使用するかどうかを表現します。初期値はfalseです。 */
		public void useProxy(boolean UseProxy) { this.UseProxy = UseProxy; }
		/** TokenEndpointとかへの接続でProxyを使用する場合のホスト名です。初期値はnullです。nullでデフォルトProxyを探しに行きます。 */
		private String ProxyHost;
		/** TokenEndpointとかへの接続でProxyを使用する場合のホスト名です。初期値はnullです。nullでデフォルトProxyを探しに行きます。 */
		public String proxyHost() { return this.ProxyHost; }
		/** TokenEndpointとかへの接続でProxyを使用する場合のホスト名です。初期値はnullです。nullでデフォルトProxyを探しに行きます。 */
		public void proxyHost(String ProxyHost) { this.ProxyHost = ProxyHost; }
		/** TokenEndpointとかへの接続でProxyを使用する場合のポートです。初期値は80です。 */
		private int ProxyPort;
		/** TokenEndpointとかへの接続でProxyを使用する場合のポートです。初期値は80です。 */
		public int proxyPort() { return this.ProxyPort; }
		/** TokenEndpointとかへの接続でProxyを使用する場合のポートです。初期値は80です。 */
		public void proxyPort(int ProxyPort) { this.ProxyPort = ProxyPort; }
		/** TokenEndpointとかへの接続で接続を待機する秒数です。初期値は3です。 */
		private int ConnectTimeout;
		/** TokenEndpointとかへの接続で接続を待機する秒数です。初期値は3です。 */
		public int connectTimeout() { return this.ConnectTimeout; }
		/** TokenEndpointとかへの接続で接続を待機する秒数です。初期値は3です。 */
		public void connectTimeout(int ConnectTimeout) { this.ConnectTimeout = ConnectTimeout; }
		/** TokenEndpointとかへの接続で読み込みを待機する秒数です（実際にはConnectTimeoutと合計されてリクエストタイムアウトとして扱われます）。初期値は5です。 */
		private int ReadTimeout;
		/** TokenEndpointとかへの接続で読み込みを待機する秒数です（実際にはConnectTimeoutと合計されてリクエストタイムアウトとして扱われます）。初期値は5です。 */
		public int readTimeout() { return this.ReadTimeout; }
		/** TokenEndpointとかへの接続で読み込みを待機する秒数です（実際にはConnectTimeoutと合計されてリクエストタイムアウトとして扱われます）。初期値は5です。 */
		public void readTimeout(int ReadTimeout) { this.ReadTimeout = ReadTimeout; }
		/** TokenEndpointとかへの接続でスレッドプールを使用するかどうかを表現します。初期値はtrueです。 */
		private boolean UseThreadPool;
		/** TokenEndpointとかへの接続でスレッドプールを使用するかどうかを表現します。初期値はtrueです。 */
		public boolean useThreadPool() { return this.UseThreadPool; }
		/** TokenEndpointとかへの接続でスレッドプールを使用するかどうかを表現します。初期値はtrueです。 */
		public void useThreadPool(boolean UseThreadPool) { this.UseThreadPool = UseThreadPool; }

		/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
		private String AuthenticatedURLPath;
		/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
		public String getAuthenticatedURLPath() { return this.AuthenticatedURLPath; }
		/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
		public void setAuthenticatedURLPath(String AuthenticatedURLPath) { this.AuthenticatedURLPath = AuthenticatedURLPath; }
		/** 『/』で始まる、認証をしないURLパスです。 */
		private String[] IgnoreAuthenticationURLPaths;
		/** 『/』で始まる、認証をしないURLパスです。 */
		public String[] getIgnoreAuthenticationURLPaths() { return this.IgnoreAuthenticationURLPaths; }
		/** 『/』で始まる、認証をしないURLパスです。 */
		public void setIgnoreAuthenticationURLPaths(String[] IgnoreAuthenticationURLPaths) { this.IgnoreAuthenticationURLPaths = IgnoreAuthenticationURLPaths; }
		/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
		private Pattern IgnoreAuthenticationURLPathRegex;
		/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
		public Pattern getIgnoreAuthenticationURLPathRegex() { return this.IgnoreAuthenticationURLPathRegex; }
		/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
		public void setIgnoreAuthenticationURLPathRegex(Pattern IgnoreAuthenticationURLPathRegex) { this.IgnoreAuthenticationURLPathRegex = IgnoreAuthenticationURLPathRegex; }
		/** handleMechanismNotSelectedをHttpMessageContext#isProtectedがtrueの時だけ呼ぶかどうかです。初期値はtrueです。 */
		private boolean CreateAuthorizationRequestOnlyWhenProtected;
		/** handleMechanismNotSelectedをHttpMessageContext#isProtectedがtrueの時だけ呼ぶかどうかです。初期値はtrueです。 */
		public boolean getCreateAuthorizationRequestOnlyWhenProtected() { return this.CreateAuthorizationRequestOnlyWhenProtected; }
		/** handleMechanismNotSelectedをHttpMessageContext#isProtectedがtrueの時だけ呼ぶかどうかです。初期値はtrueです。 */
		public void setCreateAuthorizationRequestOnlyWhenProtected(boolean CreateAuthorizationRequestOnlyWhenProtected) { this.CreateAuthorizationRequestOnlyWhenProtected = CreateAuthorizationRequestOnlyWhenProtected; }

		public static final String DEFAULT_response_type = "code";
		public static final String DEFAULT_response_mode = "query";
		public static final String DEFAULT_scope = "openid";
		public static final String DEFAULT_ClientAuthenticaitonMethod = "client_secret_post";
		public static final boolean DEFAULT_UseSecureCookie = true;
		public static final String DEFAULT_scopeCookieName = "scope";
		public static final String DEFAULT_redirect_uriCookieName = "redirect_uri";
		public static final String DEFAULT_stateCookieName = "state";
		public static final String DEFAULT_nonceCookieName = "nonce";
		public static final String DEFAULT_request_pathCookieName = "request_path";
		public static final String DEFAULT_form_postParameterCookiePrefixName = "form_post_";
		public static final int DEFAULT_AllowedIssuanceDuration = 0;
		public static final boolean DEFAULT_UseProxy = false;
		public static final int DEFAULT_ProxyPort = 80;
		public static final int DEFAULT_ConnectTimeout = 3;
		public static final int DEFAULT_ReadTimeout = 5;
		public static final boolean DEFAULT_UseThreadPool = true;
		public static final boolean DEFAULT_CreateAuthorizationRequestOnlyWhenProtected = true;

		/** コンストラクタ。 */
		@Inject
		public Settings(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Issuer") String Issuer,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.AuthorizationEndpoint") String AuthorizationEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.TokenEndpoint", defaultValue="") String TokenEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.RevocationEndpoint", defaultValue="") String RevocationEndpoint,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.response_type", defaultValue="") String response_type,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.response_mode", defaultValue="") String response_mode,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.scope", defaultValue="") String scope,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.client_id") String client_id,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.ClientAuthenticaitonMethod", defaultValue="") String ClientAuthenticaitonMethod,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.client_secret", defaultValue="") String client_secret,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.UseSecureCookie", defaultValue="") String UseSecureCookie,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.TokenCookieMaxAge", defaultValue="") String TokenCookieMaxAge,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.scopeCookieName", defaultValue="") String scopeCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.redirect_uriCookieName", defaultValue="") String redirect_uriCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.stateCookieName", defaultValue="") String stateCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.nonceCookieName", defaultValue="") String nonceCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.request_pathCookieName", defaultValue="") String request_pathCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.form_postParameterCookiePrefixName", defaultValue="") String form_postParameterCookiePrefixName,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.AllowedIssuanceDuration", defaultValue="") String AllowedIssuanceDuration,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.UseProxy", defaultValue="") String UseProxy,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.ProxyHost", defaultValue="") String ProxyHost,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.ProxyPort", defaultValue="") String ProxyPort,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.ConnectTimeout", defaultValue="") String ConnectTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.ReadTimeout", defaultValue="") String ReadTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.UseThreadPool", defaultValue="") String UseThreadPool,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.AuthenticatedURLPath") String AuthenticatedURLPath,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPaths", defaultValue="") String IgnoreAuthenticationURLPaths,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPathRegex", defaultValue="") String IgnoreAuthenticationURLPathRegex,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.CreateAuthorizationRequestOnlyWhenProtected", defaultValue="") String CreateAuthorizationRequestOnlyWhenProtected
		) {
			this.Issuer = ((Issuer != null) && (Issuer.isEmpty() == false)) ? Issuer : null;
			this.AuthorizationEndpoint = ((AuthorizationEndpoint != null) && (AuthorizationEndpoint.isEmpty() == false)) ? AuthorizationEndpoint : null;
			this.TokenEndpoint = ((TokenEndpoint != null) && (TokenEndpoint.isEmpty() == false)) ?  URI.create(TokenEndpoint) : null;
			this.RevocationEndpoint = ((RevocationEndpoint != null) && (RevocationEndpoint.isEmpty() == false)) ? URI.create(RevocationEndpoint) : null;
			this.response_type = ((response_type != null) && (response_type.isEmpty() == false)) ? response_type : DEFAULT_response_type;
			this.response_mode = ((response_mode != null) && (response_mode.isEmpty() == false)) ? response_mode : DEFAULT_response_mode;
			this.scope = ((scope != null) && (scope.isEmpty() == false)) ? scope : DEFAULT_scope;
			this.client_id = ((client_id != null) && (client_id.isEmpty() == false)) ? client_id : null;
			this.ClientAuthenticaitonMethod = ((ClientAuthenticaitonMethod != null) && (ClientAuthenticaitonMethod.isEmpty() == false)) ? ClientAuthenticaitonMethod : DEFAULT_ClientAuthenticaitonMethod;
			this.client_secret = ((client_secret != null) && (client_secret.isEmpty() == false)) ? client_secret : null;
			this.UseSecureCookie = ((UseSecureCookie != null) && (UseSecureCookie.isEmpty() == false)) ? Boolean.parseBoolean(UseSecureCookie) : DEFAULT_UseSecureCookie;
			this.TokenCookieMaxAge = ((TokenCookieMaxAge != null) && (TokenCookieMaxAge.isEmpty() == false)) ? Integer.parseInt(TokenCookieMaxAge) : OpenIDConnectAuthenticationMechanism.class.getDeclaredAnnotation(RememberMe.class).cookieMaxAgeSeconds();
			this.scopeCookieName = ((scopeCookieName != null) && (scopeCookieName.isEmpty() == false)) ? scopeCookieName : DEFAULT_scopeCookieName;
			this.redirect_uriCookieName = ((redirect_uriCookieName != null) && (redirect_uriCookieName.isEmpty() == false)) ? redirect_uriCookieName : DEFAULT_redirect_uriCookieName;
			this.stateCookieName = ((stateCookieName != null) && (stateCookieName.isEmpty() == false)) ? stateCookieName : DEFAULT_stateCookieName;
			this.nonceCookieName = ((nonceCookieName != null) && (nonceCookieName.isEmpty() == false)) ? nonceCookieName : DEFAULT_nonceCookieName;
			this.request_pathCookieName = ((request_pathCookieName != null) && (request_pathCookieName.isEmpty() == false)) ? request_pathCookieName : DEFAULT_request_pathCookieName;
			this.form_postParameterCookiePrefixName = ((form_postParameterCookiePrefixName != null) && (form_postParameterCookiePrefixName.isEmpty() == false)) ? form_postParameterCookiePrefixName : DEFAULT_form_postParameterCookiePrefixName;
			this.AllowedIssuanceDuration = ((AllowedIssuanceDuration != null) && (AllowedIssuanceDuration.isEmpty() == false)) ? Integer.parseInt(AllowedIssuanceDuration) : DEFAULT_AllowedIssuanceDuration;
			this.UseProxy = ((UseProxy != null) && (UseProxy.isEmpty() == false)) ? Boolean.parseBoolean(UseProxy) : DEFAULT_UseProxy;
			this.ProxyHost = ((ProxyHost != null) && (ProxyHost.isEmpty() == false)) ? ProxyHost : null;
			this.ProxyPort = ((ProxyPort != null) && (ProxyPort.isEmpty() == false)) ? Integer.parseInt(ProxyPort) : DEFAULT_ProxyPort;
			this.ConnectTimeout = ((ConnectTimeout != null) && (ConnectTimeout.isEmpty() == false)) ? Integer.parseInt(ConnectTimeout) : DEFAULT_ConnectTimeout;
			this.ReadTimeout = ((ReadTimeout != null) && (ReadTimeout.isEmpty() == false)) ? Integer.parseInt(ReadTimeout) : DEFAULT_ReadTimeout;
			this.UseThreadPool = ((UseThreadPool != null) && (UseThreadPool.isEmpty() == false)) ? Boolean.parseBoolean(UseThreadPool) : DEFAULT_UseThreadPool;
			this.AuthenticatedURLPath = ((AuthenticatedURLPath != null) && (AuthenticatedURLPath.isEmpty() == false)) ? AuthenticatedURLPath : null;
			this.IgnoreAuthenticationURLPaths = ((IgnoreAuthenticationURLPaths != null) && (IgnoreAuthenticationURLPaths.isEmpty() == false)) ? IgnoreAuthenticationURLPaths.split("\\s*,\\s*") : null;
			this.IgnoreAuthenticationURLPathRegex = ((IgnoreAuthenticationURLPathRegex != null) && (IgnoreAuthenticationURLPathRegex.isEmpty() == false)) ? Pattern.compile(IgnoreAuthenticationURLPathRegex) : null;
			this.CreateAuthorizationRequestOnlyWhenProtected = ((CreateAuthorizationRequestOnlyWhenProtected != null) && (CreateAuthorizationRequestOnlyWhenProtected.isEmpty() == false)) ? Boolean.parseBoolean(CreateAuthorizationRequestOnlyWhenProtected) : DEFAULT_CreateAuthorizationRequestOnlyWhenProtected;
		}

	}

	/**
	 * リクエストされたパスを、認証後にリダイレクトするために記憶します。
	 * 基本、HttpAuthenticationMechanism#validateRequest(HttpServletRequest, HttpServletResponse, HttpMessageContext)の後に、
	 * RememberMeWithRedirectInterceptorによって、SEND_CONTINUEの時に呼び出されます。
	 */
	@Override
	public void memorizeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		IOpenIDConnectAuthenticationMechanism.super.memorizeRequestPath(request, response, httpMessageContext);
	}

	/**
	 * 記憶してある認証後にリダイレクトするパスを返します。ない場合はnullを返します。
	 * 初期実装は、Cookieです。
	 */
	@Override
	public String getRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		String request_path = IOpenIDConnectAuthenticationMechanism.super.getRequestPath(request, response, httpMessageContext);
		return request_path;
	}

	/**
	 * 記憶してある認証後にリダイレクトするパスを破棄します。
	 * 初期実装は、Cookieです。
	 */
	@Override
	public void removeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		IOpenIDConnectAuthenticationMechanism.super.removeRequestPath(request, response, httpMessageContext);
	}

}
