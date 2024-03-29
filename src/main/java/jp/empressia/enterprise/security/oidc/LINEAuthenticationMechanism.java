package jp.empressia.enterprise.security.oidc;

import java.nio.charset.StandardCharsets;
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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;

/**
 * LINE Social API v2.1用のMechanismです。
 * 
 * URLは頻繁に変わるみたい。
 * 
 * 『LINEログインの概要』
 * https://developers.line.biz/ja/docs/line-login/overview/
 * 『ウェブアプリにLINEログインを組み込む』
 * https://developers.line.biz/ja/docs/line-login/integrate-line-login/
 * 
 * https://developers.line.biz/ja/docs/social-api/
 * https://developers.line.biz/ja/docs/line-login/web/integrate-line-login/
 * https://developers.line.biz/ja/reference/social-api/
 */
@ApplicationScoped
@Alternative
public class LINEAuthenticationMechanism extends OpenIDConnectAuthenticationMechanism {

	/** コンストラクタ。 */
	@Inject
	public LINEAuthenticationMechanism(Settings settings, IdentityStoreHandler IdentityStoreHandler, ExecutorService executorService) {
		super(settings, IdentityStoreHandler, executorService);
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
	 * IDトークンの文字列を解析して署名を確認します。
	 * client_secretを使って署名を確認します。
	 * https://developers.line.biz/ja/docs/line-login/integrate-line-login/#署名
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public Jws<Claims> parseIDToken(String id_tokenString, OpenIDConnectCredential credential) {
		Jws<Claims> id_token;
		{
			JwtParser parser = Jwts.parserBuilder()
				.deserializeJsonWith(new JacksonDeserializer<Map<String, ?>>(this.ObjectMapper))
				.setSigningKey(this.client_secret().getBytes(StandardCharsets.UTF_8))
				.build();
			id_token = parser.parseClaimsJws(id_tokenString);
		}
		return id_token;
	}

	/**
	 * id_tokenのpayload。
	 * https://developers.line.biz/ja/docs/line-login/integrate-line-login/#id-tokens
	 * @author すふぃあ
	 */
	@SuppressWarnings("unused")
	private static class IDTokenPayload {
		/** https://access.line.me 。IDトークンの生成URLです。 */
		public String iss;
		/** IDトークンの対象ユーザーID。 */
		public String sub;
		/** チャネルID。 */
		public String aud;
		/** トークンの有効期限。UNIXタイムです。 */
		public long exp;
		/** IDトークンの生成時間。UNIXタイムです。 */
		public long iat;
		/** ユーザー認証時間。UNIXタイムです。認可リクエストに max_age の値を指定しなかった場合は含まれません。 */
		public long auth_time;
		/** 認可URLに指定した nonce の値。認可リクエストに nonce の値を指定しなかった場合は含まれません。 */
		public String nonce;
		/** ユーザーが使用した認証方法のリスト。 */
		public String[] amr;
		/** ユーザーの表示名。認可リクエストに profile スコープを指定しなかった場合は含まれません。 */
		public String name;
		/** ユーザープロフィールの画像URL。認可リクエストに profile スコープを指定しなかった場合は含まれません。 */
		public String picture;
		/** ユーザーのメールアドレス。認可リクエストに email スコープを指定しなかった場合は含まれません。 */
		public String email;
	}

	/**
	 * 設定用のクラス。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	@Typed(Settings.class)
	public static class Settings extends OpenIDConnectAuthenticationMechanism.Settings {

		/** IssuerのLINE用の初期値です。 */
		public static final String DEFAULT_Issuer = "https://access.line.me";
		/** AuthorizationEndpointのLINE用の初期値です。 */
		public static final String DEFAULT_AuthorizationEndpoint = "https://access.line.me/oauth2/v2.1/authorize";
		/** TokenEndpointのLINE用の初期値です。 */
		public static final String DEFAULT_TokenEndpoint = "https://api.line.me/oauth2/v2.1/token";
		/** RevocationEndpointのLINE用の初期値です。 */
		public static final String DEFAULT_RevocationEndpoint = "https://api.line.me/oauth2/v2.1/revoke";

		/** コンストラクタ。 */
		@Inject
		public Settings(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.Issuer", defaultValue="") Optional<String> Issuer,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.AuthorizationEndpoint", defaultValue="") Optional<String> AuthorizationEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.TokenEndpoint", defaultValue="") Optional<String> TokenEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.RevocationEndpoint", defaultValue="") Optional<String> RevocationEndpoint,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.response_type", defaultValue="") Optional<String> response_type,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.response_mode", defaultValue="") Optional<String> response_mode,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.scope", defaultValue="") Optional<String> scope,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.client_id") Optional<String> client_id,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.ClientAuthenticaitonMethod", defaultValue="") Optional<String> ClientAuthenticaitonMethod,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.client_secret") Optional<String> client_secret,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.UseSecureCookie", defaultValue="") Optional<String> UseSecureCookie,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.TokenCookieMaxAge", defaultValue="") Optional<String> TokenCookieMaxAge,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.scopeCookieName", defaultValue="") Optional<String> scopeCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.redirect_uriCookieName", defaultValue="") Optional<String> redirect_uriCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.stateCookieName", defaultValue="") Optional<String> stateCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.nonceCookieName", defaultValue="") Optional<String> nonceCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.request_pathCookieName", defaultValue="") Optional<String> request_pathCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.form_postParameterCookiePrefixName", defaultValue="") Optional<String> form_postParameterCookiePrefixName,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.AllowedIssuanceDuration", defaultValue="") Optional<String> AllowedIssuanceDuration,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.UseProxy", defaultValue="") Optional<String> UseProxy,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.ProxyHost", defaultValue="") Optional<String> ProxyHost,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.ProxyPort", defaultValue="") Optional<String> ProxyPort,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.ConnectTimeout", defaultValue="") Optional<String> ConnectTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.ReadTimeout", defaultValue="") Optional<String> ReadTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.UseThreadPool", defaultValue="") Optional<String> UseThreadPool,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.LINE.AuthenticatedURLPath") Optional<String> AuthenticatedURLPath,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPaths", defaultValue="") Optional<String> IgnoreAuthenticationURLPaths,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPathRegex", defaultValue="") Optional<String> IgnoreAuthenticationURLPathRegex,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.CreateAuthorizationRequestOnlyWhenProtected", defaultValue="") Optional<String> CreateAuthorizationRequestOnlyWhenProtected
		) {
			this(
				((Issuer != null) && (Issuer.isEmpty() == false)) ? Issuer.get() : null,
				((AuthorizationEndpoint != null) && (AuthorizationEndpoint.isEmpty() == false)) ? AuthorizationEndpoint.get() : null,
				((TokenEndpoint != null) && (TokenEndpoint.isEmpty() == false)) ?  TokenEndpoint.get() : null,
				((RevocationEndpoint != null) && (RevocationEndpoint.isEmpty() == false)) ? RevocationEndpoint.get() : null,
				((response_type != null) && (response_type.isEmpty() == false)) ? response_type.get() : null,
				((response_mode != null) && (response_mode.isEmpty() == false)) ? response_mode.get() : null,
				((scope != null) && (scope.isEmpty() == false)) ? scope.get() : null,
				client_id.get(),
				((ClientAuthenticaitonMethod != null) && (ClientAuthenticaitonMethod.isEmpty() == false)) ? ClientAuthenticaitonMethod.get() : null,
				client_secret.get(),
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
				((CreateAuthorizationRequestOnlyWhenProtected != null) && (CreateAuthorizationRequestOnlyWhenProtected.isEmpty() == false)) ? CreateAuthorizationRequestOnlyWhenProtected.get() : null
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
			String CreateAuthorizationRequestOnlyWhenProtected
		) {
			super(
				((Issuer != null) && (Issuer.isEmpty() == false)) ? Issuer : DEFAULT_Issuer,
				((AuthorizationEndpoint != null) && (AuthorizationEndpoint.isEmpty() == false)) ? AuthorizationEndpoint : DEFAULT_AuthorizationEndpoint,
				((TokenEndpoint != null) && (TokenEndpoint.isEmpty() == false)) ?  TokenEndpoint : DEFAULT_TokenEndpoint,
				((RevocationEndpoint != null) && (RevocationEndpoint.isEmpty() == false)) ? RevocationEndpoint : DEFAULT_RevocationEndpoint,
				response_type, response_mode,
				scope,
				client_id, ClientAuthenticaitonMethod, client_secret,
				UseSecureCookie, TokenCookieMaxAge, scopeCookieName, redirect_uriCookieName, stateCookieName, nonceCookieName, request_pathCookieName, form_postParameterCookiePrefixName,
				AllowedIssuanceDuration,
				UseProxy, ProxyHost, ProxyPort, ConnectTimeout, ReadTimeout, UseThreadPool,
				AuthenticatedURLPath, IgnoreAuthenticationURLPaths, IgnoreAuthenticationURLPathRegex, CreateAuthorizationRequestOnlyWhenProtected
			);
		}

	}

}
