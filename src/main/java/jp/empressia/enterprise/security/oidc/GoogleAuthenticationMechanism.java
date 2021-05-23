package jp.empressia.enterprise.security.oidc;

import java.io.IOException;
import java.net.URI;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
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
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.JacksonDeserializer;

/**
 * Google OpenID Connect用のMechanismです。
 * https://developers.google.com/identity/protocols/OpenIDConnect
 * @author すふぃあ
 */
@ApplicationScoped
@Alternative
public class GoogleAuthenticationMechanism extends OpenIDConnectAuthenticationMechanism {

	/** Google-issued tokens are signed using one of the certificates。 */
	private URI jwks_uri;
	/** Google-issued tokens are signed using one of the certificates。 */
	protected URI jwks_uri() { return this.jwks_uri; }

	/** 公開鍵の取得を支援するインスタンス。 */
	private PublicKeyHelper PublicKeyHelper;

	/** コンストラクタ。 */
	@Inject
	public GoogleAuthenticationMechanism(Settings settings, IdentityStoreHandler IdentityStoreHandler, ExecutorService executorService, PublicKeyHelper PublicKeyHelper) {
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
	 * https://developers.google.com/identity/protocols/OpenIDConnect#validatinganidtoken
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
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
			JwtParser parser = Jwts.parser().deserializeJsonWith(new JacksonDeserializer<Map<String, ?>>(this.ObjectMapper));
			parser = parser.setSigningKey(key);
			jws = parser.parseClaimsJws(id_token);
		}
		return jws;
	}

	/**
	 * Google ID Tokens (known as claims)。
	 * https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	 * @author すふぃあ
	 */
	@SuppressWarnings("unused")
	private static class IDTokenPayload {
		/** The Issuer Identifier for the Issuer of the response. Always https://accounts.google.com or accounts.google.com for Google ID tokens（必須）. */
		public String iss;
		/** Access token hash. */
		public String at_hash;
		/** True if the user's e-mail address has been verified; otherwise false. */
		public String email_verified;
		/** An identifier for the user, unique among all Google accounts and never reused（必須）. */
		public String sub;
		/** The client_id of the authorized presenter. */
		public String azp;
		/** The user's email address. This may not be unique and is not suitable for use as a primary key. Provided only if your scope included the string "email". */
		public String email;
		/** The URL of the user's profile page. */
		public String profile;
		/** The URL of the user's profile picture. */
		public String picture;
		/** The user's full name, in a displayable form. */
		public String name;
		/** Identifies the audience that this ID token is intended for（必須）. */
		public String aud;
		/** The time the ID token was issued, represented in Unix time (integer seconds)（必須）. */
		public long iat;
		/** The time the ID token expires, represented in Unix time (integer seconds)（必須）. */
		public long exp;
		/** The value of the nonce supplied by your app in the authentication request. */
		public String nonce;
		/** The hosted G Suite domain of the user. */
		public String hd;
	}

	/**
	 * 設定用のクラス。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	@Typed(Settings.class)
	public static class Settings extends OpenIDConnectAuthenticationMechanism.Settings {

		/** Google-issued tokens are signed using one of the certificates。 */
		private URI jwks_uri;
		/** Google-issued tokens are signed using one of the certificates。 */
		public URI jwks_uri() { return this.jwks_uri; }
		/** Google-issued tokens are signed using one of the certificates。 */
		public void jwks_uri(URI jwks_uri) { this.jwks_uri = jwks_uri; }

		/** IssuerのGoogle用の初期値です。 */
		public static final String DEFAULT_Issuer = "https://accounts.google.com";
		/** AuthorizationEndpointのGoogle用の初期値です。 */
		public static final String DEFAULT_AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
		/** TokenEndpointのGoogle用の初期値です。 */
		public static final String DEFAULT_TokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";
		/** RevocationEndpointのGoogle用の初期値です。 */
		public static final String DEFAULT_RevocationEndpoint = "https://accounts.google.com/o/oauth2/revoke";
		/** Google-issued tokens are signed using one of the certificatesのGoogle用の初期値です。 */
		public static final URI DEFAULT_jwks_uri = URI.create("https://www.googleapis.com/oauth2/v3/certs");

		/** コンストラクタ。 */
		@Inject
		public Settings(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.Issuer", defaultValue="") String Issuer,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.AuthorizationEndpoint", defaultValue="") String AuthorizationEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.TokenEndpoint", defaultValue="") String TokenEndpoint,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.RevocationEndpoint", defaultValue="") String RevocationEndpoint,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.response_type", defaultValue="") String response_type,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.response_mode", defaultValue="") String response_mode,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.scope", defaultValue="") String scope,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.client_id") String client_id,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.ClientAuthenticaitonMethod", defaultValue="") String ClientAuthenticaitonMethod,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.client_secret") String client_secret,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.UseSecureCookie", defaultValue="") String UseSecureCookie,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.TokenCookieMaxAge", defaultValue="") String TokenCookieMaxAge,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.scopeCookieName", defaultValue="") String scopeCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.redirect_uriCookieName", defaultValue="") String redirect_uriCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.stateCookieName", defaultValue="") String stateCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.nonceCookieName", defaultValue="") String nonceCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.request_pathCookieName", defaultValue="") String request_pathCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.form_postParameterCookiePrefixName", defaultValue="") String form_postParameterCookiePrefixName,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.AllowedIssuanceDuration", defaultValue="") String AllowedIssuanceDuration,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.UseProxy", defaultValue="") String UseProxy,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.ProxyHost", defaultValue="") String ProxyHost,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.ProxyPort", defaultValue="") String ProxyPort,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.ConnectTimeout", defaultValue="") String ConnectTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.ReadTimeout", defaultValue="") String ReadTimeout,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.UseThreadPool", defaultValue="") String UseThreadPool,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.AuthenticatedURLPath") String AuthenticatedURLPath,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPaths", defaultValue="") String IgnoreAuthenticationURLPaths,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPathRegex", defaultValue="") String IgnoreAuthenticationURLPathRegex,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.CreateAuthorizationRequestOnlyWhenProtected", defaultValue="") String CreateAuthorizationRequestOnlyWhenProtected,

			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.Google.jwks_uri", defaultValue="") String jwks_uri
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
			this.jwks_uri = ((jwks_uri != null) && (jwks_uri.isEmpty() == false)) ? URI.create(jwks_uri) : DEFAULT_jwks_uri;
		}

	}

}
