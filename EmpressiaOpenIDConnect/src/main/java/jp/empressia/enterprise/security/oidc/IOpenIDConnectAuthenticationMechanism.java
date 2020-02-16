package jp.empressia.enterprise.security.oidc;

import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * OpenID Connect用のインターフェースです。
 * Storeとかから呼ぶためのメソッドを定義しています。
 */
public interface IOpenIDConnectAuthenticationMechanism extends HttpAuthenticationMechanism, RedirectableAuthenticationMechanism {

	/** Issuer。 */
	public String getIssuer();

	/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
	public boolean useSecureCookie();

	/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
	public String getAuthenticatedURLPath();

	/**
	 * IDトークンの文字列を解析して署名を確認します。
	 * https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-5.2
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	public Jws<Claims> parseIDToken(String id_tokenString, OpenIDConnectCredential credential);

	/**
	 * id_tokenを検証します。
	 * Payload（Claims）を検証します。
	 * audienceは単一のもののみ対応しています。
	 * https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#IDTokenValidation
	 * 問題がある場合は例外が投げられます。
	 * @param requestedNonce 指定がある場合は確認をします。
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	public void validateIDToken(Jws<Claims> id_token, String requestedNonce, OpenIDConnectCredential  credential);

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
	public void validateAccessToken(String access_token, String token_type, Jws<Claims> id_token, String requestedScope, String requestedNonce, OpenIDConnectCredential credential);

	/**
	 * トークンをリフレッシュします。
	 * @param refresh_token
	 * @param credential リフレッシュする場合に、以前のCredentialが指定されます。
	 */
	public TokenResponse refreshToken(String refresh_token, OpenIDConnectCredential credential);

	/**
	 * トークンを失効させます。
	 * 失効した場合はtrue。それ以外はfalseを返します。
	 * @param credential 破棄する場合に、以前のCredentialが指定されます。
	 */
	public boolean revokeToken(String token, String token_type_hint, OpenIDConnectCredential credential);

	/**
	 * Token Response。
	 * @author すふぃあ
	 */
	public static class TokenResponse {
		/** 認可サーバーが発行するアクセストークン（必須）。 */
		private String access_token;
		/** 認可サーバーが発行するアクセストークン（必須）。 */
		public String access_token() { return this.access_token; }
		/** トークンのタイプ（値は大文字・小文字を区別しない）（必須）。 */
		private String token_type;
		/** トークンのタイプ（値は大文字・小文字を区別しない）（必須）。 */
		public String token_type() { return this.token_type; }
		/** アクセストークンの有効期間を表す秒数（ここでは初期値をOpenIDConnectCredential.UNDEFINED_EXPIRES_INとして扱っています）。 */
		private int expires_in = OpenIDConnectCredential.UNDEFINED_EXPIRES_IN;
		/** アクセストークンの有効期間を表す秒数（ここでは初期値をOpenIDConnectCredential.UNDEFINED_EXPIRES_INとして扱っています）。 */
		public int expires_in() { return this.expires_in; }
		/** リフレッシュトークン。 */
		private String refresh_token;
		/** リフレッシュトークン。 */
		public String refresh_token() { return this.refresh_token; }
		/** アクセストークンのスコープ。 */
		private String scope;
		/** アクセストークンのスコープ。 */
		public String scope() { return this.scope; }
		/** 認証セッションに紐づいた ID Token 値（必須）。 */
		private String id_token;
		/** 認証セッションに紐づいた ID Token 値（必須）。 */
		public String id_token() { return this.id_token; }
		/** すべてを指定するコンストラクタ。 */
		public TokenResponse(String access_token, String token_type, int expires_in, String refresh_token, String scope, String id_token) {
			this.access_token = access_token;
			this.token_type = token_type;
			this.expires_in = expires_in;
			this.refresh_token = refresh_token;
			this.scope = scope;
			this.id_token = id_token;
		}
	}

	/** OpenID Connectでの認証に失敗したことを表現します。 */
	@SuppressWarnings("serial")
	public static class NotAuthenticatedException extends RuntimeException {
		/** WWW-Authenticate用のtypeです。OAuthです。 */
		public String getType() { return "OAuth"; }
		/** 対象のリクエストです。 */
		private HttpServletRequest Request;
		/** 対象のリクエストです。 */
		public HttpServletRequest getRequest() { return this.Request; }
		/** 対象のレスポンスです。 */
		private HttpServletResponse Response;
		/** 対象のレスポンスです。 */
		public HttpServletResponse getResponse() { return this.Response; }
		/** コンストラクタ。 */
		public NotAuthenticatedException(HttpServletRequest request, HttpServletResponse response) {
			this.Request = request;
			this.Response = response;
		}
	}

	/**
	 * リクエストされたパスを、認証後にリダイレクトするために記憶します。
	 * 基本、HttpAuthenticationMechanism#validateRequest(HttpServletRequest, HttpServletResponse, HttpMessageContext)の後に、
	 * RememberMeWithRedirectInterceptorによって、SEND_CONTINUEの時に呼び出されます。
	 */
	@Override
	public default void memorizeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		String URLBase = request.getRequestURL().substring(0, request.getRequestURL().lastIndexOf(request.getRequestURI()));
		String URLPath = request.getRequestURL().substring(URLBase.length());
		String request_path = URLPath;
		Cookie request_pathCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.request_pathCookieName(), request_path, this.getAuthenticatedURLPath(), this.useSecureCookie());
		response.addCookie(request_pathCookie);
	}

	/**
	 * 記憶してある認証後にリダイレクトするパスを返します。ない場合はnullを返します。
	 * 初期実装は、Cookieです。
	 */
	@Override
	public default String getRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		Cookie request_pathCookie = IOpenIDConnectAuthenticationMechanism.extractCookie(this.request_pathCookieName(), request);
		String request_path = (request_pathCookie != null) ? request_pathCookie.getValue() : null;
		return request_path;
	}

	/**
	 * 記憶してある認証後にリダイレクトするパスを破棄します。
	 * 初期実装は、Cookieです。
	 */
	@Override
	public default void removeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		Cookie request_pathCookie = IOpenIDConnectAuthenticationMechanism.extractCookie(this.request_pathCookieName(), request);
		if(request_pathCookie == null) { return; }
		Cookie removeCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.request_pathCookieName(), request_pathCookie.getValue(), request_pathCookie.getPath(), this.useSecureCookie());
		removeCookie.setMaxAge(0);
		response.addCookie(removeCookie);
	}

	/** リクエストから指定のクッキーを取得します。なければ、nullです。 */
	public static Cookie extractCookie(String name, HttpServletRequest request) {
		Cookie foundCookie = null;
		{
			Cookie[] cookies = request.getCookies();
			if(cookies != null) {
				for(Cookie cookie : cookies) {
					if(cookie.getName().equals(name)) {
						foundCookie = cookie;
						break;
					}
				}
			}
		}
		return foundCookie;
	}

	/** 認証に必要なクッキーを作ります。 */
	public static Cookie createCookie(String name, String value, String path, boolean useSecureCookie) {
		Cookie cookie = new Cookie(name, value);
		cookie.setSecure(useSecureCookie);
		if(path != null) {
			cookie.setPath(path);
		} else {
			cookie.setPath("/");
		}
		cookie.setHttpOnly(true);
		return cookie;
	}

}
