package jp.empressia.enterprise.security.oidc;

import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * OpenID Connectでリダイレクトをサポートするインターフェースです。
 * RememberMeWithRedirectInterceptorで使用されます。
 */
public interface RedirectableAuthenticationMechanism extends HttpAuthenticationMechanism {

	/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。 */
	public String request_pathCookieName();

	/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。 */
	public String getAuthenticatedURLPath();

	/**
	 * リクエストされたパスを、認証後にリダイレクトするために記憶します。
	 * 基本、HttpAuthenticationMechanism#validateRequest(HttpServletRequest, HttpServletResponse, HttpMessageContext)の後に、
	 * RememberMeWithRedirectInterceptorによって、SEND_CONTINUEの時に呼び出されます。
	 */
	public void memorizeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext);

	/** 記憶してある認証後にリダイレクトするパスを返します。ない場合はnullを返します。 */
	public String getRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext);

	/** 記憶してある認証後にリダイレクトするパスを破棄します。 */
	public void removeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext);

}
