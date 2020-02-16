package jp.empressia.enterprise.security.oidc;

import java.util.Collection;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.authentication.mechanism.http.RememberMe;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

/**
 * 複数のOpenID Connectのサービスを扱うMechanismです。
 * @author すふぃあ
 */
@ApplicationScoped
@Alternative
@RememberMe(cookieSecureOnlyExpression="#{self.useSecureCookie()}", cookieMaxAgeSecondsExpression="#{self.getTokenCookieMaxAge()}")
public class MultipleIssuersOpenIDConnectAuthenticationMechanism implements IOpenIDConnectAuthenticationMechanism {

	/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
	private boolean useSecureCookie;
	/** トークンとかを保存するクッキーにSecure属性を付けるかどうかです。初期値はtrueです。 */
	@Override
	public boolean useSecureCookie() { return this.useSecureCookie; }

	/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
	private int TokenCookieMaxAge;
	/** クッキーでトークンを保存する期間（秒）です。初期値はRememberMe#cookieMaxAgeSeconds()です。 */
	public int getTokenCookieMaxAge() { return this.TokenCookieMaxAge; }

	/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。 */
	private String request_pathCookieName;
	/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。 */
	@Override
	public String request_pathCookieName() { return this.request_pathCookieName; }

	/** 『/』で始まる、認証をしないURLパスです。 */
	private String[] IgnoreAuthenticationURLPaths;
	/** 『/』で始まる、認証をしないURLパスです。 */
	public String[] getIgnoreAuthenticationURLPaths() { return this.IgnoreAuthenticationURLPaths; }

	/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
	private Pattern IgnoreAuthenticationURLPathRegex;
	/** 『/』で始まる、認証をしないURLパスの正規表現です。 */
	public Pattern getIgnoreAuthenticationURLPathRegex() { return this.IgnoreAuthenticationURLPathRegex; }

	/** コンストラクタ内でしか呼び出されませんが、念のため保持しています。 */
	private OpenIDConnectAuthenticationMechanismSupplier MechanismSupplier;

	/** 認証（validateRequest）を必要とするリクエストから、どのIssuerに任せるかを選択します。 */
	private OpenIDConnectAuthenticationMechanismSelectable MechanismSelector;
	/**
	 * 認証（validateRequest）を必要とするリクエストから、どのMechanismに任せるかを選択します。
	 * 初期実装では、以下の順で探索します。
	 * 1. 移譲先のURLが呼び出されている（Mechanismの一覧からgetAuthenticatedURLを確認します）。
	 * 2. リクエストから移譲先を特定する（コンストラクタで指定された、OpenIDConnectAuthenticationMechanismSelectableを呼び出します）。
	 * 3. トークンから移譲先を特定する。
	 * 特定できなかった場合はnullを返します。
	 */
	protected IOpenIDConnectAuthenticationMechanism selectMechanism(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		IOpenIDConnectAuthenticationMechanism mechanism = null;
		if(mechanism == null) {
			String requestURI = request.getRequestURI();
			var entry = this.Mechanisms.entrySet().stream().filter(m -> requestURI.equals(m.getValue().getAuthenticatedURLPath())).findFirst().orElse(null);
			mechanism = (entry != null) ? entry.getValue() : null;
		}
		if(mechanism == null) {
			String issuer = this.MechanismSelector.select(request, response, httpMessageContext);
			mechanism = this.getMechanisms().get(issuer);
		}
		if(mechanism == null) {
			Cookie tokenCookie = IOpenIDConnectAuthenticationMechanism.extractCookie(this.TokenCookieName, request);
			if(tokenCookie != null) {
				OpenIDConnectCredential credential = this.IdentityStore.findCredential(tokenCookie.getValue());
				if(credential != null) {
					String issuer = credential.getIssuer();
					mechanism = this.getMechanisms().get(issuer);
				}
			}
		}
		return mechanism;
	}

	/** 認証するIssuerが特定できなかった場合に呼び出されるHandler。 */
	private IssuerNotSelectedHandler IssuerNotSelectedHandler;
	/**
	 * 認証するIssuerが特定できなかった場合に呼び出されます。
	 * Issuerをユーザーが選択するための、redirect、page、JSONデータとかを提供するためのメソッドです。
	 * 基本は、responseに対して、redirectを設定してSEND_CONNTINUEを返してください。
	 * 初期実装では、コンストラクタで指定されたIssuerNotSelectedHandlerを呼び出します。
	 */
	protected AuthenticationStatus handleIssuerNotSelected(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		return this.IssuerNotSelectedHandler.handle(request, response, httpMessageContext);
	}

	/** Issuerをキーとする移譲先のIOpenIDConnectAuthenticationMechanismです。 */
	private Map<String, IOpenIDConnectAuthenticationMechanism> Mechanisms;
	/**
	 * Issuerをキーとする移譲先のIOpenIDConnectAuthenticationMechanismです。
	 * 初期実装では、コンストラクタで指定された、
	 * OpenIDConnectAuthenticationMechanismSupplierが提供するIOpenIDConnectAuthenticationMechanismの一覧を返します。
	 */
	protected Map<String, IOpenIDConnectAuthenticationMechanism> getMechanisms() {
		return this.Mechanisms;
	}

	/** トークンからCredentialを得ることでMechanismを選択するために使うIdentityStoreです。 */
	private IOpenIDConnectIdentityStore IdentityStore;

	/** トークンに使用するクッキーの名前です。 */
	private String TokenCookieName;

	/**
	 * コンストラクタ。
	 * CDI経由で呼び出すには、各引数の対象がCDIの対象になっている必要があります。
	 * 継承して使用する場合は、各引数に対応するメソッドをオーバーライドしていれば、引数をnullにしても平気です。
	 */
	@Inject
	public MultipleIssuersOpenIDConnectAuthenticationMechanism(Settings settings, OpenIDConnectAuthenticationMechanismSupplier MechanismSupplier, OpenIDConnectAuthenticationMechanismSelectable MechanismSelector, IssuerNotSelectedHandler IssuerNotSelectedHandler, IOpenIDConnectIdentityStore IdentityStore) {
		this.MechanismSupplier = MechanismSupplier;
		this.MechanismSelector = MechanismSelector;
		this.IssuerNotSelectedHandler = IssuerNotSelectedHandler;
		this.useSecureCookie = settings.useSecureCookie();
		this.TokenCookieMaxAge = settings.getTokenCookieMaxAge();
		this.request_pathCookieName = settings.request_pathCookieName();
		this.IgnoreAuthenticationURLPaths = settings.getIgnoreAuthenticationURLPaths();
		this.IgnoreAuthenticationURLPathRegex = settings.getIgnoreAuthenticationURLPathRegex();
		this.IdentityStore = IdentityStore;
		this.TokenCookieName = this.getClass().getAnnotation(RememberMe.class).cookieName();
		if(this.MechanismSupplier != null) {
			this.Mechanisms = this.MechanismSupplier.mechanisms(useSecureCookie).stream().collect(Collectors.toMap(m -> m.getIssuer(), m -> m));
		}
	}

	/** 使用するIOpenIDConnectAuthenticationMechanismを示します。 */
	@FunctionalInterface
	public static interface OpenIDConnectAuthenticationMechanismSupplier {
		public Collection<IOpenIDConnectAuthenticationMechanism> mechanisms(boolean useSecureCookie);
	}

	/** 認証（validateRequest）を必要とするリクエストから、どのIssuerに任せるかを選択します。 */
	@FunctionalInterface
	public static interface OpenIDConnectAuthenticationMechanismSelectable {
		public String select(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext);
	}

	/** 認証するIssuerが特定できなかった場合に呼び出されるHandlerのインターフェース。 */
	@FunctionalInterface
	public static interface IssuerNotSelectedHandler {
		public AuthenticationStatus handle(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext);
	}

	/** Issuer。特定のIssuerを持たないのでnullを返します。 */
	@Override
	public String getIssuer() { return null; }
	/** 『/』で始まる、認証を完了して認証サーバーからリダイレクトされてきた時のURLパスです。『/』より手前は自動で設定されます。初期値はnullです。 */
	@Override
	public String getAuthenticatedURLPath() { return null; }

	/**
	 * RememberMeのキャッシュ確認で回収しきれなかった（クッキーがないとかの）場合に、
	 * Java EE Security API（Jakarta Security）から呼び出されます。
	 * 対象となるMechanismに処理を委譲します。
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
		IOpenIDConnectAuthenticationMechanism mechanism = this.selectMechanism(request, response, httpMessageContext);
		AuthenticationStatus result;
		if(mechanism != null) {
			result = mechanism.validateRequest(request, response, httpMessageContext);
		} else {
			result = this.handleIssuerNotSelected(request, response, httpMessageContext);
		}
		return result;
	}

	/**
	 * IDトークンの文字列を解析して署名を確認します。
	 * @param credential リフレッシュされた場合に、以前のCredentialが指定されます。
	 */
	@Override
	public Jws<Claims> parseIDToken(String id_tokenString, OpenIDConnectCredential credential) {
		String issuer = credential.getIssuer();
		IOpenIDConnectAuthenticationMechanism mechanism = this.getMechanisms().get(issuer);
		return mechanism.parseIDToken(id_tokenString, credential);
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
	public void validateIDToken(Jws<Claims> id_token, String requestedNonce, OpenIDConnectCredential credential) {
		String issuer = credential.getIssuer();
		IOpenIDConnectAuthenticationMechanism mechanism = this.getMechanisms().get(issuer);
		mechanism.validateIDToken(id_token, requestedNonce, credential);
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
		String issuer = credential.getIssuer();
		IOpenIDConnectAuthenticationMechanism mechanism = this.getMechanisms().get(issuer);
		mechanism.validateAccessToken(access_token, token_type, id_token, requestedScope, requestedNonce, credential);
	}

	/**
	 * トークンをリフレッシュします。
	 * @param refresh_token
	 * @param credential リフレッシュする場合に、以前のCredentialが指定されます。
	 * @return
	 */
	@Override
	public TokenResponse refreshToken(String refresh_token, OpenIDConnectCredential credential) {
		String issuer = credential.getIssuer();
		IOpenIDConnectAuthenticationMechanism mechanism = this.getMechanisms().get(issuer);
		return mechanism.refreshToken(refresh_token, credential);
	}

	/**
	 * トークンを失効させます。
	 * 失効した場合はtrue。それ以外はfalseを返します。
	 * @param credential 破棄する場合に、以前のCredentialが指定されます。
	 */
	@Override
	public boolean revokeToken(String token, String token_type_hint, OpenIDConnectCredential credential) {
		String issuer = credential.getIssuer();
		IOpenIDConnectAuthenticationMechanism mechanism = this.getMechanisms().get(issuer);
		return mechanism.revokeToken(token, token_type_hint, credential);
	}

	/**
	 * 設定用のクラス。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	@Typed(Settings.class)
	public static class Settings {

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

		/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はpre_request_pathです。 */
		private String request_pathCookieName;
		/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はpre_request_pathです。 */
		public String request_pathCookieName() { return this.request_pathCookieName; }
		/** このライブラリ専用のrequest_pathを保存するクッキーの名前です。初期値はrequest_pathです。 */
		public void request_pathCookieName(String request_pathCookieName) { this.request_pathCookieName = request_pathCookieName; }

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

		/** このライブラリ専用のrequest_pathを保存するクッキーの名前の初期値です。 */
		public static final String DEFAULT_request_pathCookieName = "pre_request_path";

		/** コンストラクタ。 */
		@Inject
		public Settings(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.UseSecureCookie", defaultValue="") String UseSecureCookie,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.TokenCookieMaxAge", defaultValue="") String TokenCookieMaxAge,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.request_pathCookieName", defaultValue="") String request_pathCookieName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.IgnoreAuthenticationURLPaths", defaultValue="") String IgnoreAuthenticationURLPaths,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.IgnoreAuthenticationURLPathRegex", defaultValue="") String IgnoreAuthenticationURLPathRegex
		) {
			this.UseSecureCookie = ((UseSecureCookie != null) && (UseSecureCookie.isEmpty() == false)) ? Boolean.parseBoolean(UseSecureCookie) : OpenIDConnectAuthenticationMechanism.Settings.DEFAULT_UseSecureCookie;
			this.TokenCookieMaxAge = ((TokenCookieMaxAge != null) && (TokenCookieMaxAge.isEmpty() == false)) ? Integer.parseInt(TokenCookieMaxAge) : MultipleIssuersOpenIDConnectAuthenticationMechanism.class.getDeclaredAnnotation(RememberMe.class).cookieMaxAgeSeconds();
			this.request_pathCookieName = ((request_pathCookieName != null) && (request_pathCookieName.isEmpty() == false)) ? request_pathCookieName : Settings.DEFAULT_request_pathCookieName;
			this.IgnoreAuthenticationURLPaths = ((IgnoreAuthenticationURLPaths != null) && (IgnoreAuthenticationURLPaths.isEmpty() == false)) ? IgnoreAuthenticationURLPaths.split("\\s*,\\s*") : null;
			this.IgnoreAuthenticationURLPathRegex = ((IgnoreAuthenticationURLPathRegex != null) && (IgnoreAuthenticationURLPathRegex.isEmpty() == false)) ? Pattern.compile(IgnoreAuthenticationURLPathRegex) : null;
		}

	}

	/**
	 * IssuerをQueryStringから確認します。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	public static class RedirectedIssurSelector implements OpenIDConnectAuthenticationMechanismSelectable {

		/** 選択したIssuerを表現するパラメーター名です。初期値はIssuerです。 */
		private String IssuerParameterName;
		/** 選択したIssuerを表現するパラメーター名です。初期値はIssuerです。 */
		public String getIssuerParameterName() { return this.IssuerParameterName; };
		/** 『/』で始まる、Issuerを選択してきた時のURLパスです。 */
		private String IssuerSelectedURLPath;
		/** 『/』で始まる、Issuerを選択してきた時のURLパスです。 */
		public String getIssuerSelectedURLPath() { return this.IssuerSelectedURLPath; };

		/** 選択したIssuerを表現するパラメーター名の初期値です。 */
		public static final String DEFAULT_IssuerParameterName = "Issuer";

		/** コンストラクタ。 */
		@Inject
		public RedirectedIssurSelector(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectedIssurSelector.IssuerParameterName", defaultValue="") String IssuerParameterName,
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectedIssurSelector.IssuerSelectedURLPath") String IssuerSelectedURLPath
		) {
			this.IssuerParameterName = ((IssuerParameterName != null) && (IssuerParameterName.isEmpty() == false)) ? IssuerParameterName : DEFAULT_IssuerParameterName;
			this.IssuerSelectedURLPath = IssuerSelectedURLPath;
		}

		/** IssuerをQueryStringから確認します。 */
		@Override
		public String select(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
			String requestURI = request.getRequestURI();
			String Issuer;
			if(requestURI.equals(this.getIssuerSelectedURLPath())) {
				Issuer = request.getParameter(this.getIssuerParameterName());
			} else {
				Issuer = null;
			}
			return Issuer;
		}

	}

	/**
	 * Issuerを選択してリクエストを投げるPageへのリダイレクトをします。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	public static class RedirectIssuerNotSelectedHandler implements IssuerNotSelectedHandler {

		/** Issuerを選択するためのPageへのパスです。 */
		private String IssuerSelectionPageURLPath;
		/** Issuerを選択するためのPageへのパスです。 */
		public String getIssuerSelectionPageURLPath() { return this.IssuerSelectionPageURLPath; }

		/** コンストラクタ。 */
		@Inject
		public RedirectIssuerNotSelectedHandler(
			@ConfigProperty(name="jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectIssuerNotSelectedHandler.IssuerSelectionPageURLPath") String IssuerSelectionPageURLPath
		) {
			this.IssuerSelectionPageURLPath = IssuerSelectionPageURLPath;
		}

		/** Issuerを選択してリクエストを投げるPageへのリダイレクトをします。 */
		@Override
		public AuthenticationStatus handle(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
			response.setStatus(303);
			response.setHeader("Location", this.getIssuerSelectionPageURLPath());
			return AuthenticationStatus.SEND_CONTINUE;
		}

	}

	/**
	 * リクエストされたパスを、認証後にリダイレクトするために記憶します。
	 * 基本、HttpAuthenticationMechanism#validateRequest(HttpServletRequest, HttpServletResponse, HttpMessageContext)の後に、
	 * RememberMeWithRedirectInterceptorによって、SEND_CONTINUEの時に呼び出されます。
	 */
	@Override
	public void memorizeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		IOpenIDConnectAuthenticationMechanism mechanism = this.selectMechanism(request, response, httpMessageContext);
		if(mechanism != null) {
			String request_path = this.getRequestPath(request, response, httpMessageContext);
			if(request_path == null) {
				String URLBase = request.getRequestURL().substring(0, request.getRequestURL().lastIndexOf(request.getRequestURI()));
				String URLPath = request.getRequestURL().substring(URLBase.length());
				request_path = URLPath;
			}
			Cookie request_pathCookie = IOpenIDConnectAuthenticationMechanism.createCookie(mechanism.request_pathCookieName(), request_path, mechanism.getAuthenticatedURLPath(), this.useSecureCookie());
			response.addCookie(request_pathCookie);
		} else {
			String URLBase = request.getRequestURL().substring(0, request.getRequestURL().lastIndexOf(request.getRequestURI()));
			String URLPath = request.getRequestURL().substring(URLBase.length());
			String request_path = URLPath;
			Cookie request_pathCookie = IOpenIDConnectAuthenticationMechanism.createCookie(this.request_pathCookieName(), request_path, null, this.useSecureCookie());
			response.addCookie(request_pathCookie);
		}
	}

	/**
	 * 記憶してある認証後にリダイレクトするパスを返します。ない場合はnullを返します。
	 * 初期実装は、Cookieです。
	 */
	@Override
	public String getRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		IOpenIDConnectAuthenticationMechanism mechanism = this.selectMechanism(request, response, httpMessageContext);
		String request_path = null;
		if(mechanism != null) {
			request_path = mechanism.getRequestPath(request, response, httpMessageContext);
		}
		if(request_path == null) {
			request_path = IOpenIDConnectAuthenticationMechanism.super.getRequestPath(request, response, httpMessageContext);
		}
		return request_path;
	}

	/**
	 * 記憶してある認証後にリダイレクトするパスを破棄します。
	 * 初期実装は、Cookieです。
	 */
	@Override
	public void removeRequestPath(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		IOpenIDConnectAuthenticationMechanism mechanism = this.selectMechanism(request, response, httpMessageContext);
		if(mechanism != null) {
			mechanism.removeRequestPath(request, response, httpMessageContext);
		}
		IOpenIDConnectAuthenticationMechanism.super.removeRequestPath(request, response, httpMessageContext);
	}

}
