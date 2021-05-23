package jp.empressia.enterprise.security.oidc;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jp.empressia.enterprise.security.oidc.OpenIDConnectAuthenticationMechanism.Settings;
import mockit.Expectations;
import mockit.Mocked;

/**
 * テストです。
 * @author すふぃあ
 */
public class Tests {

	/**
	 * リクエストがisProtectedではない場合、Authentication Requestが作成されない。
	 */
	@Test
	public void authenticationRequestIsNotCreatedIfTheRequestIsNotProtected(
		@Mocked HttpServletRequest request,
		@Mocked HttpMessageContext httpMessageContext
	) {
		Settings settings = createTestSettings();
		OpenIDConnectAuthenticationMechanism mechanism = new TestOpenIDConnectAuthenticationMechanism(settings);
		new Expectations() {{
			request.getRequestURI();
			result = "/test";
			httpMessageContext.isProtected();
			result = false;
		}};
		AuthenticationStatus status = assertDoesNotThrow(() -> 
			mechanism.validateRequest(request, null, httpMessageContext)
		);
		assertAll(
			() -> assertThat(status, is(AuthenticationStatus.NOT_DONE))
		);
	}

	public static class TestOpenIDConnectAuthenticationMechanism extends OpenIDConnectAuthenticationMechanism {
		public TestOpenIDConnectAuthenticationMechanism(Settings settings) {
			super(settings, null, null);
		}
		@Override
		public Jws<Claims> parseIDToken(String id_tokenString, OpenIDConnectCredential credential) {
			return null;
		}
	}

	public static Settings createTestSettings() {
		Settings settings = new Settings(
			"Issuer",
			"AuthorizationEndpoint",
			"TokenEndpoint",
			"RevocationEndpoint",

			"response_type",
			"response_mode",

			"scope",

			"client_id",
			"ClientAuthenticaitonMethod",
			"client_secret",

			"UseSecureCookie",
			"", // TokenCookieMaxAge
			"scopeCookieName",
			"redirect_uriCookieName",
			"stateCookieName",
			"nonceCookieName",
			"request_pathCookieName",
			"form_postParameterCookiePrefixName",

			"", // AllowedIssuanceDuratio

			"UseProxy",
			"ProxyHost",
			"", // ProxyPort
			"", // ConnectTimeout
			"", // ReadTimeout
			"UseThreadPool",

			"AuthenticatedURLPath",
			"IgnoreAuthenticationURLPaths",
			"IgnoreAuthenticationURLPathRegex",
			"" // CreateAuthorizationRequestOnlyWhenProtected
		);
		return settings;
	}

}
