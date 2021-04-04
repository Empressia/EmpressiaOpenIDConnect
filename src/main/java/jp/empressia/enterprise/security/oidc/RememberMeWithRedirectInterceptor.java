package jp.empressia.enterprise.security.oidc;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.util.Arrays;

import javax.annotation.Priority;
import javax.interceptor.AroundConstruct;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.authentication.mechanism.http.RememberMe;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authenticate＆RememberMeされた後に、リダイレクトするためのInterceptorです。
 * HttpAuthenticationMechanismのあとに、RememberMeのInterceptorによってクッキーが付与されますが、
 * HttpAuthenticationMechanismの時点でリダイレクトしようとしても、レスポンス結果が宇和が枯れてしまいます。
 * また、HttpAuthenticationMechanismの時点でレスポンスをFlushすると、RememberMeが機能できません。
 * よって、RememberMeのInterceptorの外側で、リダイレクトをFlushします。
 * @author すふぃあ
 */
@Interceptor
@RememberMe
@Priority(Interceptor.Priority.PLATFORM_BEFORE + 210 - 100)
@SuppressWarnings("serial")
public class RememberMeWithRedirectInterceptor implements Serializable {

	/** Interceoptor対象のメソッドです。 */
	private Method TargetInterfaceMethod;

	/** コンストラクタ。 */
	public RememberMeWithRedirectInterceptor() {
		try {
			this.TargetInterfaceMethod = RedirectableAuthenticationMechanism.class.getMethod("validateRequest", HttpServletRequest.class, HttpServletResponse.class, HttpMessageContext.class);
		} catch(NoSuchMethodException | SecurityException ex) {
			String message = "Interceptor構築のためのReflectionに失敗しました。";
			throw new IllegalStateException(message, ex);
		}
	}

	/** リダイレクトするMechanismです。 */
	private RedirectableAuthenticationMechanism Mechanism;

	/** 初期化用メソッドです。 */
	@AroundConstruct
	public void initialize(InvocationContext ctx) throws Exception {
		ctx.proceed();
		Object target = ctx.getTarget();
		if(target instanceof RedirectableAuthenticationMechanism) {
			RedirectableAuthenticationMechanism m = (RedirectableAuthenticationMechanism)target;
			this.Mechanism = m;
		}
	}

	/** 認証成功後にリダイレクトします。 */
	@AroundInvoke
	public Object intercept(InvocationContext ctx) throws Exception {
		Object o = ctx.proceed();
		if(this.Mechanism == null) { return o; }
		String request_pathCookieName = this.Mechanism.request_pathCookieName();
		if(request_pathCookieName == null) { return o; }
		if(((o == AuthenticationStatus.SEND_CONTINUE) || (o == AuthenticationStatus.SUCCESS)) == false) { return o; }
		// ここまでで、できる限り不要な処理はガードする。
		Method m = ctx.getMethod();
		Method targetInterfaceMethod = this.TargetInterfaceMethod;
		if(
			// 一般的な評価順と逆順になっている。ダメ？
			Arrays.equals(m.getParameterTypes(), targetInterfaceMethod.getParameterTypes()) &&
			m.getName().equals(targetInterfaceMethod.getName()) &&
			targetInterfaceMethod.getDeclaringClass().isAssignableFrom(m.getDeclaringClass())
		) {
			AuthenticationStatus r = (AuthenticationStatus)o;
			HttpServletRequest request = (HttpServletRequest)ctx.getParameters()[0];
			HttpServletResponse response = (HttpServletResponse)ctx.getParameters()[1];
			HttpMessageContext httpMessageContext = (HttpMessageContext)ctx.getParameters()[2];
			switch(r) {
				case SEND_CONTINUE: {
					String requestURI = request.getRequestURI();
					if(requestURI.equals(this.Mechanism.getAuthenticatedURLPath()) == false) {
						this.Mechanism.memorizeRequestPath(request, response, httpMessageContext);
					}
					break;
				}
				case SUCCESS: {
					String request_path = this.Mechanism.getRequestPath(request, response, httpMessageContext);
					if(request_path != null) {
						this.Mechanism.removeRequestPath(request, response, httpMessageContext);
						response.setStatus(303);
						response.setHeader("Location", request_path);
						response.flushBuffer();
					}
					break;
				}
				default: { throw new IllegalStateException("ここを通ることはありません。"); }
			}
		}
		return o;
	}

}
