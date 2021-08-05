# Empressia OpenID Connect

* [概要](#概要)
* [使い方](#使い方)
* [複数の実装クラスを同時に扱う方法](#複数の実装クラスを同時に扱う方法)
* [Reverse Proxyの後ろで扱う方法](#Reverse Proxyの後ろで扱う方法)
* [トークンを取得する処理を非同期に変更する方法](#トークンを取得する処理を非同期に変更する方法)
* [ライブラリの依存関係](#ライブラリの依存関係)
* [制限事項](#制限事項)
	* [このライブラリの制限](#このライブラリの制限)
	* [Payara Microでの制限](#Payara%20Microでの制限)
* [サンプル](#サンプル)
* [IOpenIDConnectAuthenticationMechanismの注意事項](#IOpenIDConnectAuthenticationMechanismの注意事項)
* [ライセンス](#ライセンス)

## 概要

Jakarta Security用の、  
OpenID Connectプロトコルを使用した認証をサポートするためのライブラリです。  

## 使い方

実装の[サンプル](#サンプル)があります。  

以下の手順に沿って実装や設定をします。  

1. [ライブラリを追加します。](#ライブラリを追加します。)
1. [OpenIDConnectAuthenticationMechanismを用意します。](#OpenIDConnectAuthenticationMechanismを用意します。)
1. [OpenIDConnectIdentityStoreを用意します。](#OpenIDConnectIdentityStoreを用意します。)
1. [OpenIDConnectRememberMeIdentityStoreを用意します。](#OpenIDConnectRememberMeIdentityStoreを用意します。)
1. [APIを制限します。](#APIを制限します。)
1. [認証しないパスを設定します。](#認証しないパスを設定します。)

### ライブラリを追加します。

Gradleであれば、例えば以下のように設定します。  

```groovy
	// use Empressia OpenID Connect.
	implementation(group:"jp.empressia", name:"jp.empressia.enterprise.security.oidc", version:"1.2.0");
```

使う場合は、関連したライブラリの依存関係も必要になると思います。
例えば、以下のように追加してください。  

```groovy
	// use CDI.
	providedCompile(group:"jakarta.enterprise", name:"jakarta.enterprise.cdi-api", version:"2.0.2");
	// use Java EE Security API.
	providedCompile(group:"jakarta.security.enterprise", name: "jakarta.security.enterprise-api", version:"1.0.2");
	// use HttpServletRequest, HttpServletResponse.
	// providedCompile(group:"jakarta.servlet", name: "jakarta.servlet-api", version:"4.0.2");
	// use for security interceptor priority.
	// providedCompile(group:"jakarta.annotation", name:"jakarta.annotation-api", version:"1.3.5");
	// use MicroProfile Config API.
	// providedCompile(group:"org.eclipse.microprofile.config", name:"microprofile-config-api", version:"2.0");
	// use JCache for security token cache (not in Jave EE 8).
	// providedCompile(group:"javax.cache", name:"cache-api", version:"1.1.1");
	// use for JWT.
	// providedRuntime(group:"io.jsonwebtoken", name:"jjwt-impl", version:"0.11.2");
	// providedCompile(group:"io.jsonwebtoken", name:"jjwt-jackson", version:"0.11.2");
	//  or
	// implementation(group:"io.jsonwebtoken", name:"jjwt-jackson", version:"0.11.2");
```

コメントアウトしてる部分は、依存関係の宣言が必ず必要というわけではないかと思います。  

### OpenIDConnectAuthenticationMechanismを用意します。

基本は、OpenIDConnectAuthenticationMechanismを継承したクラスをCDIに登録することで機能します。  

実装済みのクラスとして、以下のクラスがあります。  

* GoogleAuthenticationMechanism
* LINEAuthenticationMechanism
* MicrosoftAuthenticationMechanism

また、複数の実装クラスを同時に使うために、以下のクラスがあります。  

* MultipleIssuersAuthenticationMechanism

例えば、Microsoft ID プラットフォームを使用する場合は以下のようにします。  

```java
@ApplicationScoped
public class ApplicationAuthenticationMechanism extends MicrosoftAuthenticationMechanism {
	@Inject
	public ApplicationAuthenticationMechanism(Settings settings, IdentityStoreHandler IdentityStoreHandler, PublicKeyHelper PublicKeyHelper) {
		super(settings, IdentityStoreHandler, null, PublicKeyHelper);
	}
}
```

実装済みのMicrosoftAuthenticationMechanismを継承して、
スコープ設定を行いCDIの対象とします。

必要に応じて、コンストラクタインジェクション用のクラスをbeans.xmlに設定します。  

```xml
<beans>
	<alternatives>
		<class>jp.empressia.enterprise.security.oidc.MicrosoftAuthenticationMechanism$Settings</class>
		<class>jp.empressia.enterprise.security.oidc.PublicKeyHelper</class>
	</alternatives>
</beans>
```

自動的に、RememberMeWithRedirectInterceptorが有効になります。  
Java EE Security API（Jakarta Security）の構成上、このライブラリで必要なInterceptorになります。  
普段は気にすることはないと思います。  

継承したMechanism用のSettingsをbeans.xmlで有効にすると、MicroProfile Configによって設定が読み込まれます。  
設定は、『[microprofile-config.properties](EmpressiaOpenIDConnect/src/main/resources/META-INF/microprofile-config.properties)』を参考にして、必要な設定を行ってください。  

例えば、MicrosoftAuthenticationMechanismの場合は、以下の設定が必須となります。  

* client_id
* client_secret
* AuthenticatedURLPath

[このライブラリの制限](#このライブラリの制限)により、client_secretは必須です。  

例えば、META-INF/microprofile-config.propertiesに、以下のように設定します。  

```
jp.empressia.enterprise.security.oidc.Microsoft.client_id=00000000-0000-0000-0000-000000000000
jp.empressia.enterprise.security.oidc.Microsoft.client_secret=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
jp.empressia.enterprise.security.oidc.Microsoft.AuthenticatedURLPath=/api/auth/Google/authenticated
```

client_secrestなどは、システムプロパティとして、  
以下のようにJavaのVM引数に指定してするなど、  
MicroProfile Configの別のConfigSourceとして設定しても良いかもしれません。  

```
-Djp.empressia.enterprise.security.oidc.Microsoft.client_id=00000000-0000-0000-0000-000000000000 -Djp.empressia.enterprise.security.oidc.Microsoft.client_secret=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

これらの設定自体は、別の手段で設定しても問題ありません。  
各OpenIDConnectAuthenticationMechanismの引数に定義されているSettingsに対応しているだけなので。  

さらに細かい調整が必要な場合は、  
任意のメソッドをオーバーライドしてください。  

設定には、現在、[制限事項](#制限事項)があるのでご注意ください。  

### OpenIDConnectIdentityStoreを用意します。

認証結果とアプリケーションで発行されたトークンを記憶するIdentityStoreを用意します。  

OpenIDConnectIdentityStoreを継承して、以下のメソッドを実装してください。  

* findCredential
* registerCredential
* updateToken
* removeToken

例えば、DBとかに保存するよう実装してください。  

また、必要に応じて以下のメソッドを実装します。  

* generateName
* generateGroups

各メソッドの詳細は、[OpenIDConnectIdentityStore](EmpressiaOpenIDConnect/src/main/java/jp/empressia/enterprise/security/oidc/OpenIDConnectIdentityStore.java)を参照してください。  

具体的な実装は、アプリケーションによって大きく異なると考えられます。  
[サンプル](#サンプル)を参考に、実装してください。  

### OpenIDConnectRememberMeIdentityStoreを用意します。

クッキーに保存するためのトークンを解決するRememberMeIdentityStoreを用意します。  

トークンをJCacheを使用してキャッシュすることで資格情報（Credential）を速やかに解決する、  
OpenIDConnectRememberMeIdentityStoreとTokenCacheを用意しています。  

OpenIDConnectRememberMeIdentityStoreを継承して、以下のメソッドを実装してください。  

* generateLoginTokenInternal(OpenIDConnectPrincipal, HashSet<String>)

例えば、DBとかに事前保存していたトークンを取得するように実装してください。  
OpenIDConnectIdentityStoreを継承してトークンを記憶していれば、そのトークンを読みだします。  

各メソッドの詳細は、[OpenIDConnectRememberMeIdentityStore](EmpressiaOpenIDConnect/src/main/java/jp/empressia/enterprise/security/oidc/OpenIDConnectRememberMeIdentityStore.java)を参照してください。  

具体的な実装は、アプリケーションによって大きく異なると考えられます。  
[サンプル](#サンプル)を参考に、実装してください。  

必要に応じて、コンストラクタインジェクション用のクラスをbeans.xmlに設定します。  

```xml
<beans>
	<alternatives>
		<class>jp.empressia.enterprise.security.oidc.OpenIDConnectRememberMeIdentityStore$TokenCache</class>
	</alternatives>
</beans>
```

### APIを制限します。

APIを役割や権限で制限するは、このライブラリとは関係ありません。  

Java EE Security（Jakarta Security）の機能をそのまま使用してください。  

例えば、JAX-RSであれば、以下のようにGroupの有無による制限ができます。  

```java
@Singleton
@DeclareRoles("User")
@Path("test")
public class TestWebAPI {

	@GET
	@Path("username")
	@RolesAllowed({"User"})
	@Produces("text/plain")
	public String username(@Context SecurityContext context) throws IOException {
		Principal p = context.getUserPrincipal();
		String name = p.getName();
		System.out.println(name);
		return name;
	}

}
```

@DeclareRolesと@RolesAllowedを用いて制限を実装しています。  

### 認証しないパスを設定します。

RolesAllowedアノテーションなどを使う場合は、  
HttpMessageContext#isProtectedが自動でtrueになるため、  
通常は、必要なときだけ認証されると思います。  

しかし、常に認証したい場合は、設定で切り替えられます。  
また、必要に応じて、認証しないパスも設定できます。  

いずれも、Mechanism用のSettingsにプロパティが用意されています。  

例えば、assets以下のURLでは認証をせず、それ以外では常に認証を行う場合、以下のように設定します。  

```
jp.empressia.enterprise.security.oidc.IgnoreAuthenticationURLPathRegex=^/assets/.*$
jp.empressia.enterprise.security.oidc.CreateAuthorizationRequestOnlyWhenProtected=false
```

## 複数の実装クラスを同時に扱う方法

実装の[サンプル](#サンプル)があります。  

複数のMechanismの実装クラスを同時に扱う場合は、  
MultipleIssuersAuthenticationMechanismを継承してCDIに登録します。  

このクラスは、認証のリクエストがあった場合に、Issuerをユーザーに選択させ、  
選択されたIssuer用のOpenIDConnectAuthenticationMechanismに、処理を委譲します。  

委譲するため、以下の3つのインターフェースを実装する必要があります。  

|#|インターフェース|概要|
|-|-|-|
|1|OpenIDConnectAuthenticationMechanismSupplier|サポートしたいOpenIDConnectAuthenticationMechanismの一覧を定義します。|
|2|OpenIDConnectAuthenticationMechanismSelectable|リクエストに対してどのOpenIDConnectAuthenticationMechanismを選択するかを定義します。リクエストパラメーターから選択するRedirectedIssurSelectorが用意されています。|
|3|MechanismNotSelectedHandler|いずれのOpenIDConnectAuthenticationMechanismも選択されなかった場合の動作を定義します。選択するページへリダイレクトするRedirectIssuerNotSelectedHandlerが用意されています。|

例えば、以下のように実装します。  
移譲先となるMechanismはCDIに登録すると、CDIでの解決ができなくなる点に注意してください。  

```java
/**
 * アプリケーションでのOpenID Connectのサービスを扱います。
 * @author すふぃあ
 */
@ApplicationScoped
public class ApplicationAuthenticationMechanism extends MultipleIssuersOpenIDConnectAuthenticationMechanism {

	/** Google、LINE、Microsoftをサポートする。 */
	@Dependent
	public static class ApplicationMechanismSupplier implements OpenIDConnectAuthenticationMechanismSupplier {

		private GoogleAuthenticationMechanism.Settings GoogleSettings;
		private LINEAuthenticationMechanism.Settings LINESettings;
		private MicrosoftAuthenticationMechanism.Settings MicrosoftSettings;

		private Collection<IOpenIDConnectAuthenticationMechanism> Mechanisms;

		@Inject
		public ApplicationMechanismSupplier(
			GoogleAuthenticationMechanism.Settings GoogleSettings,
			LINEAuthenticationMechanism.Settings LINESettings,
			MicrosoftAuthenticationMechanism.Settings MicrosoftSettings,
			IdentityStoreHandler IdentityStoreHandler,
			PublicKeyHelper PublicKeyHelper
		) {
			this.GoogleSettings = GoogleSettings;
			this.LINESettings = LINESettings;
			this.MicrosoftSettings = MicrosoftSettings;
			this.Mechanisms = Set.<IOpenIDConnectAuthenticationMechanism>of(
				new GoogleAuthenticationMechanism(this.GoogleSettings, IdentityStoreHandler, null, PublicKeyHelper) {
					@Override
					protected LinkedHashMap<String, String> handleAuthorizationRequestParameters(LinkedHashMap<String, String> parameters) {
						parameters.put("access_type", "offline");
						parameters.put("prompt", "consent");
						return parameters;
					}
				},
				new LINEAuthenticationMechanism(this.LINESettings, IdentityStoreHandler, null),
				new MicrosoftAuthenticationMechanism(this.MicrosoftSettings, IdentityStoreHandler, null, PublicKeyHelper)
			);
		}

		@Override
		public Collection<IOpenIDConnectAuthenticationMechanism> mechanisms(boolean useSecureCookie) {
			return this.Mechanisms;
		}

	}

	/**
	 * コンストラクタ。
	 */
	@Inject
	public ApplicationAuthenticationMechanism(Settings settings, OpenIDConnectAuthenticationMechanismSupplier MechanismSupplier, OpenIDConnectAuthenticationMechanismSelectable MechanismSelector, MechanismNotSelectedHandler MechanismNotSelectedHandler, IOpenIDConnectIdentityStore IdentityStore) {
		super(settings, MechanismSupplier, MechanismSelector, MechanismNotSelectedHandler, IdentityStore);
	}

}
```

この実装の場合、beans.xmlは以下のようになります。  

```xml
<beans>
	<alternatives>
		<class>jp.empressia.enterprise.security.oidc.GoogleAuthenticationMechanism$Settings</class>
		<class>jp.empressia.enterprise.security.oidc.LINEAuthenticationMechanism$Settings</class>
		<class>jp.empressia.enterprise.security.oidc.MicrosoftAuthenticationMechanism$Settings</class>
		<class>jp.empressia.enterprise.security.oidc.PublicKeyHelper</class>
		<class>jp.empressia.enterprise.security.oidc.OpenIDConnectRememberMeIdentityStore$TokenCache</class>
		<class>jp.empressia.enterprise.security.oidc.MultipleIssuersOpenIDConnectAuthenticationMechanism$Settings</class>
		<class>jp.empressia.enterprise.security.oidc.MultipleIssuersOpenIDConnectAuthenticationMechanism$RedirectedIssurSelector</class>
		<class>jp.empressia.enterprise.security.oidc.MultipleIssuersOpenIDConnectAuthenticationMechanism$RedirectIssuerNotSelectedHandler</class>
	</alternatives>
</beans>
```

必要に応じて、認証をしないパスやIssuerを選択する仕組みを設定する必要があります。  
例えば、以下のように設定します。  

```
jp.empressia.enterprise.security.oidc.MultipleIssuers.IgnoreAuthenticationURLPaths=/pages/IssuerSelection.html
jp.empressia.enterprise.security.oidc.MultipleIssuers.IgnoreAuthenticationURLPathRegex=^/assets/.*$
jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectedIssurSelector.IssuerSelectedURLPath=/api/auth/MultipleIssuers/issuerSelected
jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectIssuerNotSelectedHandler.IssuerSelectionPageURLPath=/pages/IssuerSelection.html
```

この場合、認証をしないパスには、  
Issuerの選択に使用するURL（HTMLやjsとか）を指定しています。  
Issuerの選択結果は認証の処理になるのでIgnoreには追加しません。  

## Reverse Proxyの後ろで扱う方法

Reverse Proxyで使用する場合、そのままの設定だと、  
redirect_uriのAuthorityが、『localhost:8080』などになります。  

これを調整する場合は、例えば、以下のようにhandleAuthenticatedURLメソッドをオーバーライドします。  

```java
				new MicrosoftAuthenticationMechanism(this.MicrosoftSettings, IdentityStoreHandler, PublicKeyHelper) {
					@Override
					protected String handleAuthenticatedURL(String URL) {
						String scheme = this.useSecureCookie() ? "https" : "http";
						return scheme + "://" + "Authority" + this.getAuthenticatedURLPath();
					}
				}
```

## トークンを取得する処理を非同期に変更する方法

上記までの説明で、各Mechanismの引数にnullが設定されていますが、  
そこにExecutorServiceを設定することで、トークンを取得する処理が非同期になります。  
nullだと、同期処理になります。  

## ライブラリの依存関係

Java EE Security API（Jakarta Security）の他に、以下の仕様とライブラリに強く依存しています。  

CDI  
> https://github.com/eclipse-ee4j/cdi

Java JWT: JSON Web Token for Java and Android  
> https://github.com/jwtk/jjwt

他、以下の仕様を利用する想定です。  
使わなくても問題ありませんが、使用したほうが良いと思います。  

JCache  
> https://github.com/jsr107/jsr107spec

MicroProfile Config  
> https://github.com/eclipse/microprofile-config

## 制限事項

### このライブラリの制限

このライブラリでの制限事項は以下の通りです。  

* stateとnonceを必ず使用します。
* Issuerからの認証結果は、決まったURLにリクエストされる必要があります。
* 認証後にアクセスしたいアドレスへは、認証後にリダイレクトします。
* 各種パラメーターの維持にクッキーを使用します。
* form_postされた場合は、Cookieにフォーム内容を設定して自身にredirectすることで値を取得しようとします。
* Client Authentication Methodは、client_secret_postにだけ対応しています。
	他の方法は、OpenIDConnectAuthenticationMechanismのメソッドを継承して自分で実装する必要があります。  
* Version 1.2.0で、MicroProfile Config 2.0の仕様にあわせてあります。

### Payara Microでの制限

Payara Micro 5.194だと、必要のないクラスの設定もしないと動かないようです。  
以下のissueが解決すると設定しなくてもすむかもしれません。  

> https://github.com/payara/Payara/issues/4455

この場合の設定値は、使用されないので任意で問題ありません。  
必須のプロパティは以下の通りです。  
詳細は、microprofile-config.propertiesを確認してください。  

```
jp.empressia.enterprise.security.oidc.Issuer=
jp.empressia.enterprise.security.oidc.AuthorizationEndpoint=
jp.empressia.enterprise.security.oidc.client_id=
jp.empressia.enterprise.security.oidc.AuthenticatedURLPath=
jp.empressia.enterprise.security.oidc.Google.client_id=
jp.empressia.enterprise.security.oidc.Google.client_secret=
jp.empressia.enterprise.security.oidc.Google.AuthenticatedURLPath=
jp.empressia.enterprise.security.oidc.LINE.client_id=
jp.empressia.enterprise.security.oidc.LINE.client_secret=
jp.empressia.enterprise.security.oidc.LINE.AuthenticatedURLPath=
jp.empressia.enterprise.security.oidc.Microsoft.client_id=
jp.empressia.enterprise.security.oidc.Microsoft.AuthenticatedURLPath=
jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectedIssurSelector.IssuerSelectedURLPath=
jp.empressia.enterprise.security.oidc.MultipleIssuers.RedirectIssuerNotSelectedHandler.IssuerSelectionPageURLPath=
```

Payara Micro 5.2021.1からは、MicroProfile Config 2.0になっていて、この制限は受けません。  

## サンプル

* [サンプルプロジェクト](https://github.com/Empressia/EmpressiaOpenIDConnectSample)
* [Microsoft ID プラットフォームを使用するサンプル（サンプル01）](https://github.com/Empressia/EmpressiaOpenIDConnectSample/EmpressiaOpenIDConnectSample01)
	* [OpenIDConnectIdentityStoreの実装サンプル](https://github.com/Empressia/EmpressiaOpenIDConnectSample/EmpressiaOpenIDConnectSample01/src/main/java/jp/empressia/app/empressia_oidc_sample_02/security/ApplicationIdentityStore.java)
	* [OpenIDConnectRememberMeIdentityStoreの実装サンプル](https://github.com/Empressia/EmpressiaOpenIDConnectSample/EmpressiaOpenIDConnectSample01/src/main/java/jp/empressia/app/empressia_oidc_sample_02/security/ApplicationRememberMeIdentityStore.java)
* [複数のIssuerを同時に使用するサンプル（サンプル02）](https://github.com/Empressia/EmpressiaOpenIDConnectSample/EmpressiaOpenIDConnectSample02)

## IOpenIDConnectAuthenticationMechanismの注意事項

IOpenIDConnectAuthenticationMechanismを直接実装することはないと思いますが、  
実装する場合は、以下の点にご注意ください。  

以下のメソッドはデフォルトメソッドなので、  
CDIで使う場合はオーバーライドしないと、  
UnsupportedExceptionが投げられる場合があります。  

* IOpenIDConnectAuthenticationMechanismの
	* memorizeRequestPath
	* getRequestPath
	* removeRequestPath
* IOpenIDConnectIdentityStore
	* findCredential

## プロジェクトビルドの注意事項

Visual Studio Codeでテストする場合は、  
java.test.configのvmArgsにJMockitのJavaagentを設定する必要があります。  
Gradleに設定してあるcopySyncTestJavaAgentタスクを実行することで、  
build/TestAgentJava/に、ライブラリがコピーされるようになっています。  

## ライセンス

いつも通りのライセンスです。  
zlibライセンス、MITライセンスでも利用できます。  

ただし、チーム（複数人）で使用する場合は、MITライセンスとしてください。  
