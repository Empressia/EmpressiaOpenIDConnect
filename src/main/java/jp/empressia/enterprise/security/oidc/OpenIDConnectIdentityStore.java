package jp.empressia.enterprise.security.oidc;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;
import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.RememberMeCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jp.empressia.enterprise.security.oidc.IOpenIDConnectAuthenticationMechanism.TokenResponse;

/**
 * OpenID Connect用のIdentity Store。
 * @author すふぃあ
 */
@ApplicationScoped
@Alternative
public class OpenIDConnectIdentityStore implements IOpenIDConnectIdentityStore {

	/** トークンのリフレッシュなどに使用するMechanismです。 */
	private IOpenIDConnectAuthenticationMechanism Mechanism;

	/** コンストラクタ。 */
	@Inject
	public OpenIDConnectIdentityStore(IOpenIDConnectAuthenticationMechanism Mechanism) {
		this.Mechanism = Mechanism;
	}

	/** 成功した場合、OpenID Connect Principalを含むCredentialValidationResultを返します。 */
	@Override
	public CredentialValidationResult validate(Credential credential) {
		CredentialValidationResult result;
		if(credential instanceof OpenIDConnectCredential) {
			// 新たに認証されたされたものなので、ストアとして受け入れて記憶する。
			result = this.validate((OpenIDConnectCredential)credential);
		} else if(credential instanceof RememberMeCredential) {
			// トークンをもとに認証をかける。必要に応じて、リフレッシュする。
			result = this.validate((RememberMeCredential)credential);
		} else {
			// サポート外のCredential。
			result = CredentialValidationResult.NOT_VALIDATED_RESULT;
		}
		return result;
	}

	/**
	 * 指定されたtokenからOpenIDConnectCredentialを返します。
	 * 存在しない場合は、nullを返します。
	 */
	@Override
	public OpenIDConnectCredential findCredential(String token) {
		return null;
	}

	/**
	 * 指定されたOpenIDConnectCredentialを登録します。
	 * トークンを同時に発行してストアに登録しておいても良いかもしれません。
	 * ここで発行しておくと、OpenIDConnectRememberMeIdentityStore#generateLoginTokenInternalでは、
	 * それを読み読む形になります。
	 */
	protected void registerCredential(OpenIDConnectCredential credential) {
	}

	/**
	 * 指定されたtokenを更新します。
	 * @param credential リフレッシュされた新しい認証認可情報。IDトークンは亡い可能性がある店に注意する。
	 */
	protected void updateToken(String token, OpenIDConnectCredential credential) {
	}

	/**
	 * 指定されたtokenを無効にします。
	 */
	protected void removeToken(String token, OpenIDConnectCredential credential) {
	}

	/**
	 * 指定されたcredentialからnameを生成します。
	 * OpenIDConnectPrincipalのnameになります。
	 * 一意になるのを推奨します。
	 * これは、Java内に一意として扱っているケースが存在するから。
	 * 例えば、java.nio.file.attribute.UserPrincipalLookupService。
	 * 初期実装は、Issuer＋#＋Subject（URLエンコード済み）です。
	 */
	protected String generateName(OpenIDConnectCredential credential) {
		String name = credential.getIssuer() + "#" + URLEncoder.encode(credential.getSubject(), StandardCharsets.UTF_8);
		return name;
	}

	/**
	 * 指定されたcredentialgroupsを生成します。
	 * CredentialValidationResultに渡されるgroupsです。
	 * 役割や権限の表現に相当すると思われます。
	 * 初期実装は、空のセットを返します。
	 */
	protected Set<String> generateGroups(OpenIDConnectCredential credential) {
		return Set.of();
	}

	/**
	 * リクエストされたクッキーにトークンがある場合に、Java EE Security（Jakarta Security）から呼ばれます。
	 * ストアにトークンが記録されていれば、
	 * OpenID Connect Principalを含むCredentialValidationResultを返します。
	 */
	protected CredentialValidationResult validate(RememberMeCredential credential) {
		String token = credential.getToken();
		OpenIDConnectCredential c = this.findCredential(credential.getToken());
		if(c == null) {
			return CredentialValidationResult.INVALID_RESULT;
		}
		// Issuerのトークンは期限内？
		if(c.isAvailable()) {
			// 期限内なら、そのまま使える。
			// ただ、RememberMeが使われている場合は、ここは通らないはず。
		} else {
			// リフレッシュ可能なら、試みる。
			if(c.getRefreshToken() != null) {
				TokenResponse tokenResponse = this.Mechanism.refreshToken(c.getRefreshToken(), c);
				String access_token = tokenResponse.access_token();
				String refresh_token = tokenResponse.refresh_token();
				String token_type = tokenResponse.token_type();
				int expires_in = tokenResponse.expires_in();
				LocalDateTime createdAt = LocalDateTime.now();
				String scope = tokenResponse.scope();
				String id_token = tokenResponse.id_token();
				String issuer;
				String subject;
				long expirationTime;
				long issuedAt;
				Claims claims;
				if(id_token == null) {
					// id_tokenがこないのは変更が無いと言うことで、現状を引き継ぎます。
					id_token = c.getIDToken();
					issuer = c.getIssuer();
					subject = c.getSubject();
					expirationTime = c.getExpirationTime();
					issuedAt = c.getIssuedAt();
					claims = null;
				} else {
					Jws<Claims> id_tokenJws = this.Mechanism.parseIDToken(id_token, c);
					try {
						this.Mechanism.validateIDToken(id_tokenJws, null, c);
					} catch(Exception ex) {
						throw new IllegalStateException("リフレッシュしたid_tokenが不正なIDトークンでした。");
					}
					try {
						this.Mechanism.validateAccessToken(access_token, token_type, id_tokenJws, (scope != null) ? scope : c.getScope(), null, c);
					} catch(Exception ex) {
						throw new IllegalStateException("リフレッシュしたaccess_tokenが不正なアクセストークンでした。");
					}
					Claims id_tokenBody = id_tokenJws.getBody();
					issuer = id_tokenBody.getIssuer();
					subject = id_tokenBody.getSubject();
					expirationTime = id_tokenBody.getExpiration().toInstant().toEpochMilli() / 1000;
					issuedAt = id_tokenBody.getIssuedAt().toInstant().toEpochMilli() / 1000;
					claims = id_tokenBody;
				}
				OpenIDConnectCredential newCredential = new OpenIDConnectCredential(
					issuer, subject, id_token, expirationTime, issuedAt,
					access_token, refresh_token, expires_in, createdAt,
					(scope != null) ? scope : c.getScope(),
					claims
				);
				this.updateToken(token, newCredential);
				// 古いトークンの破棄を試す。
				String past_access_token = c.getAccessToken();
				if(past_access_token != null) {
					try {
						this.Mechanism.revokeToken(past_access_token, null, c);
					} catch(Exception ex) {
						// revokeの失敗は、とりあえず無視する。
					}
				}
				c = newCredential;
			}
			// いろいろやった結果。
			if(c.isAvailable() == false) {
				this.removeToken(token, c);
				// リフレッシュできないから、再認証が必要です。
				return CredentialValidationResult.INVALID_RESULT;
			}
		}
		CredentialValidationResult result = this.createValidResult(c);
		return result;
	}

	/**
	 * 新しく認証が通った時にJava EE Security API（Jakarta Security）から呼ばれます。
	 * ストアに記録して、
	 * OpenID Connect Principalを含むCredentialValidationResultを返します。
	 * アプリケーション用のトークンをこの時点（実際にはregisterCredential）で発行しておくことをおすすめします。
	 */
	protected CredentialValidationResult validate(OpenIDConnectCredential credential) {
		this.registerCredential(credential);
		OpenIDConnectCredential c = credential;
		CredentialValidationResult result = this.createValidResult(c);
		return result;
	}

	/**
	 * CredentialからPrincipalとGroupを生成して、有効なCredentialValidationResultを返します。
	 */
	public CredentialValidationResult createValidResult(OpenIDConnectCredential credential) {
		String name = this.generateName(credential);
		Set<String> groups = this.generateGroups(credential);
		CredentialValidationResult result = new CredentialValidationResult(new OpenIDConnectPrincipal(name, credential), groups);
		return result;
	}

	/**
	 * OpenID Connect用のCallerPrincipal。
	 * @author すふぃあ
	 */
	@SuppressWarnings("serial")
	public static class OpenIDConnectPrincipal extends CallerPrincipal implements Serializable {
		/** Credential。 */
		private OpenIDConnectCredential Credential;
		/** Credential。 */
		public OpenIDConnectCredential getCredential() { return this.Credential; }
		/** コンストラクタ。 */
		public OpenIDConnectPrincipal(String name, OpenIDConnectCredential credential) {
			super(name);
			this.Credential = credential;
		}
		/** シリアライズ用です。 */
		private Object writeReplace() throws ObjectStreamException {
			Serialized replaced = new Serialized();
			replaced.Name = this.getName();
			replaced.Credential = this.Credential;
			return replaced;
		}
		/**
		 * シリアライズ用です。
		 * @author すふぃあ
		 */
		private static class Serialized implements Serializable {
			/** CallerPrincipal.name。 */
			private String Name;
			/** Credential。 */
			private OpenIDConnectCredential Credential;
			/** シリアライズ用です。 */
			private Object readResolve() throws ObjectStreamException {
				OpenIDConnectPrincipal resolved = new OpenIDConnectPrincipal(this.Name, this.Credential);
				return resolved;
			}
		}
	}

}
