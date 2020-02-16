package jp.empressia.enterprise.security.oidc;

import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;

/**
 * OpenID Connect用のインターフェースです。
 * RememberMeなStoreとかから呼ぶためのメソッドを定義しています。
 */
public interface IOpenIDConnectIdentityStore extends IdentityStore {

	/**
	 * 指定されたtokenからOpenIDConnectCredentialを返します。
	 * 存在しない場合は、nullを返します。
	 */
	public default OpenIDConnectCredential findCredential(String token) {
		return null;
	}

	/**
	 * CredentialからPrincipalとGroupを生成して、有効なCredentialValidationResultを返します。
	 */
	public CredentialValidationResult createValidResult(OpenIDConnectCredential credential);

}
