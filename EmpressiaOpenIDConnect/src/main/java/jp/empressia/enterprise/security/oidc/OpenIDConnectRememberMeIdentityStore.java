package jp.empressia.enterprise.security.oidc;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.cache.annotation.CachePut;
import javax.cache.annotation.CacheRemove;
import javax.cache.annotation.CacheResult;
import javax.cache.annotation.CacheValue;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Alternative;
import javax.security.enterprise.CallerPrincipal;
import javax.security.enterprise.credential.RememberMeCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.RememberMeIdentityStore;

import jp.empressia.enterprise.security.oidc.OpenIDConnectIdentityStore.OpenIDConnectPrincipal;
import jp.empressia.enterprise.security.oidc.OpenIDConnectRememberMeIdentityStore.TokenCache.TokenNotCachedException;

/**
 * OpenID Connectの認証結果をアプリケーションのトークンをキャッシュするストアです。
 * @author すふぃあ
 */
public abstract class OpenIDConnectRememberMeIdentityStore implements RememberMeIdentityStore {

	/** トークンキャッシュのJCache用の名前です。 */
	public static final String TOKEN_CACHE_NAME = "jp.empressia.security.OpenIDConnectRememberMeIdentityStore.TokenCache";

	/** トークンキャッシュ。 */
	private TokenCache TokenCache;

	/** トークンからCredentialを復元するために使うIdentityStoreです。 */
	private IOpenIDConnectIdentityStore IdentityStore;

	/**
	 * キャッシュ用。CredentialValidationResultは、都度作るものだと思うから、別のクラスにした。
	 * @author すふぃあ
	 */
	@SuppressWarnings("serial")
	protected static class Holder implements Serializable {
		/** Principal。 */
		private OpenIDConnectPrincipal Principal;
		/** Groups。 */
		private Set<String> Groups;
		/** コンストラクタ。 */
		public Holder(OpenIDConnectPrincipal Principal, Set<String> Groups) {
			this.Principal = Principal;
			this.Groups = Groups;
		}
		/** シリアライズ用。 */
		private Object writeReplace() throws ObjectStreamException {
			Serialized replaced = new Serialized();
			replaced.Principal = this.Principal;
			if(this.Groups instanceof LinkedHashSet) {
				replaced.Groups = (LinkedHashSet<String>)this.Groups;
			} else {
				replaced.Groups = new LinkedHashSet<>(this.Groups);
			}
			return replaced;
		}
		/**
		 * シリアライズ用。
		 * @author すふぃあ
		 */
		private static class Serialized implements Serializable {
			/** Holder.Principal。 */
			private OpenIDConnectPrincipal Principal;
			/** Holder.Groups。*/
			private LinkedHashSet<String> Groups;
			/** シリアライズ用。 */
			private Object readResolve() throws ObjectStreamException {
				Holder resolved = new Holder(this.Principal, this.Groups);
				return resolved;
			}
		}
	}

	/** コンストラクタ。 */
	public OpenIDConnectRememberMeIdentityStore(TokenCache TokenCache, IOpenIDConnectIdentityStore IdentityStore) {
		this.TokenCache = TokenCache;
		this.IdentityStore = IdentityStore;
	}

	/** クッキーにトークンがある場合に、Java EE Security（Jakarta Security）から呼ばれます。 */
	@Override
	public CredentialValidationResult validate(RememberMeCredential credential) {
		String token = credential.getToken();
		Holder holder;
		try {
			holder = this.TokenCache.get(token);
		} catch(TokenNotCachedException ex) {
			holder = null;
		}
		CredentialValidationResult result;
		if(holder != null) {
			if(holder.Principal.getCredential().isAvailable()) {
				result = new CredentialValidationResult(holder.Principal, holder.Groups);
			} else {
				result = CredentialValidationResult.INVALID_RESULT;
			}
		} else {
			// キャッシュにないだけだったらStoreから復元するよ。
			OpenIDConnectCredential c = this.IdentityStore.findCredential(token);
			if((c != null) && c.isAvailable()) {
				result = this.IdentityStore.createValidResult(c);
				OpenIDConnectPrincipal principal = (OpenIDConnectPrincipal)result.getCallerPrincipal();
				Set<String> groups = result.getCallerGroups();
				Holder h = new Holder(principal, groups);
				this.TokenCache.put(token, h);
			} else {
				result = CredentialValidationResult.INVALID_RESULT;
			}
		}
 		return result;
	}
	 
	/**
	 * アプリケーションでのトークンを発行します。
	 * ここではキャッシュもしているから、
	 * 具体的な発行は、generateLoginTokenInternalで実装する。
	 */
	@Override
	public String generateLoginToken(CallerPrincipal callerPrincipal, Set<String> groups) {
		// 参考：http://openid-foundation-japan.github.io/rfc6749.ja.html#anchor38
		// ここではキャストできる構成で通る……はず。
		OpenIDConnectPrincipal principal = (OpenIDConnectPrincipal)callerPrincipal;
		Holder h = new Holder(principal, groups);
		String token = this.generateLoginTokenInternal(principal, groups);
		this.TokenCache.put(token, h);
		return token;
	}

	/** アプリケーションのトークンを発行します。 */
	protected abstract String generateLoginTokenInternal(OpenIDConnectPrincipal principal, Set<String> groups);

	/**
	 * Tokenのキャッシュストアです。
	 * CDIの機能を使っています。直接newするのではなく、CDI経由で取得して使用してください。
	 * JCacheの詳細は確認していないけど、CacheResultでnullを返すと、
	 * nullをキャッシュしようとして落ちる。
	 * このため、例外を投げるか、Optionalを返すかの二択になる感じがする。
	 * OptionalってSerializeできるのかな？
	 * throwも投げるだけならそんなに重くないかな。デバッグだとキャッシュしたのを普通に投げると変に重くなるけど。
	 * @author すふぃあ
	 */
	@Dependent
	@Alternative
	public static class TokenCache {
		/** あらかじめ用意された例外です。 */
		private TokenNotCachedException Exception = new TokenNotCachedException();
		/** キャッシュします。 */
		@CachePut(cacheName=TOKEN_CACHE_NAME)
		public void put(String token, @CacheValue Holder holder) {
		}
		/** キャッシュから返します。 */
		@CacheResult(cacheName=TOKEN_CACHE_NAME)
		public Holder get(String token) {
			throw this.Exception;
		}
		/** キャッシュから除外します。 */
		@CacheRemove(cacheName=TOKEN_CACHE_NAME)
		public void remove(String token) {
		}
		/**
		 * きゃっしゅが見つからなかったことを表現する例外です。
		 * @author すふぃあ
		 */
		@SuppressWarnings("serial")
		public static class TokenNotCachedException extends RuntimeException {
		}
	}

	/** トークンを除去します。 */
	@Override
	public void removeLoginToken(String token) {
		this.TokenCache.remove(token);
	}

}
