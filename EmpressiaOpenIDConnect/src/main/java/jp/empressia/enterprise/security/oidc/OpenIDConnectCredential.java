package jp.empressia.enterprise.security.oidc;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.ZoneId;

import javax.security.enterprise.credential.Credential;

import io.jsonwebtoken.Claims;

/**
 * expirationTimeとissuedAtはJWTを参考にしている。
 * intで十分だけど、longを受け付けられるようにしている。
 * @author すふぃあ
 */
@SuppressWarnings("serial")
public class OpenIDConnectCredential implements Credential, Serializable {

	/** このクラスでのExpiresInの未定義値です。 */
	public static final int UNDEFINED_EXPIRES_IN = -1;

	/** Issuer（iss）。 */
	private String Issuer;
	/** Issuer（iss）。 */
	public String getIssuer() { return this.Issuer; }
	/** Subject（sub）。 */
	private String Subject;
	/** Subject（sub）。 */
	public String getSubject() { return this.Subject; }
	/** IDToken。 */
	private String IDToken;
	/** IDToken。 */
	public String getIDToken() { return this.IDToken; }
	/** ExpirationTime（exp）。 */
	private long ExpirationTime;
	/** ExpirationTime（exp）。 */
	public long getExpirationTime() { return this.ExpirationTime; }
	/** IssuedAt（iat）。 */
	private long IssuedAt;
	/** IssuedAt（iat）。 */
	public long getIssuedAt() { return this.IssuedAt; }

	/** AccessToken。 */
	private String AccessToken;
	/** AccessToken。 */
	public String getAccessToken() { return this.AccessToken; }
	/** RefreshToken。 */
	private String RefreshToken;
	/** RefreshToken。 */
	public String getRefreshToken() { return this.RefreshToken; }
	/** ExpiresIn。 */
	private int ExpiresIn = UNDEFINED_EXPIRES_IN;
	/** ExpiresIn。 */
	public int getExpiresIn() { return this.ExpiresIn; }
	/** CreatedAt。 */
	private LocalDateTime CreatedAt;
	/** CreatedAt。 */
	public LocalDateTime getCreatedAt() { return this.CreatedAt; }

	/** Scope。 */
	private String Scope;
	/** Scope。 */
	public String getScope() { return this.Scope; }

	/** Claims（id_tokenを受け取ったとき以外はnullの場合があります）。 */
	private transient Claims Claims;
	/**
	 * Claims（id_tokenを受け取ったとき以外はnullの場合があります）。
	 */
	public Claims getClaims() { return this.Claims; }

	/**
	 * コンストラクタ。
	 * @param Issuer Issuer（iss）。
	 * @param Subject Subject（sub）。
	 * @param IDToken。
	 * @param ExpirationTime ExpirationTime（exp）。
	 * @param IssuedAt IssuedAt（iat）。
	 * @param AccessToken。
	 * @param RefreshToken。
	 * @param ExpiresIn
	 * @param CreatedAt
	 * @param Scope
	 */
	public OpenIDConnectCredential(String Issuer, String Subject, String IDToken, long ExpirationTime, long IssuedAt, String AccessToken, String RefreshToken, int ExpiresIn, LocalDateTime CreatedAt, String Scope) {
		this(Issuer, Subject, IDToken, ExpirationTime, IssuedAt, AccessToken, RefreshToken, ExpiresIn, CreatedAt, Scope, null);
	}

	/**
	 * コンストラクタ。
	 * @param Issuer Issuer（iss）。
	 * @param Subject Subject（sub）。
	 * @param IDToken。
	 * @param ExpirationTime ExpirationTime（exp）。
	 * @param IssuedAt IssuedAt（iat）。
	 * @param AccessToken。
	 * @param RefreshToken。
	 * @param ExpiresIn
	 * @param CreatedAt
	 * @param Scope
	 * @param Claims
	 */
	public OpenIDConnectCredential(String Issuer, String Subject, String IDToken, long ExpirationTime, long IssuedAt, String AccessToken, String RefreshToken, int ExpiresIn, LocalDateTime CreatedAt, String Scope, Claims Claims) {
		this.Issuer = Issuer;
		this.Subject = Subject;
		this.IDToken = IDToken;
		this.ExpirationTime = ExpirationTime;
		this.IssuedAt = IssuedAt;
		this.AccessToken = AccessToken;
		this.RefreshToken = RefreshToken;
		this.ExpiresIn = ExpiresIn;
		this.CreatedAt = CreatedAt;
		this.Scope = Scope;
		this.Claims = Claims;
	}

	/**
	 * コンストラクタ。
	 * @param Issuer Issuer（iss）。
	 * @param Subject Subject（sub）。
	 * @param IDToken。
	 * @param ExpirationTime ExpirationTime（exp）。
	 * @param IssuedAt IssuedAt（iat）。
	 * @param Scope
	 */
	public OpenIDConnectCredential(String Issuer, String Subject, String IDToken, long ExpirationTime, long IssuedAt, String Scope) {
		this(Issuer, Subject, IDToken, ExpirationTime, IssuedAt, null, null, OpenIDConnectCredential.UNDEFINED_EXPIRES_IN, null, Scope, null);
	}

	/**
	 * コンストラクタ。
	 * @param Issuer Issuer（iss）。
	 * @param Subject Subject（sub）。
	 * @param IDToken。
	 * @param ExpirationTime ExpirationTime（exp）。
	 * @param IssuedAt IssuedAt（iat）。
	 * @param Scope
	 * @param Claims。
	 */
	public OpenIDConnectCredential(String Issuer, String Subject, String IDToken, long ExpirationTime, long IssuedAt, String Scope, Claims Claims) {
		this(Issuer, Subject, IDToken, ExpirationTime, IssuedAt, null, null, OpenIDConnectCredential.UNDEFINED_EXPIRES_IN, null, Scope, Claims);
	}

	/** 秘密な情報は含まないため、常にtrueを返す。 */
	@Override
	public boolean isCleared() { return true; }

	/** このCredentialが有効か確認します。 */
	@Override
	public boolean isValid() { return this.isAvailable(); }

	/**
	 * このCredentialが有効か確認します。
	 * 各種トークンの有効期間を確認します。
	 */
	public boolean isAvailable() {
		long current = OpenIDConnectUtilities.currentUNIXTime();
		boolean isAvalilable = (current <= this.ExpirationTime);
		if(isAvalilable) {
			if(this.AccessToken != null) {
				// ローカル日時をUNIX時間８UTCエポック秒）に変換する。
				long expiration = this.CreatedAt.atZone(ZoneId.systemDefault()).toEpochSecond() + this.ExpiresIn;
				isAvalilable = (current < expiration);
			}
		}
		return isAvalilable;
	}

	private Object writeReplace() throws ObjectStreamException {
		Serialized replaced = new Serialized();
		replaced.Issuer = this.Issuer;
		replaced.Subject = this.Subject;
		replaced.IDToken = this.IDToken;
		replaced.ExpirationTime = this.ExpirationTime;
		replaced.IssuedAt = this.IssuedAt;
		replaced.AccessToken = this.getAccessToken();
		replaced.RefreshToken = this.RefreshToken;
		replaced.ExpiresIn = this.ExpiresIn;
		replaced.CreatedAt = this.CreatedAt;
		replaced.Scope = this.Scope;
		return replaced;
	}

	/**
	 * @author すふぃあ
	 */
	private static class Serialized implements Serializable {
		private String Issuer;
		private String Subject;
		private String IDToken;
		private long ExpirationTime;
		private long IssuedAt;
		private String AccessToken;
		private String RefreshToken;
		private int ExpiresIn = OpenIDConnectCredential.UNDEFINED_EXPIRES_IN;
		private LocalDateTime CreatedAt;
		private String Scope;
		private Object readResolve() throws ObjectStreamException {
			OpenIDConnectCredential resolved = new OpenIDConnectCredential(this.Issuer, this.Subject, this.IDToken, this.ExpirationTime, this.IssuedAt, this.AccessToken, this.RefreshToken, this.ExpiresIn, this.CreatedAt, this.Scope, null);
			return resolved;
		}
	}

}
