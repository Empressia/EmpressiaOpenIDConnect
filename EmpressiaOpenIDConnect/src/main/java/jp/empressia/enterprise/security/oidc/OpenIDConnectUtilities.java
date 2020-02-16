package jp.empressia.enterprise.security.oidc;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.MessageFormat;
import java.time.Clock;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * 乱数や時刻系のユーティリティ。
 * @author すふぃあ
 */
public class OpenIDConnectUtilities {

	/** stateで使用されるランダム生成器。 */
	private static SecureRandom StateRandom;
	/** stateの長さ。 */
	private static int state_length = 8;

	static {
		try {
			OpenIDConnectUtilities.StateRandom = OpenIDConnectUtilities.createSecureRandom();
		} catch(NoSuchAlgorithmException ex) {
			String message = "この環境ではランダム生成器が作れませんでした。環境を確認してください。";
			throw new IllegalStateException(message, ex);
		}
	}

	/** SecureRandomのインスタンスを生成します。 */
	private static SecureRandom createSecureRandom() throws NoSuchAlgorithmException {
		SecureRandom r;
		// getInstanceStrongが推奨されているけど、Linuxでは/dev/randomを使用してブロックされてしまう可能性があるから、
		// まずは、NonBlockingのアルゴリズムを探してから、それ以外で推奨値を使用するよ。
		try {
			r = SecureRandom.getInstance("NativePRNGNonBlocking");
		} catch(NoSuchAlgorithmException ex) {
			r = SecureRandom.getInstanceStrong();
		}
		return r;
	}

	/**
	 * stateを生成します。
	 * ここでは、8桁の16進数で生成します。
	 */
	public static String generateState() {
		int v = OpenIDConnectUtilities.StateRandom.nextInt();
		String generated = Integer.toHexString(v);
		if(generated.length() < OpenIDConnectUtilities.state_length) {
			generated = IntStream.range(0, OpenIDConnectUtilities.state_length - generated.length()).mapToObj(i -> "0").collect(Collectors.joining()) + generated;
		} else if(generated.length() > OpenIDConnectUtilities.state_length) {
			// Integer.MAX_VALUEは、16進数^8桁と同じ程度だから、8桁の設定なら常に収まる。
			String message = MessageFormat.format("stateの生成桁数[{0}]が大きすぎます。この例外は通常発生しません。", OpenIDConnectUtilities.state_length);
			throw new IllegalStateException(message);
		}
		return generated;
	}

	/**
	 * nonceを生成します。
	 * ここでは、UUIDとなります。
	 */
	public static String generateNonce() {
		return UUID.randomUUID().toString();
	}

	/**
	 * tokenを生成します。
	 * ここでは、UUID2個の結合となります。
	 */
	public static String generateToken() {
		return UUID.randomUUID().toString() + UUID.randomUUID().toString();
	}

	/** UNIX Time（UTCでの現在日時）（秒）。 */
	public static long currentUNIXTime() {
		long current = Clock.systemUTC().millis() / 1000;
		return current;
	}

}
