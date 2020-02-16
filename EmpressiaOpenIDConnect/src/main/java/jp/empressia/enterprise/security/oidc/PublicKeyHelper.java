package jp.empressia.enterprise.security.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.MessageFormat;

import javax.cache.annotation.CacheResult;
import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Alternative;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.io.Decoders;

/**
 * 公開鍵の取得を支援する。
 * @author すふぃあ
 */
@Dependent
@Alternative
public class PublicKeyHelper {

	/**
	 * 外部に接続して、公開鍵情報を取得します。
	 * RSA固定で構築します。
	 * https://openid.net/specs/openid-connect-discovery-1_0.html
	 * https://openid-foundation-japan.github.io/rfc7517.ja.html
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	@CacheResult
	public Key getPubliKey(URI jwks_uri, String kid) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
		ObjectMapper mapper = new ObjectMapper();
		HttpClient client = HttpClient.newHttpClient();
		Key key;
		{
			HttpRequest request = HttpRequest.newBuilder(jwks_uri).build();
			HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
			if(response.statusCode() != 200) {
				String message = MessageFormat.format("OpenID Connect用の公開鍵の取得に失敗しました[{0}]。", response.statusCode());
				throw new IllegalStateException(message);
			}
			JsonNode node = mapper.readTree(response.body());
			JsonNode keysNode = node.get("keys");
			if(keysNode.isArray() == false) {
				throw new IllegalStateException("keys要素が配列形式になっていません。");
			}
			JsonNode targetKeyNode = null;
			for(JsonNode keyNode : keysNode) {
				if(keyNode.get("kid").asText().equals(kid)) {
					targetKeyNode = keyNode;
					break;
				}
			}
			if(targetKeyNode == null) {
				throw new IllegalStateException("必要な鍵が見つかりませんでした。");
			}
			String keyType = targetKeyNode.get("kty").asText();
			if(keyType.equals("RSA") == false) {
				String message = MessageFormat.format("未サポートのkty[{0}]が指定されました。", keyType);
				throw new IllegalStateException(message);
			}
			// RSA publi Keyは多分こんなかんじ。定義は特に見てないけど、まぁ、大丈夫かな。
			String e = targetKeyNode.get("e").asText();
			String n = targetKeyNode.get("n").asText();
			BigInteger publicExponent = new BigInteger(1, Decoders.BASE64URL.decode(e));
			BigInteger modulus = new BigInteger(1, Decoders.BASE64URL.decode(n));
			RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			key = keyFactory.generatePublic(keySpec);
		}
		return key;
	}

}
