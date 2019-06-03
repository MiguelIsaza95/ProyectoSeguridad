import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64;

public class EncriptacionMensajes {

	// Definición del tipo de algoritmo a utilizar (AES, DES, RSA)
	private final static String AES = "AES";
	// Definición del modo de cifrado a utilizar
	private final static String TIPOCIFRADO = "AES/CBC/PKCS5Padding";

	public static String encriptar(String key, String iv, String cleartext) throws Exception {
		Cipher cipher = Cipher.getInstance(TIPOCIFRADO);
		SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), AES);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
		byte[] encrypted = cipher.doFinal(cleartext.getBytes());
		return new String(encodeBase64(encrypted));
	}

	public static String desencriptar(String key, String iv, String encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance(TIPOCIFRADO);
		SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), AES);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
		byte[] enc = decodeBase64(encrypted);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
		byte[] decrypted = cipher.doFinal(enc);
		return new String(decrypted);
	}

}