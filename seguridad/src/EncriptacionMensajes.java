import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.encodeBase64;

/**
 * Clase encargada de ejecutar el algoritmo AES para encriptar los mensajes.
 * @author Miguel Isaza, Steven Montealegre, Cristian Morales
 *
 */
public class EncriptacionMensajes {

	// Definici�n del tipo de algoritmo a utilizar (AES)
	private final static String AES = "AES";
	
	// Definici�n del modo de cifrado a utilizar (AES CBC de 128 bits)
	private final static String TIPOCIFRADO = "AES/CBC/PKCS5Padding";

	/**
	 * M�todo que recibe una llave y un vector de inicializaci�n y el texto a cifrar
	 * @param key, la llave a utilizar
	 * @param iv, vector de inicializaci�n a usar
	 * @param texto, texto a cifrar
	 * @return el texto cifrado
	 * @throws Exception
	 */
	public static String encriptar(String key, String iv, String textoDesencriptado) throws Exception {
		Cipher cipher = Cipher.getInstance(TIPOCIFRADO);
		SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), AES);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
		byte[] encriptado = cipher.doFinal(textoDesencriptado.getBytes());
		String cifrado = new String(encodeBase64(encriptado));
		return cifrado;
	}

	/**
	 * M�todo encargado de desencriptar un texto cifrado
	 * @param key, la llave a usar
	 * @param iv, el vector de inicializaci�n
	 * @param encrypted, texto encriptado
	 * @return El texto descenriptado
	 * @throws Exception
	 */
	public static String desencriptar(String key, String iv, String textoEncriptado) throws Exception {
		Cipher cipher = Cipher.getInstance(TIPOCIFRADO);
		SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), AES);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
		byte[] enc = decodeBase64(textoEncriptado);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
		byte[] decrypted = cipher.doFinal(enc);
		String descifrado = new String(decrypted);
		return descifrado;
	}

}