import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import com.ingrian.security.nae.IngrianProvider;

public class co_bmt {

	public static void main(String[] args) {

		// Input String for Encryption
		enc("lena");

		// Input String for Decryption
		dec("1000102D0CD0D592F79B6801CAF9D704227836");
	}

	public static String enc(String encobject) {

		String result = "";

		try {

			// Initialize
			NAESession session = NAESession.getSession("shpark", "Oncrew1!".toCharArray());
			// SecureRandom sr = SecureRandom.getInstance("IngrianRNG", "IngrianProvider");
			byte[] iv = new byte[16];
			iv = IngrianProvider.hex2ByteArray("8BDB9F2D31A00BA3AC69BABC1B204D2E");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
			SecretKey key = NAEKey.getSecretKey("test", session);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

			// add
			System.out.println("==================== Cut Line ====================");
			System.out.println();
			// getAlgorithm
			String Algorithm = NAEKey.getSecretKey("test", session).getAlgorithm();
			System.out.println("Algorithm : " + Algorithm);
			// getFingerprint
			String fingerprint = NAEKey.getSecretKey("test", session).getFingerprint();
			System.out.println("fingerprint : " + fingerprint);
			// getDefaultIV
			System.out.println("DefaultIV : " + NAEKey.getSecretKey("test", session).getDefaultIV());
			// getAllAlgorithms
			String[] AllAlgorithm = NAEKey.getSecretKey("test", session).getAllAlgorithms();
			for (int k = 0; k < AllAlgorithm.length; k++) {
				System.out.println(k + "'s Algorithm : " + AllAlgorithm[k]);
			}
			// getKeyVersion
			int keyversion = NAEKey.getSecretKey("test", session).getKeyVersion();
			System.out.println("KeyVersion : " + keyversion);
			// getAllKeyVersions
			int AllKeyVersion = NAEKey.getSecretKey("test", session).getAllKeyVersions();
			System.out.println("AllKeyVersion : " + AllKeyVersion);
			// is_encryptAll
			System.out.println("is_encryptAll : " + NAEKey.getSecretKey("test", session).is_encryptAll());
			System.out.println("==================== Cut Line ====================");

			// Do Encryption
			byte[] ciphertext = cipher.doFinal(IngrianProvider.toByteArray(encobject));

			// byte[] -> HexString
			result = IngrianProvider.byteArray2Hex(ciphertext);

			// Show Result
			System.out.println("Encryption result!! : " + result);

		} catch (Exception e) {
			System.out.println("The Cause is " + e.getMessage() + ".");
			e.printStackTrace();
		}

		return result;

	}

	public static String dec(String decobject) {

		String result = "";

		try {

			// Initialize
			NAESession session = NAESession.getSession("shpark", "Oncrew1!".toCharArray());
			byte[] iv = new byte[16];
			iv = IngrianProvider.hex2ByteArray("8BDB9F2D31A00BA3AC69BABC1B204D2E");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
			SecretKey key1 = NAEKey.getSecretKey("test", session);
			cipher.init(Cipher.DECRYPT_MODE, key1, new IvParameterSpec(iv));

			// Do Decryption
			byte[] plaintext = cipher.doFinal(IngrianProvider.hex2ByteArray(decobject));

			// byte[] -> String
			result = IngrianProvider.toString(plaintext);

			// Show Result
			System.out.println("Decryption Result!! : " + result);

		} catch (Exception e) {
			System.out.println("The Cause is " + e.getMessage() + ".");
			e.printStackTrace();
		}
		return result;
	}
}
