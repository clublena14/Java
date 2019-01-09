import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import com.ingrian.security.nae.IngrianProvider;
import com.ingrian.security.nae.KeyInfoData;

public class co_bmt2 {

	public static void main(String[] args) {
		

		// Input String for Encryption
		enc("test");

		// Input String for Decryption
		dec("1000202D0BEF1D5146B6A3D71C3421229B6A3D");

		// 1000202D0BEF1D5146B6A3D71C3421229B6A3D
		// 1000201EA9242DBED43D5EC98C550CF892A2CB

	}

	public static String enc(String encobject) {

		String result = "";

		try {

			// Initialize
			NAESession session = NAESession.getSession("shpark", "Oncrew1!".toCharArray());
			SecureRandom sr = SecureRandom.getInstance("IngrianRNG", "IngrianProvider");
			byte[] iv = new byte[16];
			iv = IngrianProvider.hex2ByteArray(NAEKey.getSecretKey("test", session).getDefaultIV());
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
			SecretKey key = NAEKey.getSecretKey("test", session);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

			// Do Encryption
			byte[] ciphertext = cipher.doFinal(IngrianProvider.toByteArray(encobject));

			// byte[] -> HexString
			result = IngrianProvider.byteArray2Hex(ciphertext);

			// Show Result
			System.out.println("Encryption Input value !! : " + encobject);
			System.out.println("Encryption result!! : " + result);
			System.out.println("=================================================");
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
			int Version = NAEKey.getSecretKey("test", session).getKeyVersion();
			
			KeyInfoData[] KeyInfoArray = NAEKey.getSecretKey("test", session).getKeyInfoData(true);
			String ivstr = KeyInfoArray[(Version - 1)].getDefaultIV();		
			iv = IngrianProvider.hex2ByteArray(ivstr);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "IngrianProvider");
			SecretKey key1 = NAEKey.getSecretKey("test" + "#"+ Version, session);
			cipher.init(Cipher.DECRYPT_MODE, key1, new IvParameterSpec(iv));

			// Do Decryption
			byte[] plaintext = cipher.doFinal(IngrianProvider.hex2ByteArray(decobject));

			// byte[] -> String
			result = IngrianProvider.toString(plaintext);

			// Show Result

			System.out.println("Decryption Value : " + decobject);
			System.out.println("Decryption Result!! : " + result);

			System.out.println("=================================================");

		} catch (Exception e) {
			System.out.println("The Cause is " + e.getMessage() + ".");
			e.printStackTrace();
		}
		return result;
	}
}