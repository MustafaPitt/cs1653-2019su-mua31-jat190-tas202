import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Security;

public class AES {
    AES(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public SecretKey generateKey()
            throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }


     byte[][] cfbEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }
    byte[] cfbDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

	byte[][]cfbEncrypt(byte[] key, Object data) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream os = new ObjectOutputStream(out);
		byte[][] encrypted;

		SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
		try {
			os.writeObject(data);
			encrypted = cfbEncrypt(key, out.toByteArray());
			return encrypted;
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return null;
		}
	}

	Object cfbDecrypt(byte[] key, byte[][] ciphertext) {
		byte[] objbytes;
		SecretKeySpec secretKey = new SecretKeySpec(key ,"AES");

		try {
			objbytes = cfbDecrypt(key, ciphertext[0], ciphertext[1]);
			ByteArrayInputStream in = 
			ObjectInputStream is = new ObjectInputStream(
				new ByteArrayInputStream(objbytes));
			return is.readObject();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return null;
		}
	}

    String bytesToString(byte[] input){
        StringBuilder sb = new StringBuilder();
        for(byte b : input) {
            sb.append((char)b);
        }
        return sb.toString();
    }

    public static void main (String [] args) throws GeneralSecurityException {
//        AES aes = new AES();
//        SecretKey secretKey =  aes.generateKey();
//        String plainText = "ABC mustafa al azzawi";
//        System.out.println("Secret key : " + Arrays.toString(secretKey.getEncoded()));
//        byte [][] cipherTextWithIV = cfbEncrypt(secretKey,plainText.getBytes());
//        System.out.println ("iv:  " +bytesToString(cipherTextWithIV[0]));
//        System.out.println("cipher: " + bytesToString(cipherTextWithIV[1]));
//
//        byte [] decPlainText =  cfbDecrypt(secretKey,cipherTextWithIV[0],cipherTextWithIV[1]);
//        System.out.println("Message after decrypt: " + bytesToString(decPlainText));


    }


}
