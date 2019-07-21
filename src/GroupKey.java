import java.io.Serializable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class GroupKey implements Serializable {
	public SecretKey encrypt_key;
	public SecretKey verify_key;
	public int current_version;

	public GroupKey(byte[] lts, int version)
		throws NoSuchAlgorithmException
	{
		MessageDigest d = MessageDigest.getInstance("SHA-256");

		String s = new String(lts) + version + "encrypt";
		encrypt_key = new SecretKeySpec(d.digest(s.getBytes()), "AES");

		s = new String(lts) + version + "verify";
		verify_key = new SecretKeySpec(d.digest(s.getBytes()), "HMacSHA256");
	}
}
