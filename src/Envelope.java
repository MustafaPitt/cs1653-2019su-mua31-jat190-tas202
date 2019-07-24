import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.SecretKey;


public class Envelope implements Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private byte[][] ciphermsg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	private byte[] hmac;
	private byte[] sharedkey;

	public Envelope(String text)
	{
		msg = text;
	}

	public Envelope(String text, byte[] sk)
	{
		ciphermsg = new AES().cfbEncrypt(sk, text.getBytes());
		sharedkey = sk;
	}

	public String getMessage()
	{

		if(sharedkey == null) {
			//System.out.println("msg= " + msg);
			return msg;
		}
		//System.out.println("ciphermsg= " + ciphermsg);
		String ret = new String((byte[])(new AES().cfbDecrypt(sharedkey, ciphermsg)));
		//System.out.println("ret= " + ret);

		return ret;
	}

	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public byte[] getSignature() {
		return hmac;
	}

	public void addObject(Object object)
	{
		objContents.add(object);
	}

	public void sign(byte[] sk) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(out);

			os.writeObject(msg);
			for (Object o : objContents) {
				os.writeObject(o);
			}

			hmac = new HMAC().calculateHmac(sk, out.toByteArray());
			// System.out.print("\tHMAC(sign): ");
			// for(byte b : HMAC)
			// 	System.out.printf("%02x ", b);
			// System.out.println("");

		} catch (Exception e) {
			System.err.println("This message should never appear.");
		}
	}

	public boolean verify(byte[] sk) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(out);

			os.writeObject(msg);

			for (Object o : objContents) {
				os.writeObject(o);
			}

			byte[] tempHMAC = new HMAC().calculateHmac(sk, out.toByteArray());
			// System.out.print("\tHMAC(verify): ");
			// for(byte b : tempHMAC)
			// 	System.out.printf("%02x ", b);
			// System.out.println("");

			return Arrays.equals(tempHMAC,hmac);

		} catch (Exception e) {
			System.err.println("This message should never appear.");
		}

		return false;
	}
}
