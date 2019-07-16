import java.io.*;
import java.security.*;
import java.util.ArrayList;


public class Envelope implements java.io.Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	private byte[] signature;
	
	public Envelope(String text)
	{
		msg = text;
	}
	
	public String getMessage()
	{
		return msg;
	}
	
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}

	public byte[] getSignature() {
		return signature;
	}
	
	public void addObject(Object object)
	{
		objContents.add(object);
	}

	public void sign(PrivateKey sk) {
		try {
			MessageDigest d = MessageDigest.getInstance("SHA-256");
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(out);

			os.writeObject(msg);

			for (Object o : objContents) {
				os.writeObject(o);
			}

			byte[] hash = d.digest(out.toByteArray());

			signature = new RSA().generatePkcs1Signature(
				sk, d.digest(out.toByteArray()));

			System.out.print("Hash (sign)");
			for (byte b : hash)
				System.out.printf("%02x ", b);
			System.out.println("");
			
		} catch (Exception e) {
			System.err.println("This message should never appear.");
		}
	}

	public boolean verify(PublicKey pk) {
		try {
			MessageDigest d = MessageDigest.getInstance("SHA-256");
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(out);

			os.writeObject(msg);

			for (Object o : objContents) {
				os.writeObject(o);
			}

			byte[] hash = d.digest(out.toByteArray());

			System.out.print("Hash (verify)");
			for (byte b : hash)
				System.out.printf("%02x ", b);
			System.out.println("");

			return new RSA().verifyPkcs1Signature(
				pk, hash, signature);
			
		} catch (Exception e) {
			System.err.println("This message should never appear.");
		}

		return false;
	}
}
