import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;


public class Envelope implements java.io.Serializable {

	/**
	 *
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	private byte[] HMAC;

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
		return HMAC;
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

			HMAC = new HMAC().calculateHmac(sk, out.toByteArray());
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

			if(Arrays.compare(tempHMAC, HMAC) != 0){
				return false;
			}
			return true;

		} catch (Exception e) {
			System.err.println("This message should never appear.");
		}

		return false;
	}
}
