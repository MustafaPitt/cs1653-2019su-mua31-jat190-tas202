import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output = null;
	protected ObjectInputStream input = null;

	public boolean connect(final String server, final int port) {
		try {
			sock = new Socket(server,port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
//			Envelope msg = new Envelope("GET");
//			output.writeObject(msg);

		} catch (IOException e) {
			e.printStackTrace();
		}
		return isConnected();
	}

	public boolean isConnected() {
		return sock != null && sock.isConnected();
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}



//	static class SecureSessionParameters implements Serializable {
//		public DHParameterSpec dhParameterSpec;
//		public PublicKey publicKey;
//		public SecureSessionParameters(DHParameterSpec dhParameterSpec, PublicKey publicKey) {
//			this.dhParameterSpec = dhParameterSpec;
//			this.publicKey = publicKey;
//		}
//	}
}
