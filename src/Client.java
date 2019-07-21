import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.List;

public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output = null;
	protected ObjectInputStream input = null;

	protected HashMap<String, List<GroupKey>> keychain;

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

	boolean isConnected() {
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


//	public abstract HashMap<String, List<SecretKey>> getUserGroupsKeys(UserToken token);
//	public abstract boolean getUserGroupsKeys(UserToken token);
}
