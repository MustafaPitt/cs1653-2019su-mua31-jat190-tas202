/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */


// import com.sun.istack.internal.Nullable;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;


@SuppressWarnings("ALL")
public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	// store all client public keys to verifiy their connections <username, public key>
	public HashMap <String,PublicKey> clientCertifcates;

	private KeyPair keyPair;
	public PrivateKey privateKeySig;
	public PublicKey publicKeyVir;

	public SecretKey hashPWSecretKey;

	// to manage group members => each group map to a list contains members belong to key group
	public HashMap<String,List<String>> groupMembers ;
	private DHParameterSpec dhParameterSpec;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));


		//Open required file , userlist , groupMemebers, and required keys
		try
		{
			// open user list
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();

			// open group memeber
			fis = new FileInputStream("GroupMembers.bin");
			groupStream = new ObjectInputStream(fis);
			groupMembers = (HashMap) groupStream.readObject();

			// open private key file
			fis = new FileInputStream("rsaPrivateKeySig.bin");
			groupStream = new ObjectInputStream(fis);
			privateKeySig = (PrivateKey) groupStream.readObject();

			// open hash secret key for passwords
			fis = new FileInputStream("hashPWSecretKey.bin");
			groupStream = new ObjectInputStream(fis);
			hashPWSecretKey = (SecretKey) groupStream.readObject();

			// open hash secret key for passwords
			fis = new FileInputStream("clientCertificates.bin");
			groupStream = new ObjectInputStream(fis);
			clientCertifcates = (HashMap<String, PublicKey>) groupStream.readObject();

			System.out.println("DBG  show all users in the group servers");
			userList.showAllUsers();
			fis.close();
		}

		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();


			try {
				System.out.println("Generating Public and private keys for Signature /Verifier. Don't share group server private key");
				System.out.println("Generating Public and private keys for Encryption/ Decryption. Don't share group server private key");
				RSA rsa = new RSA();
				keyPair = rsa.generateKeyPair();
			  privateKeySig = keyPair.getPrivate();
			  publicKeyVir = keyPair.getPublic();


			} catch (GeneralSecurityException e1) {
				e1.printStackTrace();
			}

			try {
				System.out.println("Genrating password Hashing Secret key");
				HMAC hmac = new HMAC();
				hashPWSecretKey = hmac.generateKey();
			} catch (GeneralSecurityException e1) {
				e1.printStackTrace();
			}




			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			groupMembers = new HashMap<>();  // init a group members
			clientCertifcates = new HashMap<>(); // init client certificates
			String pw = PW.generate(8); // generate pw of length n
			byte [] pwHash = new byte[256];
			try {
				pwHash = HMAC.calculateHmac(hashPWSecretKey,pw.getBytes());
			} catch (GeneralSecurityException e1) {
				e1.printStackTrace();
				System.exit(1);
			}

			System.out.println("Login Info");
			System.out.println("Username: " + username);
			System.out.println("Password: " + pw);

			userList.addUser(username, new String(pwHash));
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			List<String> members = new ArrayList<>();
			// add username to group member
			members.add(username);
			groupMembers.put("ADMIN",members);
			// create a new user "admin " public and private key. Save the public in the client certificates hashmap
			//and give the private to the client
			PublicKey clientPublicKey = keyPair.getPublic();
			PrivateKey clientPrivateKey = keyPair.getPrivate();
			clientCertifcates.put(username,clientPublicKey);
			//generate a client certificate and store in client certificates



			ObjectOutputStream outStreamGroup;
			try {
				// save the private key and give it to the client
				outStreamGroup = new ObjectOutputStream(new FileOutputStream(username+"_clientPrivate.bin"));
				outStreamGroup.writeObject(clientPrivateKey);
				outStreamGroup.close();
				// save user name and generated password to text file

				BufferedWriter writer = new BufferedWriter(new FileWriter(username + "_PW.txt", true));
				writer.append("username: " + username);
				writer.append("\n");
				writer.append("password: "+ pw);
				writer.close();


				// save clients cerificates
				outStreamGroup = new ObjectOutputStream(new FileOutputStream("clientCertificates.bin"));
				outStreamGroup.writeObject(clientCertifcates);
				outStreamGroup.close();

				// save group server private key signature
				outStreamGroup = new ObjectOutputStream(new FileOutputStream("rsaPrivateKeySig.bin"));
				outStreamGroup.writeObject(privateKeySig);
				outStreamGroup.close();

				// save group server public key verifier
				outStreamGroup = new ObjectOutputStream(new FileOutputStream("rsaPublicKeyVir.bin"));
				outStreamGroup.writeObject(publicKeyVir);
				outStreamGroup.close();

				// save group server hashing secret key
				outStreamGroup = new ObjectOutputStream(new FileOutputStream("hashPWSecretKey.bin"));
				outStreamGroup.writeObject(hashPWSecretKey);
				outStreamGroup.close();


			}
			catch (Exception ex){ ex.printStackTrace();}
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				System.err.println("waiting for connection");
				sock = serverSock.accept();
				System.err.println("got connection");
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		ObjectOutputStream outStreamGroup;

		try
		{
			// save userList
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream.close();

			// save GroupMembers
			outStreamGroup = new ObjectOutputStream(new FileOutputStream("GroupMembers.bin"));
			outStreamGroup.writeObject(my_gs.groupMembers);
			outStreamGroup.close();


		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(100000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					outStream.close();
					outStream = new ObjectOutputStream(new FileOutputStream("GroupMembers.bin"));
					outStream.writeObject(my_gs.groupMembers);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}

			FileInputStream fis = null;
			try {
				fis = new FileInputStream("clientCertificates.bin");
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			}
			ObjectInputStream groupStream = null;
			try {
				groupStream = new ObjectInputStream(fis);
			} catch (IOException e) {
				e.printStackTrace();
			}
			try {
				my_gs.clientCertifcates = (HashMap<String, PublicKey>) groupStream.readObject();
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
			}
		}while(true);
	}
}
