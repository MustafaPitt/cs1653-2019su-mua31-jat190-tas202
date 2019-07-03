/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.*;

public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static FileList fileList;

	HashMap <String,PublicKey> clientCertificates;

	private KeyPair keyPair;
	PrivateKey privateKeySig;
	private PublicKey publicKeyVir;

	FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	FileServer(int _port) {
		super(_port, "FilePile");
	}

	public PublicKey getGroupPublicKey() {
		return publicKeyVir;
	}

	public void start() {
		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			fileList = new FileList();

		}
		catch(IOException | ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		// open Client Certificates
		try{
			FileInputStream fis = new FileInputStream("clientCertificates.bin");
			fileStream = new ObjectInputStream(fis);
			clientCertificates = (HashMap<String, PublicKey>) fileStream.readObject();
			if (clientCertificates == null) {
				System.out.println("System will shutdown. Couldn't verify client certificates");
				System.exit(-1);
			}
		}catch (FileNotFoundException ignore){
			System.out.println("System Couldn't open clients certificates. The system will shutdown");
			System.exit(-1);
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		//try to open rsa files
		try{
			FileInputStream fis = new FileInputStream(super.port + "FS_rsaPublic.bin");
			fileStream = new ObjectInputStream(fis);
			publicKeyVir = (PublicKey)fileStream.readObject();

			fis = new FileInputStream(super.port + "FS_rsaPrivate.bin");
			fileStream = new ObjectInputStream(fis);
			privateKeySig = (PrivateKey)fileStream.readObject();
		}catch(FileNotFoundException e){
			System.out.println("rsa keys do not exist. Creating keys...");
			try{
				RSA rsa = new RSA();
				keyPair = rsa.generateKeyPair();
				privateKeySig = keyPair.getPrivate();
				publicKeyVir = keyPair.getPublic();
			} catch (GeneralSecurityException e1) {
				e1.printStackTrace();
			}

			ObjectOutputStream outStreamGroup;
			try {
				// save keys
				outStreamGroup = new ObjectOutputStream(new FileOutputStream(super.port + "FS_rsaPublic.bin"));
				outStreamGroup.writeObject(publicKeyVir);
				outStreamGroup.close();

				outStreamGroup = new ObjectOutputStream(new FileOutputStream(super.port + "FS_rsaPrivate.bin"));
				outStreamGroup.writeObject(privateKeySig);
				outStreamGroup.close();


			}catch(Exception ex){ ex.printStackTrace();}

			fileList = new FileList();

		}catch(Exception ex){ ex.printStackTrace();}

		try{
			FileInputStream fis = new FileInputStream("rsaPublicKeyVir.bin");
			fileStream = new ObjectInputStream(fis);
			publicKeyVir = (PublicKey)fileStream.readObject();
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("Group Server public key not found can't continue");
		}

		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");
		 }

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;

		try
		{
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock, this);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
		}while(true);
	}
}
