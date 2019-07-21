/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import java.security.MessageDigest;

public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;

	private byte[] agreedKeyFSDH;
	private PublicKey userPubKey;

	private byte[] HMACkey;
	private Long seqnum;

	public FileThread(Socket _socket, FileServer my_fs)
	{
		socket = _socket;
		this.my_fs = my_fs;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response = null;

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());
				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES")){

					if (!e.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						break;
					}

					// Decrypt message
					AES aes = new AES();
					byte[][] encrypted = (byte[][])e.getObjContents().get(0);
					Token t = (Token)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
					encrypted = (byte[][])e.getObjContents().get(1);

					Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
					if (!recv_seq.equals(seqnum)) {
						System.out.println("The message has been reordered!");
						socket.close();
						break;
					}
					seqnum++;
					byte[][] enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);

					// check expiration
					if (checkTokenExpiration(t)){
						System.out.println("token expired keep checking");
						Envelope msgToSend = new Envelope("Expired");
						msgToSend.addObject(enc_seqnum);
						msgToSend.sign(HMACkey);
						output.writeObject(msgToSend);
						seqnum++;
						break;
					}

					if (!checkFSPublicKey(t.getFsPublicKey())){

						System.out.println("This token doesn't have permission for this file server");
						Envelope msgToSend = new Envelope("invalid_fs_pk");
						msgToSend.addObject(enc_seqnum);
						msgToSend.sign(HMACkey);
						output.writeObject(msgToSend);
						seqnum++;
						break;
					}
					// Verify token
					if (t == null || !t.verifyHash(my_fs.getGroupPublicKey()))
					{
						response = new Envelope("FAIL-BADTOKEN");
						System.out.println("Error: bad token. System Exit");
					}


					else { // Do the actual stuff
						List<String> files = new ArrayList<String>();

						for (ShareFile sf : FileServer.fileList.getFiles()) {
							if (t.getGroups().contains(sf.getGroup()))
								files.add(sf.getPath());
						}

						// Send response
						encrypted = aes.cfbEncrypt(agreedKeyFSDH, files);
						if (encrypted != null) {
							response = new Envelope("OK");
							response.addObject(encrypted);
						} else {
							System.out.println("Failed to encrypt response!");
							response = new Envelope("FAIL");
						}
					}
					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					output.writeObject(response);
					seqnum++;
				}

				if(e.getMessage().equals("UPLOADF")){

					if (!e.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
 						break;
					}

					if(e.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().contains(null)) {
							response = new Envelope("FAIL-BADPATH");
						}
						else {
							AES aes = new AES();
							String remotePath = (String)aes.cfbDecrypt(agreedKeyFSDH,
									(byte[][])e.getObjContents().get(0));
							String group = (String)aes.cfbDecrypt(agreedKeyFSDH,
								(byte[][])e.getObjContents().get(1));
							Token yourToken = (Token)aes.cfbDecrypt(agreedKeyFSDH,
								(byte[][])e.getObjContents().get(2));

							byte[][] encrypted = (byte[][])e.getObjContents().get(3);
							Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									break;
								}
								seqnum++;
								byte[][] enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);

								// check expiration
								if (checkTokenExpiration(yourToken)){
									System.out.println("token expired keep checking");
									Envelope msgToSend = new Envelope("Expired");
									msgToSend.addObject(enc_seqnum);
									msgToSend.sign(HMACkey);
									output.writeObject(msgToSend);
									seqnum++;
									break;
								}

								if (!checkFSPublicKey(yourToken.getFsPublicKey())){

									System.out.println("This token doesn't have permission for this file server");
									Envelope msgToSend = new Envelope("invalid_fs_pk");
									msgToSend.addObject(enc_seqnum);
									msgToSend.sign(HMACkey);
									output.writeObject(msgToSend);
									seqnum++;
									break;
								}

							if (!yourToken.verifyHash(my_fs.getGroupPublicKey())) {
								System.out.println("Error: Invalid token signature");
								response = new Envelope("FAIL-BADTOKEN");
							}
							else if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								response.addObject(enc_seqnum);
								response.sign(HMACkey);
								output.writeObject(response);
								seqnum++;

								e = (Envelope)input.readObject();
								encrypted = (byte[][])e.getObjContents().get(2);
								recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									break;
								}
								seqnum++;
								enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);

								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])aes.cfbDecrypt(agreedKeyFSDH, (byte[][]) e.getObjContents().get(0)), 0,
										(Integer)aes.cfbDecrypt(agreedKeyFSDH, (byte[][])e.getObjContents().get(1)));
									response = new Envelope("READY"); //Success
									response.addObject(enc_seqnum);
									response.sign(HMACkey);
									output.writeObject(response);
									seqnum++;

									e = (Envelope)input.readObject();
									//System.out.println(e.getMessage() + " size: " + e.getObjContents().size());
									encrypted = (byte[][])e.getObjContents().get(e.getObjContents().size()-1);
									recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
									if (!recv_seq.equals(seqnum)) {
										System.out.println("The message has been reordered!");
										socket.close();
										proceed = false;
										break;
									}
									seqnum++;
									enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);
								}

								System.out.println("\tdone reading chunks");
								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyFSDH, seqnum);
					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					output.writeObject(response);
					seqnum++;

				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					if (!e.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					AES aes = new AES();
					String remotePath = (String)aes.cfbDecrypt(agreedKeyFSDH, (byte[][])e.getObjContents().get(0));
					Token t = (Token)aes.cfbDecrypt(agreedKeyFSDH, (byte[][])e.getObjContents().get(1));
					byte[][] encrypted = (byte[][])e.getObjContents().get(2);
					Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
					if (!recv_seq.equals(seqnum)) {
						System.out.println("The message has been reordered!");
						socket.close();
						proceed = false;
						break;
					}
					seqnum++;
					byte[][] enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);

					// check expiration
					if (checkTokenExpiration(t)){
						System.out.println("token expired keep checking");
						Envelope msgToSend = new Envelope("Expired");
						msgToSend.addObject(enc_seqnum);
						msgToSend.sign(HMACkey);
						output.writeObject(msgToSend);
						seqnum++;
						break;
					}

					if (!checkFSPublicKey(t.getFsPublicKey())){

						System.out.println("This token doesn't have permission for this file server");
						Envelope msgToSend = new Envelope("invalid_fs_pk");
						msgToSend.addObject(enc_seqnum);
						msgToSend.sign(HMACkey);
						output.writeObject(msgToSend);
						seqnum++;
						break;
					}

					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);

					if (!t.verifyHash(my_fs.getGroupPublicKey())) {
						System.out.println("Error: Invalid token signature");
						e = new Envelope("ERROR_BADTOKEN");
						e.addObject(enc_seqnum);
						e.sign(HMACkey);
						output.writeObject(e);
						seqnum++;
					}
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						e.addObject(enc_seqnum);
						e.sign(HMACkey);
						output.writeObject(e);
						seqnum++;
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						e.addObject(enc_seqnum);
						e.sign(HMACkey);
						output.writeObject(e);
						seqnum++;
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							e.addObject(enc_seqnum);
							e.sign(HMACkey);
							output.writeObject(e);
							seqnum++;
						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");
								}

								e.addObject(aes.cfbEncrypt(agreedKeyFSDH, buf));
								e.addObject(aes.cfbEncrypt(agreedKeyFSDH, new Integer(n)));
								e.addObject(enc_seqnum);
								e.sign(HMACkey);

								output.writeObject(e);
								seqnum++;

								e = (Envelope)input.readObject();
								if (!e.verify(HMACkey)) {
									System.out.println("The message has been modified!");
									socket.close();
									proceed = false;
									break;
								}
								encrypted = (byte[][])e.getObjContents().get(0);
								recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;
								enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);

							}
							while (fis.available()>0);

							fis.close();

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{
								System.out.println("\tdone reading chunks");
								e = new Envelope("EOF");
								e.addObject(enc_seqnum);
								e.sign(HMACkey);
								output.writeObject(e);
								seqnum++;

								e = (Envelope)input.readObject();
								if (!e.verify(HMACkey)) {
									System.out.println("The message has been modified!");
									socket.close();
									proceed = false;
									break;
								}
								encrypted = (byte[][])e.getObjContents().get(0);
								recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;
								enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);


								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					if (!e.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					AES aes = new AES();
					String remotePath = (String)aes.cfbDecrypt(agreedKeyFSDH,
						(byte[][])e.getObjContents().get(0));
					Token t = (Token)aes.cfbDecrypt(agreedKeyFSDH,
						(byte[][])e.getObjContents().get(1));
					byte[][] encrypted = (byte[][])e.getObjContents().get(2);
					Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
					if (!recv_seq.equals(seqnum)) {
						System.out.println("The message has been reordered!");
						socket.close();
						proceed = false;
						break;
					}
					seqnum++;
					byte[][] enc_seqnum = aes.cfbEncrypt(agreedKeyFSDH, seqnum);

					// check expiration
					if (checkTokenExpiration(t)){
						System.out.println("token expired keep checking");
						Envelope msgToSend = new Envelope("Expired");
						msgToSend.addObject(enc_seqnum);
						msgToSend.sign(HMACkey);
						output.writeObject(msgToSend);
						seqnum++;
						break;
					}

					if (!checkFSPublicKey(t.getFsPublicKey())){

						System.out.println("This token doesn't have permission for this file server");
						Envelope msgToSend = new Envelope("invalid_fs_pk");
						msgToSend.addObject(enc_seqnum);
						msgToSend.sign(HMACkey);
						output.writeObject(msgToSend);
						seqnum++;
						break;
					}

					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (!t.verifyHash(my_fs.getGroupPublicKey())) {
						System.out.println("Error: Invalid token signature.");
						e = new Envelope("ERROR_BADTOKEN");
					}
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{

							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					e.addObject(enc_seqnum);
					e.sign(HMACkey);
					output.writeObject(e);
					seqnum++;

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}

				else if (e.getMessage().equals("SecureSession")) {
					response = establishSecureSessionWithClient(e);
					if (response.getMessage().equals("OK")) {
						System.out.println("secure session established");
						output.writeObject(response);

					} else {
						System.out.println("couldn't established secure connections");
						output.writeObject(response);
					}
				}

				else if(e.getMessage().equals("Challange")){
					byte[][] sharedKeyEncryptedN = (byte[][]) e.getObjContents().get(0);
					//remove shared key encryption
					AES aes = new AES();
					SecretKeySpec secretKey = new SecretKeySpec(agreedKeyFSDH,"AES");
					//System.out.println("FS shared: " + agreedKeyFSDH);
					byte[] publicKeyEncryptedN = new byte[0];

					RSA rsa = new RSA();
					byte[] msgByte = new byte[0];
					boolean fail = false;
					try {
						publicKeyEncryptedN = aes.cfbDecrypt(secretKey, sharedKeyEncryptedN[0], sharedKeyEncryptedN[1]);

						//decrypt again to remove public key encryption
						msgByte = rsa.cfbDecrypt(my_fs.privateKeySig, publicKeyEncryptedN);
					} catch (Exception ex) {
						ex.printStackTrace();
						e = new Envelope("FAIL");
						fail = true;
					}

					//now we have bigint n in byte[], we want to send it back encypted
					//with the shared key
					byte[][] encyrptedN = new byte[0][0];
					if(fail == false){
						try {
							encyrptedN = aes.cfbEncrypt(secretKey, msgByte);
							e = new Envelope("OK");
						} catch (Exception ex) {
							ex.printStackTrace();
							e = new Envelope("FAIL");
						}
					}

					e.addObject(encyrptedN);
					output.writeObject(e);
				}

				else if(e.getMessage().equals("EstablishSeqNum")){
					if (!e.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					AES aes = new AES();
					byte[][] encrypted =
						(byte[][])e.getObjContents().get(0);

					seqnum = (Long)aes.cfbDecrypt(agreedKeyFSDH, encrypted);
					seqnum++;

					response = new Envelope("OK");
					response.addObject(aes.cfbEncrypt(agreedKeyFSDH, seqnum));
					response.sign(HMACkey);
					output.writeObject(response);
					seqnum++;
				}


			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private boolean checkTokenExpiration(Token t) {
		if (MyTime.isExpired(t.getExpiredTime())){
			System.out.println("Your token is expired. Please re-login");
			return true;
		}
		return false;
	}

	private boolean checkFSPublicKey(PublicKey k){
		byte[] k1 = new byte[0];
		byte[] k2 = new byte[0];
		try {
			 k1  =  serialize(my_fs.publicKeyVir);
			 k2  =  serialize(k);

		} catch (IOException e) {
			e.printStackTrace();
		}
		//System.out.println(Arrays.toString(k1));
		//System.out.println(Arrays.toString(k2));
		System.out.println(Arrays.equals(k1,k2));
		return Arrays.equals(k1,k2);
	}

	public  byte[] serialize(Serializable obj) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream os = new ObjectOutputStream(out);
		os.writeObject(obj);
		return out.toByteArray();
	}

	private Envelope establishSecureSessionWithClient(Envelope message) {

		userPubKey = (PublicKey) message.getObjContents().get(0);
		PublicKey clientDHPK = (PublicKey) message.getObjContents().get(1);
		byte [] sigbytes = (byte[]) message.getObjContents().get(2);

		RSA rsa = new RSA();
		byte [] bytesMsg = new byte[0];
		try {
			bytesMsg = rsa.serialize(clientDHPK);
		} catch (IOException e) {
			e.printStackTrace();
		}
		//PublicKey pk = my_fs.clientCertificates.get(username);

		try {
			if (rsa.verifyPkcs1Signature(userPubKey,bytesMsg,sigbytes)){
				DH dh = new DH();
				KeyPair keyPairFSDH = dh.generateKeyPair(((DHPublicKey)clientDHPK).getParams());
				agreedKeyFSDH  =  dh.initiatorAgreementBasic(keyPairFSDH.getPrivate(),clientDHPK);

				try{
					//generate 2nd DH key based of first one for HMACs
					MessageDigest d = MessageDigest.getInstance("SHA-256");
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					ObjectOutputStream os = new ObjectOutputStream(out);
					HMACkey = Arrays.copyOfRange(d.digest(out.toByteArray()), 0, 16);

				}catch(Exception e){
					e.printStackTrace();
					System.exit(-1);
				}

				byte [] sig = new byte[0];
				Envelope msg = new Envelope("OK");
				try {
					sig =rsa.generatePkcs1Signature(my_fs.privateKeySig, rsa.serialize(keyPairFSDH.getPublic()));
				} catch (IOException e) {
					e.printStackTrace();
				}
				msg.addObject(sig);
				msg.addObject(keyPairFSDH.getPublic());
				return msg;
			}
		} catch(GeneralSecurityException e){
			e.printStackTrace();
		}
		return new Envelope("FAIL");
	}
}
