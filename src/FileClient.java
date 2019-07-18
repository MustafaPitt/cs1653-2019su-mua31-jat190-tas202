/* FileClient provides all the client functionality regarding the file server */

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.*;
import java.math.BigInteger;

public class FileClient extends Client implements FileClientInterface {

	private byte[] sharedKeyClientFS;
	private byte[] HMACkey;
	private Long seqnum;

	// pkSig is user's private key
	// userPubKey is user's public key
	// publicKeyFSrsa is file server's public key.
	public boolean connect(final String server, final int port,
		PrivateKey pkSig, PublicKey userPubKey, PublicKey publicKeyFSrsa){
		super.connect(server, port);
		//new code
		try {
			establishSecureSessionWithFS(port, pkSig, userPubKey, publicKeyFSrsa);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		if (!establishSequenceNumber()) {
			disconnect();
		}

		//server challange
		if(serverChallange(publicKeyFSrsa)){
			System.out.println("--File Server " + port + " is trusted.--");
		}else{
			System.out.println("--File Server " + port + " is NOT trusted.--");
			return false;
		}

		return isConnected();
	}

	public boolean delete(String filename, UserToken token) {
		AES aes = new AES();

		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(aes.cfbEncrypt(sharedKeyClientFS, remotePath));
	    env.addObject(aes.cfbEncrypt(sharedKeyClientFS, token));
			env.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));

			env.sign(HMACkey);

	    try {
				output.writeObject(env);
				seqnum++;


		    env = (Envelope)input.readObject();
				if (!env.verify(HMACkey)) {
					System.out.println("The message has been modified!");
					disconnect();
				}
				ArrayList<Object> temp = null;
				temp = env.getObjContents();
				Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
					(byte[][])temp.get(temp.size() - 1));

				//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
				if (!(recv_seq.equals(seqnum))) {
					System.out.println("The message has been reordered!");
					disconnect();
				}
				seqnum++;

				if (env.getMessage().compareTo("OK")==0) {
					System.out.printf("File %s deleted successfully\n", filename);
				}
				else {
					System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
					return false;
				}
			} catch (IOException e1) {
				e1.printStackTrace();
			} catch (ClassNotFoundException e1) {
				e1.printStackTrace();
			}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}

				File file = new File(destFile);
			    try {
					AES aes = new AES();


				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);

					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(aes.cfbEncrypt(sharedKeyClientFS, sourceFile));
					    env.addObject(aes.cfbEncrypt(sharedKeyClientFS, token));
							env.addObject(aes.cfbEncrypt(sharedKeyClientFS, seqnum));

							env.sign(HMACkey);
					    output.writeObject(env);
							seqnum++;

					    env = (Envelope)input.readObject();
							if (!env.verify(HMACkey)) {
								System.out.println("The message has been modified!");
								disconnect();
							}
							ArrayList<Object> temp = null;
							temp = env.getObjContents();
							Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
								(byte[][])temp.get(temp.size() - 1));

							//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
							if (!(recv_seq.equals(seqnum))) {
								System.out.println("The message has been reordered!");
								disconnect();
							}
							seqnum++;

							while (env.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])aes.cfbDecrypt(sharedKeyClientFS,
										(byte[][])env.getObjContents().get(0)), 0,
										(Integer)aes.cfbDecrypt(sharedKeyClientFS,
										(byte[][])env.getObjContents().get(1)));
									System.out.printf(".");
									env = new Envelope("DOWNLOADF"); //Success
									env.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));

									env.sign(HMACkey);
									output.writeObject(env);
									seqnum++;

									env = (Envelope)input.readObject();
									if (!env.verify(HMACkey)) {
										System.out.println("The message has been modified!");
										disconnect();
									}
									temp = env.getObjContents();
									recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
										(byte[][])temp.get(temp.size() - 1));

									//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
									if (!(recv_seq.equals(seqnum))) {
										System.out.println("The message has been reordered!");
										disconnect();
									}
									seqnum++;
							}
							fos.close();

						  if(env.getMessage().compareTo("EOF")==0) {
						    	 fos.close();
									System.out.printf("\nTransfer successful file %s\n", sourceFile);
									env = new Envelope("OK"); //Success
									env.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));
									env.sign(HMACkey);
									output.writeObject(env);
									seqnum++;
							}else {
									System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
									file.delete();
									return false;
							}

				    }else{
							System.out.printf("Error couldn't create file %s\n", destFile);
							return false;
				    }


			    } catch (IOException e1) {

			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;


				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");

			 // Encrypt the token
			 AES aes = new AES();
			 byte[][] token_encrypted = aes.cfbEncrypt(sharedKeyClientFS, token);

			 message.addObject(token_encrypted); //Add requester's token
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));

 		   message.sign(HMACkey);
			 output.writeObject(message);
			 seqnum++;

			 e = (Envelope)input.readObject();
			 if (!e.verify(HMACkey)) {
				 System.out.println("The message has been modified!");
				 disconnect();
			 }
			 ArrayList<Object> temp = null;
			 temp = e.getObjContents();
			 Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
				 (byte[][])temp.get(temp.size() - 1));

			 //System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			 if (!(recv_seq.equals(seqnum))) {
				 System.out.println("The message has been reordered!");
				 disconnect();
			 }
			 seqnum++;

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				return (List<String>)aes.cfbDecrypt(sharedKeyClientFS,
					(byte[][])e.getObjContents().get(0));
					 //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {
			 AES aes = new AES();
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, destFile));
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, group));
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, token));
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));

			 message.sign(HMACkey);
			 output.writeObject(message);
			 seqnum++;

			 FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();
			 if (!env.verify(HMACkey)) {
					System.out.println("The message has been modified!");
					disconnect();
				}
				ArrayList<Object> temp = null;
				temp = env.getObjContents();
				Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
					(byte[][])temp.get(temp.size() - 1));

				//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
				if (!(recv_seq.equals(seqnum))) {
					System.out.println("The message has been reordered!");
					disconnect();
				}
				seqnum++;

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }


			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					message.addObject(aes.cfbEncrypt(sharedKeyClientFS, buf));
					message.addObject(aes.cfbEncrypt(sharedKeyClientFS, new Integer(n)));
					message.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));

					message.sign(HMACkey);
					output.writeObject(message);
					seqnum++;

					env = (Envelope)input.readObject();
					if (!env.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						disconnect();
					}
					temp = env.getObjContents();
					recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
						(byte[][])temp.get(temp.size() - 1));

					//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
					if (!(recv_seq.equals(seqnum))) {
						System.out.println("The message has been reordered!");
						disconnect();
					}
					seqnum++;
			 }
			 while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				message.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));
				message.sign(HMACkey);
				output.writeObject(message);
				seqnum++;

				env = (Envelope)input.readObject();
				if (!env.verify(HMACkey)) {
					System.out.println("The message has been modified!");
					disconnect();
				}
				temp = env.getObjContents();
				recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientFS,
					(byte[][])temp.get(temp.size() - 1));

				//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
				if (!(recv_seq.equals(seqnum))) {
					System.out.println("The message has been reordered!");
					disconnect();
				}
				seqnum++;

				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {

					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}



	public void establishSecureSessionWithFS(final int port, PrivateKey
		pkSig, PublicKey userPubKey, PublicKey publicKeyFSrsa)throws GeneralSecurityException {

		BouncyCastleProvider bouncyCastleProvider =  new BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);

		System.out.println("--Establishing Secure connections with File Server " + port + "--");
		DHParameterSpec dhParameterSpec = DH.generateParameters(); // these parameters need to delivered to alice and bob it contains G P
		KeyPair clientKP = DH.generateKeyPair(dhParameterSpec);

		// now send client public dh with dhParameterSpec

		// wrap the required keys and parameters
		Envelope msg = new Envelope("SecureSession");
		//System.out.println(userPubKey);
		msg.addObject(userPubKey);
		msg.addObject(clientKP.getPublic());

		RSA rsa = new RSA();
		byte [] msgByte = new byte[0];
		try {
			msgByte = rsa.serialize(clientKP.getPublic());// convert the msg object to bytes
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(-1);
		}

		// sign the message
		byte [] signature = rsa.generatePkcs1Signature(pkSig,msgByte);

		if (output == null )System.out.println("Dbg " + msg.getMessage());
		// add signature to the message
		msg.addObject(signature);
		// the message contain username , session parameter , and signature
		try {
			output.writeObject(msg);
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Couldn't establish a secure connection");
		}

		Envelope message = null;

		try {
			message= (Envelope)input.readObject();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		assert message != null;
		byte [] sigFS =  (byte[]) message.getObjContents().get(0);
		PublicKey gsPkDH = (PublicKey) message.getObjContents().get(1);
		try {
			if(rsa.verifyPkcs1Signature(publicKeyFSrsa,rsa.serialize(gsPkDH),sigFS)){
				System.out.println("--Now we established secure session successfully with file server " + port + "--");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		sharedKeyClientFS = DH.recipientAgreementBasic(clientKP.getPrivate(),gsPkDH);

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

	}

	public boolean serverChallange(PublicKey publicKeyFSrsa){
		//generate BigInt
		BigInteger n = new BigInteger(128, new SecureRandom());
		//encrypt n with servers public key
		RSA rsa = new RSA();
		byte [] msgByte = new byte[0];

		AES aes = new AES();
		byte[][] cipherNWithIV = new byte[0][0];
		SecretKeySpec secretKey = new SecretKeySpec(sharedKeyClientFS,"AES");
	 	//System.out.println("client shared: " + sharedKeyClientFS);

		try {
			//convert n to bytes and encrypt with server public key
			msgByte = rsa.cfbEncrypt(publicKeyFSrsa, n.toByteArray());

			//also encrypt with shared DH key
			cipherNWithIV = aes.cfbEncrypt(secretKey, msgByte);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		//create and send the Envelope to the FS
		Envelope msg = new Envelope("Challange");
		msg.addObject(cipherNWithIV);

		try {
			output.writeObject(msg);
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Couldn't establish a secure connection");
		}

		//recieve response
		Envelope message = null;

		try {
			message = (Envelope)input.readObject();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		byte[][] encryptedN = (byte[][]) message.getObjContents().get(0);
		//decrypt with shared key
		try {
			msgByte = aes.cfbDecrypt(secretKey, encryptedN[0], encryptedN[1]);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(-1);
		}

		//convert byte[] back to bigint
		// This will probably never be 0.
		BigInteger serverN = new BigInteger(1, msgByte);

		//compare n to serverN
		return serverN.equals(n);
	}


	public boolean establishSequenceNumber() {
		seqnum = new Long(new SecureRandom().nextLong());

		Envelope msg = new Envelope("EstablishSeqNum");

		//SecretKeySpec sk = new SecretKeySpec(sharedKeyClientGS, "AES");
		msg.addObject(new AES().cfbEncrypt(sharedKeyClientFS, seqnum));

		try {
			msg.sign(HMACkey);
			output.writeObject(msg);
			seqnum++;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

		try {
			msg = (Envelope)input.readObject();

			if (!msg.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}

			byte[][] encrypted = (byte[][])msg.getObjContents().get(0);

			Long temp = (Long)new AES().cfbDecrypt(sharedKeyClientFS, encrypted);

			if (!seqnum.equals(temp)) {
				System.out.println("Invalid seqence number. Possible attack!");
				return false;
			}
			seqnum++;

			return true;
		}
		catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

}
