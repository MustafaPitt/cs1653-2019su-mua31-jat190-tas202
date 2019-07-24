/* FileClient provides all the client functionality regarding the file server */

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.math.BigInteger;

public class FileClient extends Client implements FileClientInterface {

	private byte[] sharedKeyClientFS;
	private byte[] HMACkey;
	private Long seqnum;

	public FileClient() {}

	public FileClient(HashMap<String, List<GroupKey>> k) {
		keychain = k;
	}

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

		//server challenge
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
		Envelope env = new Envelope("DELETEF", sharedKeyClientFS); //Success
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

				if (env.getMessage().equals("Expired")){
					System.out.println("Token Expired. Please re-login.");
					return false;
				}

				if (env.getMessage().equals("invalid_fs_pk")){
					System.out.println("Your token doesn't have permission to access this fileserver");
					return false;
				}

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

					    Envelope env = new Envelope("DOWNLOADF", sharedKeyClientFS); //Success
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

							if (env.getMessage().equals("Expired")){
								System.out.println("Token Expired. Please re-login.");
								return false;
							}

							if (env.getMessage().equals("invalid_fs_pk")){
								System.out.println("Your token doesn't have permission to access this fileserver");
								return false;
							}

							while (env.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])aes.cfbDecrypt(sharedKeyClientFS,
										(byte[][])env.getObjContents().get(0)), 0,
										(Integer)aes.cfbDecrypt(sharedKeyClientFS,
										(byte[][])env.getObjContents().get(1)));
									System.out.printf(".");
									env = new Envelope("DOWNLOADF", sharedKeyClientFS); //Success
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
									env = new Envelope("OK", sharedKeyClientFS); //Success
									env.addObject(aes.cfbEncrypt(sharedKeyClientFS,seqnum));
									env.sign(HMACkey);
									output.writeObject(env);
									seqnum++;

									//T6 decrypt
									//first get version and group name
									try{
										if(decryptFile(file) == false){
											file.delete();
											return false;
										}
									}catch(Exception ex) {ex.printStackTrace();}


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
			 message = new Envelope("LFILES", sharedKeyClientFS);

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

			 if (e.getMessage().equals("Expired")){
				 System.out.println("Token Expired. Please re-login.");
				 return null;
			 }

			 if (e.getMessage().equals("invalid_fs_pk")){
				 System.out.println("Your token doesn't have permission to access this fileserver");
				 return null;
			 }

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
			 	return (List<String>)aes.cfbDecrypt(sharedKeyClientFS, (byte[][])e.getObjContents().get(0));
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
			 message = new Envelope("UPLOADF", sharedKeyClientFS);
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, destFile));
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, group));
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, token));
			 message.addObject(aes.cfbEncrypt(sharedKeyClientFS, seqnum));

			 message.sign(HMACkey);
			 output.writeObject(message);
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

				if (env.getMessage().equals("Expired")){
					System.out.println("Token Expired. Please re-login.");
					return false;
				}

				if (env.getMessage().equals("invalid_fs_pk")){
					System.out.println("Your token doesn't have permission to access this file server");
					return false;
				}

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

			List<GroupKey> l = keychain.get(group);
			Integer key_version = l.size() - 1;

			// Encrypt file to temp, then upload that.
			String temp_file = encryptFile(sourceFile, group,
				l.get(key_version).encrypt_key,
				l.get(key_version).verify_key, key_version);


			 FileInputStream fis = new FileInputStream(temp_file);

			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK", sharedKeyClientFS);
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.print(".");
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
			 fis.close();

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF", sharedKeyClientFS);
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

			}else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			}

			String n = "." + sourceFile + ".tmp";
			File deltmp = new File(n);
			if(!deltmp.delete()) System.out.println("Error deleting " + n);

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
		Envelope msg = new Envelope("Challange", sharedKeyClientFS);
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

		Envelope msg = new Envelope("EstablishSeqNum", sharedKeyClientFS);

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
				System.out.println("Invalid sequence number. Possible attack!");
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

	public String encryptFile(String filename, String groupname,
		SecretKey encrypt, SecretKey verify, int kv)
		throws Exception
	{
		byte[] block = new byte[4096];

		String tmpfn = "." + filename + ".tmp";

		FileInputStream fis = new FileInputStream(new File(filename));
		FileOutputStream fos = new FileOutputStream(
			new File("."+filename+".tmp"));

		IvParameterSpec iv = new IvParameterSpec(new byte[16]);
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, encrypt, iv);
		CipherOutputStream cos = new CipherOutputStream(fos, c);

		// Do encryption
		int i;
		while ((i = fis.read(block)) != -1) {
			cos.write(block, 0, i);
		}
		cos.close();

		fos = new FileOutputStream(new File("."+filename+".tmp"), true);

		// Write key version, group name
		fos.write(iv.getIV());
		fos.write(ByteBuffer.allocate(4).putInt(kv).array());
		byte[] gn = new byte[20];
		System.arraycopy(groupname.getBytes(), 0, gn, 0, Math.min(groupname.getBytes().length, 20));
		fos.write(gn);
		fos.close();

		// Write HMAC
		byte[] hmac = getFileHMAC(tmpfn, verify);
		fos = new FileOutputStream(new File("."+filename+".tmp"), true);
		fos.write(hmac);
		fos.close();

		//System.out.println(Arrays.toString(hmac));

		return tmpfn;
	}

	public boolean decryptFile(File file) throws Exception{
		//check HMAC
		RandomAccessFile raf = new RandomAccessFile(file, "rw");

		//seek to start of HMAC
		raf.seek(file.length() - 64);

		byte[] hmac = new byte[64];
		raf.read(hmac);
		//System.out.println("\tHMAC = " + Arrays.toString(hmac));

		//seek to start of groupname
		raf.seek(file.length() - 84);

		byte[] groupname = new byte[20];
		raf.read(groupname);
		System.out.println(Arrays.toString(groupname));
		String gn = new String(groupname);
		gn = gn.trim();
	  //System.out.println("\tgroupname = " + gn + " size: " + gn.length());

		//seek to start of version num
		raf.seek(file.length() - 88);

		byte[] version_num = new byte[4];
		raf.read(version_num);
		int vn = ByteBuffer.wrap(version_num).getInt();

		//seek to start of iv
		raf.seek(file.length() - 104);

		byte[] iv_byte = new byte[16];
		raf.read(iv_byte);
		IvParameterSpec iv = new IvParameterSpec(iv_byte);

		//compute HMAC
		raf.setLength(raf.length()-64);
		raf.close();

		byte[] encFileHMAC = getFileHMAC(file.getName(), keychain.get(gn).get(vn).verify_key);

		if(Arrays.equals(hmac, encFileHMAC) == false){
			System.out.println("This file has been modified.");
			return false;
		}

		//hmac is correct, decrypt file
		raf = new RandomAccessFile(file, "rw");
		raf.setLength(raf.length() - 40);
		raf.close();

		FileInputStream fis = new FileInputStream(file);
		File dec_data = new File("decryptedData");
		FileOutputStream fos = new FileOutputStream(dec_data);

		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, keychain.get(gn).get(vn).encrypt_key, iv);
		CipherInputStream cis = new CipherInputStream(fis, c);

		byte[] block = new byte[4096];

		// Do encryption
		int i;
		while ((i = cis.read(block)) != -1) {
			fos.write(block, 0, i);
		}
		fos.close();
		fis.close();

		String temp = file.getName();
		if (!file.delete()) System.out.println(
			"Error deleting " + temp);

		dec_data.renameTo(new File(temp));

		return true;

	}

	/* Calculate HMAC of a file using SHA-512.
	 * Key version, group name, file contents
	 */
	public byte[] getFileHMAC(String filename, SecretKey verify)
		throws Exception
	{
        Mac mac = Mac.getInstance("HMacSHA512", "BC");
        SecretKeySpec k = new SecretKeySpec(verify.getEncoded(),
			"HmacSHA512");
        mac.init(k);

		FileInputStream fis = new FileInputStream(new File(filename));

		byte[] block = new byte[4096];
		while (fis.read(block) != -1) {
			mac.update(block);
		}
		fis.close();
		return mac.doFinal();
	}
}
