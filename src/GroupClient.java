/* Implements the GroupClient Interface */

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class GroupClient extends Client implements GroupClientInterface {

	private byte[] sharedKeyClientGS;
	private Long seqnum;

	private PrivateKey sign_key;
	private PublicKey gs_verify_key;

	private byte[] HMACkey;


	public boolean connect(final String server, final int port, PrivateKey pkSig, PublicKey publicKeyGsRSA, String username) {
		super.connect(server, port);
		//new code
		try {
			establishSecureSessionWithGS(pkSig, publicKeyGsRSA, username);
		} catch (GeneralSecurityException e) {
//			e.printStackTrace();
			return false;
		}

		if (!establishSequenceNumber()) {
			disconnect();
		}

		sign_key = pkSig;
		gs_verify_key = publicKeyGsRSA;

		return isConnected();
	}

	public UserToken getToken(String username, PublicKey pk )
	{
		try
		{
			AES aes = new AES();

			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,username)); //Add user name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,pk));
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));

			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			//Get the response from the server
			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}


			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}


			seqnum++;

			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it
		//		ArrayList<Object> temp = null;
		//		temp = response.getObjContents();

				if(temp.size() == 2)
				{
					//decryption
					byte [][] cipherTokenWithIV = (byte[][]) response.getObjContents().get(0);

					byte [] bytetoken = new byte[0];
					SecretKeySpec secretKey = new SecretKeySpec(sharedKeyClientGS,"AES");
					try {
						bytetoken = aes.cfbDecrypt(secretKey, cipherTokenWithIV[0], cipherTokenWithIV[1]);
					} catch (GeneralSecurityException e) {
						e.printStackTrace();
					}


					//convert from byte[] to token
					ByteArrayInputStream in = new ByteArrayInputStream(bytetoken);
	        		ObjectInputStream is = new ObjectInputStream(in);
					token = (UserToken)is.readObject();

					getUserGroupsKeys(token);

					//System.out.println(keychain);

					return token;
				}
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

	public boolean createUser(String username, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,username)); //Add user name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add the requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));

			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUser(String username, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;

			//Tell the server to delete a user
			message = new Envelope("DUSER", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,username)); //Add user name
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token));  //Add requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));


			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,groupname)); //Add the group name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add the requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));


			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				byte[][] encrypted = (byte[][])response.getObjContents().get(0);
				keychain = (HashMap)aes.cfbDecrypt(sharedKeyClientGS, encrypted);
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,groupname)); //Add group name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));

			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;
			//Tell the server to return the member list
			message = new Envelope("LMEMBERS", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,group)); //Add group name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));


			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

					//If server indicates success, return the member list
			if(response.getMessage().equals("OK"))
			{
				byte[][] encrypted = (byte[][])response.getObjContents().get(0);
				List<String> groupMembers = (List<String>)aes.cfbDecrypt(sharedKeyClientGS, encrypted);
				return groupMembers; //This cast creates compiler warnings. Sorry.
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

	// ================================= T6 =====================================
	public boolean getUserGroupsKeys(UserToken token) {
		try
		{
			AES aes = new AES();
			Envelope message=null, response= null;
			//Tell the server to return the member list
			message = new Envelope("GroupKeys", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));

			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
					(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return the member list
			if(response.getMessage().equals("OK"))
			{
				byte[][] encrypted = (byte[][])response.getObjContents().get(0);
				keychain = (HashMap)aes.cfbDecrypt(sharedKeyClientGS, encrypted);
				return true; //This cast creates compiler warnings. Sorry.
			}

			return false;

		}

		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	//============================================================================
	public boolean addUserToGroup(String userToAdd, String groupname, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,groupname)); //Add group name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,userToAdd)); //Add user name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));


			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupName, UserToken token)
	{
		try
		{
			AES aes = new AES();
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP", sharedKeyClientGS);
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,groupName)); //Add group name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,token)); //Add requester's token
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,username)); //Add user name string
			message.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));


			message.sign(HMACkey);
			output.writeObject(message);
			seqnum++;

			response = (Envelope)input.readObject();

			if (!response.verify(HMACkey)) {
				System.out.println("The message has been modified!");
				disconnect();
			}
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				byte[][] encrypted = (byte[][])response.getObjContents().get(0);
				keychain = (HashMap)aes.cfbDecrypt(sharedKeyClientGS, encrypted);
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}



	public void establishSecureSessionWithGS(PrivateKey pkSig,PublicKey publicKeyGSrsa, String username) throws GeneralSecurityException {
		BouncyCastleProvider bouncyCastleProvider =  new BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);

		System.out.println("\n--Establishing Secure connections with Group Server--");
		DHParameterSpec dhParameterSpec = null;
		// generate dhParameterSpec
		dhParameterSpec = DH.generateParameters(); // these parameters need to delivered to alice and bob it contains G P
		KeyPair clientKP = DH.generateKeyPair(dhParameterSpec);

		// now send client public dh with dhParameterSpec

		// wrap the required keys and parameters
		//SecureSessionParameters secureSessionParameters = new SecureSessionParameters(dhParameterSpec,clientKP.getPublic());
		Envelope msg = new Envelope("SecureSession");
		msg.addObject(username);
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
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}

		assert message != null;
		if (message.getMessage().equals("FAIL")) {
			System.out.println("Invalid key provided.");
			throw new GeneralSecurityException();
		}
		byte [] sigGS =  (byte[]) message.getObjContents().get(0);
		PublicKey gsPkDH = (PublicKey) message.getObjContents().get(1);
		try {
			if(rsa.verifyPkcs1Signature(publicKeyGSrsa,rsa.serialize(gsPkDH),sigGS)){
				System.out.println("--Connection Established--\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		sharedKeyClientGS = DH.recipientAgreementBasic(clientKP.getPrivate(),gsPkDH);

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

	public boolean establishSequenceNumber() {
		seqnum = new Long(new SecureRandom().nextLong());

		Envelope msg = new Envelope("EstablishSeqNum", sharedKeyClientGS);

//		SecretKeySpec sk = new SecretKeySpec(sharedKeyClientGS, "AES");
		msg.addObject(new AES().cfbEncrypt(sharedKeyClientGS, seqnum));

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

			Long temp = (Long)new AES().cfbDecrypt(sharedKeyClientGS, encrypted);

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

	public boolean verifyPassword(String username, String password){
		Envelope msg = new Envelope("VerifyPW", sharedKeyClientGS);
		AES aes = new AES();
		byte[][] cipherUserNameWithIV;
		byte[][] cipherPWWithIV;



		SecretKeySpec secretKey = new SecretKeySpec(sharedKeyClientGS,"AES");
		try {
			cipherUserNameWithIV = aes.cfbEncrypt(secretKey, username.getBytes());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}

		try {
			cipherPWWithIV = aes.cfbEncrypt(secretKey, password.getBytes());
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			return false;
		}

		msg.addObject(cipherUserNameWithIV);
		msg.addObject(cipherPWWithIV);

		try {
			msg.addObject(aes.cfbEncrypt(sharedKeyClientGS,seqnum));
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
			ArrayList<Object> temp = null;
			temp = msg.getObjContents();
			Long recv_seq = (Long)aes.cfbDecrypt(sharedKeyClientGS,
				(byte[][])temp.get(temp.size() - 1));

			//System.out.println("r: " + recv_seq + "\ns: " +seqnum);
			if (!(recv_seq.equals(seqnum))) {
				System.out.println("The message has been reordered!");
				disconnect();
			}
			seqnum++;

		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		return (msg.getMessage().equals("OK")) ;
	}

}
