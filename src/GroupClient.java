/* Implements the GroupClient Interface */

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GroupClient extends Client implements GroupClientInterface {

	private byte[] sharedKeyClientGS;



	public boolean connect(final String server, final int port, PrivateKey pkSig, PublicKey publicKeyGSrsa, String username) {
		super.connect(server, port);
		//new code
		try {
			establishSecureSessionWithGS(pkSig, publicKeyGSrsa, username);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		return isConnected();
	}

	public UserToken getToken(String username)
	{
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 1)
				{
					//decryption
					byte [][] cipherTokenWithIV = (byte[][]) response.getObjContents().get(0);

					AES aes = new AES();
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
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(token); //Add the requester's token
			output.writeObject(message);

			response = (Envelope)input.readObject();

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
			Envelope message = null, response = null;

			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			output.writeObject(message);

			response = (Envelope)input.readObject();

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
			Envelope message = null, response = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			output.writeObject(message);

			response = (Envelope)input.readObject();

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

	public boolean deleteGroup(String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			output.writeObject(message);

			response = (Envelope)input.readObject();
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
			Envelope message = null, response = null;
			//Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			output.writeObject(message);

			response = (Envelope)input.readObject();
					//If server indicates success, return the member list
			if(response.getMessage().equals("OK"))
			{
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	public boolean addUserToGroup(String userToAdd, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(userToAdd); //Add user name string
			output.writeObject(message);

			response = (Envelope)input.readObject();
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
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(groupName); //Add group name string
			message.addObject(token); //Add requester's token

			message.addObject(username); //Add user name string

			output.writeObject(message);

			response = (Envelope)input.readObject();
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



	public void establishSecureSessionWithGS(PrivateKey pkSig,PublicKey publicKeyGSrsa, String username) throws GeneralSecurityException {
		BouncyCastleProvider bouncyCastleProvider =  new BouncyCastleProvider();
		Security.addProvider(bouncyCastleProvider);

		System.out.println("Establishing Secure connections with Group Server");
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
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		assert message != null;
		byte [] sigGS =  (byte[]) message.getObjContents().get(0);
		PublicKey gsPkDH = (PublicKey) message.getObjContents().get(1);
		try {
			if(rsa.verifyPkcs1Signature(publicKeyGSrsa,rsa.serialize(gsPkDH),sigGS)){
				System.out.println("Now we established secure session successfully with group server");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		sharedKeyClientGS = DH.recipientAgreementBasic(clientKP.getPrivate(),gsPkDH);
		System.out.println("DBG " + Arrays.toString(sharedKeyClientGS));

	}

	public boolean verifyPassword(String username, String password){
		Envelope msg = new Envelope("VerifyPW");
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
			output.writeObject(msg);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

		try {
			msg = (Envelope)input.readObject();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

		return (msg.getMessage().equals("OK")) ;


	}
}
