/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */


import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.time.LocalTime;
import java.util.*;

public class GroupThread extends Thread
{
	private final int DURATION = 30; // in mint
	private final Socket socket;
	private GroupServer my_gs;
	private byte[] agreedKeyGSDH;

	private PublicKey verify_key;

	private byte[] HMACkey;

	private Long seqnum;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			/* Do hash inversion challenge */
			try {
				if (!puzzleChallenge(input, output)) {
					System.out.println("Client failed challenge!" +
						" DISCONNECT");
					socket.close();
					return;
				}
			} catch (Exception e) {
				System.out.println("An unknown error occurred.");
				e.printStackTrace();
				return;
			}
			System.out.println("Passed puzzle test!");

			/* Main loop */
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if(message.getMessage().equals("GET"))//Client wants a token
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						break;
					}

					// Decrypt message
					AES aes = new AES();
					byte[][] encrypted = (byte[][])message.getObjContents().get(0);
					String username = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
					encrypted = (byte[][])message.getObjContents().get(1);
					PublicKey publicKey = (PublicKey) aes.cfbDecrypt(agreedKeyGSDH, encrypted);
					encrypted = (byte[][])message.getObjContents().get(2);
					Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

					//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
					if (!recv_seq.equals(seqnum)) {
						System.out.println("The message has been reordered!");
						socket.close();
						break;
					}
					seqnum++;

					byte[][] enc_seqnum =
						aes.cfbEncrypt(agreedKeyGSDH, seqnum);

					if(username == null)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
						response.addObject(null);
						response.addObject(enc_seqnum);
						response.sign(HMACkey);
						output.writeObject(response);
						seqnum++;
					}

					else
					{
						UserToken yourToken = createToken(username,publicKey); //Create a token
						//hashes the token and signs it
						assert yourToken != null;
						yourToken.updateHashToken(my_gs.privateKeySig);

						//encrypting token and signed hash token
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						ObjectOutputStream os = new ObjectOutputStream(out);

						byte[][] cipherTokenWithIV;
						SecretKeySpec secretKey = new SecretKeySpec(agreedKeyGSDH,"AES");


						try {
							os.writeObject(yourToken);
							cipherTokenWithIV = aes.cfbEncrypt(secretKey, out.toByteArray());
						} catch (GeneralSecurityException e) {
							e.printStackTrace();
							output.writeObject(new Envelope("FAIL", agreedKeyGSDH));
							return;
						}


						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK", agreedKeyGSDH);
						response.addObject(cipherTokenWithIV);
						response.addObject(enc_seqnum);
						response.sign(HMACkey);
						output.writeObject(response);
						seqnum++;

					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String username = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(2);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;

								if(createUser(username, yourToken))
								{
									System.err.println("got here 4");
									response = new Envelope("OK", agreedKeyGSDH); //Success
								}
							}
						}
					}
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyGSDH, seqnum);

					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String username = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(2);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;

								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK", agreedKeyGSDH); //Success
								}
							}
						}
					}
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyGSDH, seqnum);
					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					output.writeObject(response);
					seqnum++;
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String groupName = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(2);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;

								if(createGroup(groupName, yourToken))
								{
									response = new Envelope("OK", agreedKeyGSDH); //Success
									response.addObject(new AES().cfbEncrypt(agreedKeyGSDH, getUserGroupsKeys(yourToken)));
								}
							}
						}
					}
					response.addObject(new AES().cfbEncrypt(agreedKeyGSDH, seqnum));
					response.sign(HMACkey);

					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String groupName = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(2);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;

								if(deleteGroup(groupName, yourToken))
								{
									response = new Envelope("OK", agreedKeyGSDH); //Success
								}
							}
						}
					}
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyGSDH, seqnum);
					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}

				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						break;
					}
					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String groupName = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(2);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									break;
								}
								seqnum++;

								List<String> groupMembers = listAllMembersInGroup(groupName, yourToken);

								response = new Envelope("OK", agreedKeyGSDH); //Success
								response.addObject(aes.cfbEncrypt(agreedKeyGSDH, groupMembers));
							}
						}
					}
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyGSDH, seqnum);
					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}
				//=================== T6 ========================
				// request group keys
				else if (message.getMessage().equals("GroupKeys")){

					HashMap<String, List<GroupKey>> userGroupKeys;

					System.out.println("DBG reached here message size " + message.getObjContents().size());
					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								Token  token = (Token) aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the token

								encrypted = (byte[][])message.getObjContents().get(1);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted); // get seq

								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									break;
								}
								seqnum++;
								userGroupKeys = getUserGroupsKeys(token);

								response = new Envelope("OK", agreedKeyGSDH); //Success
								response.addObject(aes.cfbEncrypt(agreedKeyGSDH, userGroupKeys));
							}
						}
					}

//					response.addObject(new AES().cfbEncrypt(agreedKeyGSDH, userGroupKeys));
					response.addObject(new AES().cfbEncrypt(agreedKeyGSDH, seqnum));
					response.sign(HMACkey);

					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}
				//=========================================================================================
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String groupName = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(2);
								String userToAdd = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(3);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									proceed = false;
									break;
								}
								seqnum++;

								if(addUserToGroup(groupName,yourToken,userToAdd))
								{
									response = new Envelope("OK", agreedKeyGSDH); //Success
								}
								else
									response = new Envelope("FAIL", agreedKeyGSDH);
							}
						}
					}
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyGSDH, seqnum);
					response.addObject(enc_seqnum);
					response.sign(HMACkey);
					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						proceed = false;
						break;
					}

					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL", agreedKeyGSDH);
					}
					else
					{
						response = new Envelope("FAIL", agreedKeyGSDH);

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								// Decrypt message
								AES aes = new AES();
								byte[][] encrypted = (byte[][])message.getObjContents().get(0);
								String groupName = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(1);
								Token yourToken = (Token)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username
								encrypted = (byte[][])message.getObjContents().get(2);
								String userToRemove = (String)aes.cfbDecrypt(agreedKeyGSDH, encrypted); //Get the username

								encrypted = (byte[][])message.getObjContents().get(3);
								Long recv_seq = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);

								//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
								if (!recv_seq.equals(seqnum)) {
									System.out.println("The message has been reordered!");
									socket.close();
									break;
								}
								seqnum++;

							if(removeUserFromGroup(groupName,yourToken,userToRemove))
								{
									response = new Envelope("OK", agreedKeyGSDH); //Success
									response.addObject(new AES().cfbEncrypt(agreedKeyGSDH, getUserGroupsKeys(yourToken)));
								}
								else
									response = new Envelope("FAIL", agreedKeyGSDH);
							}
						}
					}
					response.addObject(new AES().cfbEncrypt(agreedKeyGSDH, seqnum));
					response.sign(HMACkey);

					System.err.println(response.getMessage());
					output.writeObject(response);
					seqnum++;
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}

				else if (message.getMessage().equals("SecureSession")) {
					response = establishSecureSessionWithClient(message);
					if (response.getMessage().equals("OK")) {
						System.out.println("secure session established");
						output.writeObject(response);

					} else {
						System.out.println("couldn't established secure connections");
						output.writeObject(response);
					}
				}
				else if (message.getMessage().equals("VerifyPW")){

					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						break;
					}

					byte[][] encrypted = (byte[][])message.getObjContents().get(2);
					Long recv_seq = (Long) new AES().cfbDecrypt(agreedKeyGSDH, encrypted);

					//System.out.println("r: " + recv_seq + "\ns: "+seqnum) ;
					if (!recv_seq.equals(seqnum)) {
						System.out.println("The message has been reordered!");
						socket.close();
						break;
					}
					seqnum++;
					byte[][] enc_seqnum = new AES().cfbEncrypt(agreedKeyGSDH, seqnum);


					response = 	verifyPwAndUsernameFromClientApp(message);
					if (response.getMessage().equals("OK")) {
						System.out.println("password correct");
						response.addObject(enc_seqnum);
						response.sign(HMACkey);
						output.writeObject(response);
						seqnum++;
					} else {
						System.out.println("password incorrect");
						response.addObject(enc_seqnum);
						response.sign(HMACkey);
						output.writeObject(response);
						seqnum++;
					}

				}
				else if(message.getMessage().equals("EstablishSeqNum"))
				{
					if (!message.verify(HMACkey)) {
						System.out.println("The message has been modified!");
						socket.close();
						break;
					}

					AES aes = new AES();
					byte[][] encrypted = (byte[][])message.getObjContents().get(0);

					seqnum = (Long)aes.cfbDecrypt(agreedKeyGSDH, encrypted);
					seqnum++;

					response = new Envelope("OK", agreedKeyGSDH);
					response.addObject(aes.cfbEncrypt(agreedKeyGSDH, seqnum));
					response.sign(HMACkey);
					output.writeObject(response);
					seqnum++;
				}
				else
				{
					response = new Envelope("FAIL", agreedKeyGSDH); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private Envelope verifyPwAndUsernameFromClientApp(Envelope message) {

		byte [][] cipherUserNameWithIV = (byte[][]) message.getObjContents().get(0);
		byte [][] cipherPasswordWithIV = (byte[][]) message.getObjContents().get(1);

		AES aes = new AES();
		byte[] username = new byte[0];
		byte[] pw = new byte[0];
		byte [] hashedPW = new byte[0];
		SecretKeySpec secretKey = new SecretKeySpec(agreedKeyGSDH,"AES");

		try {
			username = aes.cfbDecrypt(secretKey, cipherUserNameWithIV[0], cipherUserNameWithIV[1]);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		try {
			pw = aes.cfbDecrypt(secretKey, cipherPasswordWithIV[0], cipherPasswordWithIV[1]);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		if (!my_gs.userList.checkUser(new String(username)))
			return  new Envelope("Fail", agreedKeyGSDH);

		HMAC hmac = new HMAC();
		try {
			hashedPW = 	HMAC.calculateHmac(my_gs.hashPWSecretKey,pw);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		String userStr = new String(username);
		String pwStr = new String(hashedPW);

		if(my_gs.userList.getUser(userStr).getPwHash().equals(pwStr)){
			return new Envelope("OK", agreedKeyGSDH);
		}
		return new Envelope("FAIL", agreedKeyGSDH);


	}

	private Envelope establishSecureSessionWithClient(Envelope message) {
		String username =  (String) message.getObjContents().get(0);
		//Client.SecureSessionParameters secureSessionParameters = (Client.SecureSessionParameters) message.getObjContents().get(1);
		PublicKey clientDHPK = (PublicKey) message.getObjContents().get(1);
		byte [] sigbytes = (byte[]) message.getObjContents().get(2);
		RSA rsa = new RSA();
		byte [] bytesMsg = new byte[0];
		try {
			bytesMsg = rsa.serialize(clientDHPK);
		} catch (IOException e) {
			e.printStackTrace();
		}

		PublicKey pk = my_gs.clientCertifcates.get(username);
		verify_key = pk;

		if (pk == null) {
			System.out.println("User " + username +
				" tried to connect with an unknown key!");
			return new Envelope("FAIL");
		}

		try {
			if (rsa.verifyPkcs1Signature(pk,bytesMsg,sigbytes)){
				DH dh = new DH();
				KeyPair keyPairGSDH = DH.generateKeyPair(((DHPublicKey)clientDHPK).getParams());
				agreedKeyGSDH  =  DH.initiatorAgreementBasic(keyPairGSDH.getPrivate(),clientDHPK);


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
					sig =rsa.generatePkcs1Signature(my_gs.privateKeySig,rsa.serialize(keyPairGSDH.getPublic()));
				} catch (IOException e) {
					e.printStackTrace();
				}
				msg.addObject(sig);
				msg.addObject(keyPairGSDH.getPublic());
				return msg;
			}
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return new Envelope("FAIL");
	}

	private boolean removeUserFromGroup(String groupName, UserToken yourToken, String userToDel) {
		String requester = yourToken.getSubject();
		System.err.println("group name " + groupName + " requester " + requester + " user to remove  " + userToDel);
		System.err.println("ownership" + yourToken.getOwnership());
		// check if the user that want to delete to a group is exist in the group server and not the ownership of the group
		if(my_gs.userList.checkUser(userToDel)&& !my_gs.userList.getUserOwnership(userToDel).contains(groupName)){
			// check if the requester is the ownership of the given group
			if (my_gs.userList.getUserOwnership(requester).contains(groupName)){
				// check if the user is already in a group
				if (my_gs.groupMembers.get(groupName).contains(userToDel)){
					my_gs.groupMembers.get(groupName).remove(userToDel); // remove it from user group
					my_gs.userList.getUserGroups(userToDel).remove(groupName); // remove it from member list

					// ============== T6 ================
					// we add a new key each time we remove or add a user and make the recent created key as a default group key
					try {
						my_gs.createGroupKey(groupName);
					} catch (GeneralSecurityException e1) {
						e1.printStackTrace();
					}
					//===================================
					return true;
				}
			}
		}
		return false;
	}

	private List<String> listAllMembersInGroup(String groupName, UserToken token) {
		// check if the user is the ownership of the group
		// check if the user is admin or the ownership of the group
		String requester = token.getSubject();
		if(my_gs.userList.getUserGroups(requester).contains(groupName) && token.getOwnership().contains(groupName)) {
			return  my_gs.groupMembers.get(groupName);
		}
		return null;
	}
	// ======================== T6 ==============================================
	private HashMap<String, List<GroupKey>> getUserGroupsKeys(UserToken token){
		HashMap <String , List<GroupKey>> userGroupKeys = new HashMap<>();
		// find all groups that user owner belong and get group keys
		for (String group : token.getGroups()){
			if(my_gs.group_keys.containsKey(group))
				userGroupKeys.put(group,my_gs.group_keys.get(group));
		}
		return userGroupKeys;
	}
	//===========================================================================

	private boolean addUserToGroup(String groupName, UserToken yourToken, String userNameToAdd){
		String requester = yourToken.getSubject();
		System.err.println("group name " + groupName + " requester " + requester + " user to add  " + userNameToAdd);

		// check if the user that want to add to a group is exist in the group server
		if(my_gs.userList.checkUser(userNameToAdd)){
			// check if the user is the ownership of the given group
			if (my_gs.userList.getUserOwnership(requester).contains(groupName)){
				// check if the user is not already in a group
				if (!my_gs.groupMembers.get(groupName).contains(userNameToAdd)){
					my_gs.groupMembers.get(groupName).add(userNameToAdd);
					my_gs.userList.getUserGroups(userNameToAdd).add(groupName);
					// ============== T6 ================
					// we add a new key each time we remove or add a user and make the recent created key as a default group key
//					try {
//						SecretKey secretKey =  new AES().generateKey();
//						my_gs.groupKeys.get(groupName).add(secretKey);
//					} catch (GeneralSecurityException e1) {
//						e1.printStackTrace();
//					}
					//===================================

					return true;
				}
			}
		}
		return false;
	}

	private boolean createGroup(String groupName, UserToken yourToken) {

		String requester = yourToken.getSubject();
		Set<String> groups = my_gs.groupMembers.keySet();
		if (groups.contains(groupName)) {
			return false;
		}
		//Check if requester exists/ any user can create a group
		if(my_gs.userList.checkUser(requester))
		{
			// check not a such group created before
			if(my_gs.userList.getUserGroups(requester).contains(groupName) || groups.contains(groupName)){
				System.err.println("Group already exists");
				return false;
			}
			else{
				my_gs.userList.addGroup(requester,groupName); // add group
				my_gs.userList.addOwnership(requester,groupName);
				List<String> membersList = new ArrayList<>();
				membersList.add(requester);
				my_gs.groupMembers.put(groupName,membersList);

				//=============== T6 ====================================
				// create keys list for the group
				try {
					my_gs.createGroupKey(groupName);
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				}

				//=======================================================
				return true;

			}

		}

		return false; //user not exsit

	}

	//Method to create tokens
	private UserToken createToken(String username, PublicKey pk)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username),
					my_gs.userList.getUserOwnership(username), MyTime.setDurationInMint(DURATION),pk);
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, UserToken yourToken) throws IOException {
		String requester = yourToken.getSubject();
		System.err.println("requester: " + requester);
		System.err.println("All users: ");
		my_gs.userList.showAllUsers();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			System.err.println("Printing requester groups: ");
			for (String g : temp) {
				System.err.println(g);
			}
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					String pw = PW.generate(8); // generate pw of length n
					try {
						byte[] pwHash = HMAC.calculateHmac(my_gs.hashPWSecretKey,pw.getBytes());
						my_gs.userList.addUser(username,new String(pwHash));
						System.out.println("User Name: " + username);
						System.out.println("Password: " + pw);
						//and give the private to the client
						RSA rsa = new RSA();

						// write the private key to the disk and give it to the client

						ObjectOutputStream outStreamGroup = null;

						KeyPair keyPair = RSA.generateKeyPair();
						PublicKey clientPublicKey = keyPair.getPublic();
						PrivateKey clientPrivateKey = keyPair.getPrivate();

						try { // save user private key
							outStreamGroup = new ObjectOutputStream(new FileOutputStream(username + "_Private.bin"));
							outStreamGroup.writeObject(clientPrivateKey);

						} catch (IOException e) {
							e.printStackTrace();
						}
						try { // save user public key
							outStreamGroup = new ObjectOutputStream(new FileOutputStream(username + "_Public.bin"));
							outStreamGroup.writeObject(clientPublicKey);

						} catch (IOException e) {
							e.printStackTrace();
						}
						assert outStreamGroup != null;
						outStreamGroup.close();
						my_gs.clientCertifcates.put(username,clientPublicKey);
					} catch (GeneralSecurityException | IOException e1) {
						e1.printStackTrace(); }

					// save clients certificates
					ObjectOutputStream outStreamGroup;
					outStreamGroup = new ObjectOutputStream(new FileOutputStream("clientCertificates.bin"));
					outStreamGroup.writeObject(my_gs.clientCertifcates);
					outStreamGroup.close();
					// write username and password to a text file
					BufferedWriter writer = null;
					try {
						writer = new BufferedWriter(new FileWriter(username + "_PW.txt", true));
					} catch (IOException e) { e.printStackTrace();}
					writer.append("username: " + username);
					writer.append("\n");
					writer.append("password: "+ pw);
					writer.close();
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<>();
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup,
								my_gs.userList.getUserOwnership(username),MyTime.setDurationInMint(DURATION)));
					}

					// remove all groups that user own
					for (String groupOwn : my_gs.userList.getUserOwnership(username)){
						my_gs.groupMembers.remove(groupOwn);
						    //=============== T6 ==================
								// remove group keys
								my_gs.group_keys.remove(groupOwn);
								my_gs.lts_map.remove(groupOwn);
							//=====================================
					}
					for (String group : my_gs.userList.getUserGroups(username)){
						if(my_gs.groupMembers.containsKey(group))
							my_gs.groupMembers.get(group).remove(username);
						//=============== T6 ==================
						// update group key by add a new one
						try {
							my_gs.createGroupKey(group);
						} catch (GeneralSecurityException e) {
							e.printStackTrace();
						}
						//=====================================
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					// remove user public key from the client certificate
					my_gs.clientCertifcates.remove(username);

					// update file certificate.bin
					// save clients certificates
					ObjectOutputStream outStreamGroup = null;
					try {
						outStreamGroup = new ObjectOutputStream(new FileOutputStream("clientCertificates.bin"));
					} catch (IOException e) {
						e.printStackTrace();
					}
					try {
						assert outStreamGroup != null;
						outStreamGroup.writeObject(my_gs.clientCertifcates);
					} catch (IOException e) {
						e.printStackTrace();
					}
					try {
						outStreamGroup.close();
					} catch (IOException e) {
						e.printStackTrace();
					}

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean deleteGroup(String groupName, UserToken token) {

		// check if the user is admin or the ownership of the group
		String requester = token.getSubject();
		if(my_gs.userList.getUserOwnership(requester).contains(groupName)){
			// check if the group want to be del is exist
			if (!my_gs.userList.getUserGroups(requester).contains(groupName)){
				System.err.println("No a such  group " + groupName + " exist");
				return false;
			}
			my_gs.userList.removeGroup(requester,groupName); // remove the group
			my_gs.userList.removeOwnership(requester,groupName); // remove the ownership
			my_gs.groupMembers.remove(groupName); // remove all members from the group
			// =================== T6 ==================================================
			 my_gs.group_keys.remove(groupName); // remove group keys
			my_gs.lts_map.remove(groupName);
			//==========================================================================
			System.err.println("group delete successfully ");
			return true;
		}
		System.err.println("Error Del group: check user or ownership");
		return false;
	}

	private boolean puzzleChallenge(ObjectInputStream is,
		ObjectOutputStream os) throws Exception
	{
		byte[] b = new byte[64];
		Envelope e = new Envelope("HASHCHALLENGE");

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] hash;

		Long response;

		new SecureRandom().nextBytes(b);
		e.addObject(b);
		os.writeObject(e);

		/* Get response and verify */
		response = (Long)((Envelope) is.readObject()).getObjContents().get(0);
		md.update(b);
		hash = md.digest(Puzzle.Converter.longToBytes(response));

		return Puzzle.valid(hash, Puzzle.LEADING_ZEROS);
	}
}
