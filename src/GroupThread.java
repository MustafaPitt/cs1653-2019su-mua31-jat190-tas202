/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */


import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	private byte[] agreedKeyGSDH;

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
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						//hashes the token and signs it
						assert yourToken != null;
						yourToken.updateHashToken(my_gs.privateKeySig);

						//encrypting token and signed hash token
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						ObjectOutputStream os = new ObjectOutputStream(out);
						AES aes = new AES();
						byte[][] cipherTokenWithIV = new byte[0][0];
						System.out.println("DBG group thread 63 : printing Agreed key " + Arrays.toString(agreedKeyGSDH));
						SecretKeySpec secretKey = new SecretKeySpec(agreedKeyGSDH,"AES");
						boolean done = false;

						try {
							os.writeObject(yourToken);
							cipherTokenWithIV = aes.cfbEncrypt(secretKey, out.toByteArray());
						} catch (GeneralSecurityException e) {
							e.printStackTrace();
							output.writeObject(new Envelope("FAIL"));
							return;
						}
						//Respond to the client. On error, the client will receive a null token
							response = new Envelope("OK");
							response.addObject(cipherTokenWithIV);
							output.writeObject(response);

					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(createUser(username, yourToken))
								{
									System.err.println("got here 4");
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(createGroup(groupName, yourToken))
								{
									System.err.println("got here 4");
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(deleteGroup(groupName, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);
				}

				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								List<String> groupMembers = listAllMembersInGroup(groupName, yourToken);

								response = new Envelope("OK"); //Success
								response.addObject(groupMembers);
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);

				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								System.err.println("dbg add user to a group ");
								String groupName = (String)message.getObjContents().get(0); //Extract the group name
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								String userToAdd = (String)message.getObjContents().get(2); //Extract the user name to be added
								if(addUserToGroup(groupName,yourToken,userToAdd))
								{
									response = new Envelope("OK"); //Success
								}
								else
									response = new Envelope("FAIL");
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);

				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					/* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								System.err.println("dbg del user from a group ");
								String groupName = (String)message.getObjContents().get(0); //Extract the group name
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								String userToRemove = (String)message.getObjContents().get(2); //Extract the user name to be deleted
								System.err.println("DBG Grp Thrd group name " + groupName + " user to remove " + userToRemove);
								if(removeUserFromGroup(groupName,yourToken,userToRemove))
								{
									response = new Envelope("OK"); //Success
								}
								else
									response = new Envelope("FAIL");
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);


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
					response = 	verifyPwAndUsernameFromClientApp(message);
					if (response.getMessage().equals("OK")) {
						System.out.println("password correct");
						output.writeObject(response);

					} else {
						System.out.println("password incorrect");
						output.writeObject(response);
					}

				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
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
		byte username[] = new byte[0];
		byte pw[] = new byte[0];
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
			return  new Envelope("Fail");

		HMAC hmac = new HMAC();
		try {
			hashedPW = 	hmac.calculateHmac(my_gs.hashPWSecretKey,pw);
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		String userStr = new String(username);
		String pwStr = new String(hashedPW);

		if(my_gs.userList.getUser(userStr).getPwHash().equals(pwStr)){
			return new Envelope("OK");
		}
		return new Envelope("FAIL");


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
		try {
			if (rsa.verifyPkcs1Signature(pk,bytesMsg,sigbytes)){
				DH dh = new DH();
				KeyPair keyPairGSDH = dh.generateKeyPair(((DHPublicKey)clientDHPK).getParams());
				agreedKeyGSDH  =  dh.initiatorAgreementBasic(keyPairGSDH.getPrivate(),clientDHPK);
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
				return true;

			}

		}

		return false; //user not exsit

	}

	//Method to create tokens
	private UserToken createToken(String username)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username),
					my_gs.userList.getUserOwnership(username));
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

						KeyPair keyPair = rsa.generateKeyPair();
						PublicKey clientPublicKey = keyPair.getPublic();
						PrivateKey clientPrivateKey = keyPair.getPrivate();

						try {
							outStreamGroup = new ObjectOutputStream(new FileOutputStream(username + "_clientPrivate.bin"));
							outStreamGroup.writeObject(clientPrivateKey);


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
								my_gs.userList.getUserOwnership(username)));
					}

					// remove all groups that user own
					for (String groupOwn : my_gs.userList.getUserOwnership(username)){
						if(my_gs.groupMembers.containsKey(groupOwn))
							my_gs.groupMembers.remove(groupOwn);
					}
					for (String group : my_gs.userList.getUserGroups(username)){
						if(my_gs.groupMembers.containsKey(group))
							my_gs.groupMembers.get(group).remove(username);
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
			System.err.println("group delete successfully ");
			return true;
		}
		System.err.println("Error Del group: check user or ownership");
		return false;
	}

}
