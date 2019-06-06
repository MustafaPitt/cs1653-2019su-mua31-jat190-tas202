/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	
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
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					System.err.println("got here");
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
								System.err.println("dbg list member got her");
								String groupName = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								List<String> groupMembers = listAllMembersInGroup(groupName, yourToken);

								if(groupMembers!= null)
								{
									response = new Envelope("OK"); //Success
									response.addObject(groupMembers);
								}
							}
						}
					}
					System.err.println(response.getMessage());
					output.writeObject(response);

				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    /* TODO:  Write this handler */
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
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

	private List<String> listAllMembersInGroup(String groupName, UserToken token) {
		// check if the user is the ownership of the group
		// check if the user is admin or the ownership of the group
		String requester = token.getSubject();
		System.err.println("DBG print requester " + requester + " the group memebers" + my_gs.groupMembers.get(groupName));
		if(my_gs.userList.getUserOwnership(requester).contains(groupName)) {
			return  my_gs.groupMembers.get(groupName);
		}
		return null;
	}

	private boolean createGroup(String groupName, UserToken yourToken) {

		String requester = yourToken.getSubject();

		//Check if requester exists/ any user can create a group
		if(my_gs.userList.checkUser(requester))
		{
			// check not a such group created before
			if(my_gs.userList.getUserGroups(requester).contains(groupName)){
				System.err.println("Group already exists");
				return false;
			}
			else{
				my_gs.userList.addGroup(requester,groupName); // add group
				my_gs.userList.addOwnership(requester,groupName);
				List<String> memebrsList = new ArrayList<>();
				my_gs.groupMembers.put(groupName,memebrsList);
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
	private boolean createUser(String username, UserToken yourToken)
	{
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
				System.err.println("got here 2");
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					System.err.println("got here 3");
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
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
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
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
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
		if(my_gs.userList.getUserGroups(requester).contains("ADMIN") ||
				my_gs.userList.getUserOwnership(requester).contains(groupName)){

			// check if the group want to be del is exist
			if (my_gs.userList.getUserGroups(requester).contains(groupName)){
				System.err.println("No such a group " + groupName + " exist");
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
