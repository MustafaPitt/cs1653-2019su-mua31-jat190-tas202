
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;


/* client application  to connect  with group server  */
public class ClientApplication {

	static final int GROUP_PORT = 8000;
	static final int FILE_PORT = 8001;

	static GroupClient groupClient;
	static FileClient fileClient;
	static UserToken token;

    public static void main (String []args){
		groupClient = new GroupClient();
		fileClient = new FileClient();
		boolean signedIn = false;
        while (true){
            Scanner scanner = new Scanner(System.in);
						String username = null;

						if(signedIn == false){
							System.out.println("Username: ");
							username = scanner.nextLine();
							signedIn = true;
						}

						// Get token
						groupClient.connect("localhost", GROUP_PORT);
						token = groupClient.getToken(username);

            System.out.println("1)Login to group server 2) Connect to File Server 3) exit");
            String input = scanner.next();
            if (!input.matches("[0-9]")){
                System.out.println("Invalid input");
                continue;
            }
            else if (input.equals("1")) connectToGroupServer();
            else if (input.equals("2")) connectToFileServer();

            }

        }

    private static void connectToFileServer() {
        {
            // make sure the client is authorized /*.... TO DO .....*/
            fileClient = new FileClient();
            fileClient.connect("localhost", FILE_PORT);
            if (fileClient.isConnected()) System.out.println("application is connected to client server");
            Scanner scanner = new Scanner(System.in);
            while(true){ // while you are in file server
							System.out.println("1. List files\n" +
				                   "2. Upload\n" +
				                   "3. Download\n" +
				                   "4. Delete\n" +
				                   "5. Log out\n");
              String input = scanner.next();

				if (input.equals("1")) { // list files
					System.out.println(fileClient.listFiles(token));
				}

				if (input.equals("2")) { // upload
					String source;
					String dest;
					String group;

					System.out.print("Source?: ");
					scanner.nextLine();
					source = scanner.nextLine();
					System.out.print("Dest?: ");
					dest = scanner.nextLine();
					System.out.print("Groups?: ");
					group = scanner.nextLine();

					System.out.println(fileClient.upload(source, dest,
						group, token));
				}

				if (input.equals("3")) { // Download a file
					String source;
					String dest;

					System.out.print("Source?: ");
					scanner.nextLine();
					source = scanner.nextLine();
					System.out.print("Dest?: ");
					dest = scanner.nextLine();

					System.out.println(fileClient.download(source, dest, token));

				}

				if (input.equals("4")) { // Delete a file
					String filename;

					System.out.print("Filename to delete?: ");
					scanner.nextLine();
					filename = scanner.nextLine();

					System.out.println(fileClient.delete(filename, token));

				}

        if(input.equals("5")) {
          System.out.println("Logging out");
          fileClient.disconnect();
          return;
        }

				if (!input.matches("[1-5]")) System.out.println("invalid input");
      }
    }
}


    // handle all group server operations
     private static void connectToGroupServer() {

         GroupClient groupClient = new GroupClient();
         System.out.println("Connecting to Group Server Menu");
         Scanner scanner = new Scanner(System.in);
//         // establish connection with group server
          System.out.println("Input server address");
          String server = scanner.next();
          System.out.println("input port number");
          String port = scanner.next();
          groupClient.connect(server,Integer.parseInt(port)); // need to be check latter
         if (groupClient.isConnected()) {
             System.out.println("application is connected to group server");
             System.out.println("Enter your Admin account"); // if the user name is in admin group
             String adminUser = scanner.next();
// <<<<<<< HEAD
//              token = (Token) groupClient.getToken(adminUser);
//              System.out.println("token is " + token.getGroups() + "issuer  " + token.getIssuer() + "subject"+  token.getSubject());
//              if (groupClient.isConnected()){ // check if the user is a member of group admin
//                  System.out.println("You are logged in as " + adminUser);
//                  groupServerAdminMenu(groupClient);
//             }
//         }
// =======
             token = (Token) groupClient.getToken(adminUser);
             if (token != null && isUserInAdminGroup(token.getGroups())) groupServerAdminMenu(groupClient, adminUser);
             else System.out.println("Couldn't verify your user name");
         }
// >>>>>>> origin/mustafa2
         else
             System.out.println("Error connecting to a group server");
     }

     // return true if the use in the admin group
    private static boolean isUserInAdminGroup(List<String> groups) {
        try {
        for(String s : groups){
            if (s.equals("ADMIN")) return true;
        }
        return false;
        }catch (Exception Ignore){ return false;}
    }

    private static void groupServerAdminMenu(GroupClient groupClient, String adminUser) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("********** ADMIN USER MENU **********");
        while (true) {
            System.out.println("1) create a user \n2) del a user\n3) list all users\n4) create a group " +
                    "\n5) delete a group \n6) list group members \n7)Add User to Group \n8)Remove user from Group \n9) logout");
            String input = scanner.next();
            if (!Pattern.matches("[0-9]", input)) System.out.println("invalid input");

            else if (input.equals("1")) createUserInGS(groupClient, adminUser);
            else if (input.equals("2")) delUserFromGS(groupClient,adminUser);
            // else if (input.equals("3")) listAllUsers(groupClient,adminUser);
            else if (input.equals("4")) createGroupInGS(groupClient,adminUser);
            else if (input.equals("5")) delGroupInGS(groupClient,adminUser);
            else if (input.equals("6")) listMembersGroup(groupClient,adminUser);
						else if (input.equals("7")) addUserToGroup(groupClient,adminUser);
						//else if (input.equals("8")) removeUserFromGroup(groupClient,adminUser);
            else if (input.equals("9")) {
                System.out.println("logging out");
                groupClient.disconnect();
                return;
            }
        }
    }

    private static void listMembersGroup(GroupClient groupClient, String user) {
        System.out.println("........... list members group menu ..........");
        System.out.println("Enter a group name");
        Scanner scanner = new Scanner(System.in);
        String groupName =  scanner.next();
        Token token = (Token) groupClient.getToken(user);
        System.out.println(groupClient.listMembers(groupName,token));
    }

    private static void delGroupInGS(GroupClient groupClient, String adminUser) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........delete a group menu ..........");
        System.out.println("Enter a group name to delete");
        String groupName = scanner.next();
        Token token = (Token) groupClient.getToken(adminUser);
        if (groupClient.deleteGroup(groupName,token)){
            System.out.println("group " + groupName + " deleted successfully");
        }
        else System.out.println("Error deleting a group");
    }

    private static void createGroupInGS(GroupClient groupClient, String adminUser) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........create a group menu ..........");
        System.out.println("Enter a group name to create");
        Token token = (Token) groupClient.getToken(adminUser);
        String groupName = scanner.next();
        if (groupClient.createGroup(groupName,token)){
            System.out.println("group " + groupName + " created successfully");
        }
        else System.out.println("Error creating a group");
    }

    // private static void listAllUsers(GroupClient groupClient, String adminUser) {
    //     System.out.println("coming soon. This method should return all the users in " +
    //             "the group server");
    // }

    private static void delUserFromGS(GroupClient groupClient,String adminUsername) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........delete user menu ..........");
        System.out.println("Enter a username to delete");
        Token token = (Token) groupClient.getToken(adminUsername);
        String username = scanner.next();
        if (groupClient.deleteUser(username,token)){
            System.out.println("user " + username + " deleted successfully");
        }
        else System.out.println("Error deleting  a user");
    }

    private static void createUserInGS(GroupClient groupClient, String adminUsername) {
         Scanner scanner = new Scanner(System.in);
         System.out.println("...........Create new user menu ..........");
         System.out.println("Enter a new username");
         Token token = (Token) groupClient.getToken(adminUsername);
         String username = scanner.next();
         if (groupClient.createUser(username,token)){
             System.out.println("user " + username + " created successfully");
         }
         else System.out.println("Error creating a user");
     }

		 private static void addUserToGroup(GroupClient groupClient, String adminUsername) {
          Scanner scanner = new Scanner(System.in);
          System.out.println("...........Adding A User to a Group ..........");
          System.out.println("Enter a username that is being added:");
          Token token = (Token) groupClient.getToken(adminUsername);
          String username = scanner.next();

					System.out.println("Enter the group name:");
					String groupname = scanner.next();

					//does the new username exist
					if(!groupClient.userList.checkUser(username)){
						System.out.println("This user doesn't exist.");
					}

					//is the user the owner of the group
					else if(!token.getOwnership().contains(groupName)){
						System.out.println("You must be the owner of a group to add new members.");
					}

					else{
						if(!groupClient.addUserToGroup(username, groupname, token)){
							System.out.println("Error adding user to group.");
						}
							System.out.println("User succesfully added to group.");
					}


      }



 }
