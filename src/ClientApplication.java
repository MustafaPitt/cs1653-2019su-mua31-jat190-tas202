
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;


/* client application  to connect  with group server  */
public class ClientApplication {

	private static String gs_server_name;
	private static int gs_port;
	private static String fs_server_name;
	private static int fs_port;

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
						}else{
							username = token.getSubject();
						}


            System.out.println("1)Login to group server 2) Connect to File Server 3) exit");
            String input = scanner.next();
            if (!input.matches("[0-9]")){
                System.out.println("Invalid input");
                continue;
            }
            else if (input.equals("1")) connectToGroupServer(username);
            else if (input.equals("2")) connectToFileServer(username);
						else if (input.equals("3")) break;

            }

        }

    private static void connectToFileServer(String username) {
					Scanner scanner = new Scanner(System.in);
					System.out.print("Enter GROUP server address: ");
		 			gs_server_name = scanner.nextLine();
					System.out.print("Enter GROUP server port number:");
					gs_port = scanner.nextInt();

					groupClient.connect(gs_server_name, gs_port);
					token = (Token) groupClient.getToken(username); //update token
 				  groupClient.disconnect();

						System.out.print("Enter FILE server address: ");
						scanner.nextLine();
						fs_server_name = scanner.nextLine();
						System.out.print("Enter FILE server port number: ");
						fs_port = scanner.nextInt();

            fileClient = new FileClient();
            fileClient.connect(fs_server_name, fs_port);

            if (fileClient.isConnected()) System.out.println("application is connected to client server");
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


    // handle all group server operations
     private static void connectToGroupServer(String username) {
			 Scanner scanner = new Scanner(System.in);
			 System.out.print("Enter group server address: ");
			 gs_server_name = scanner.nextLine();
			 System.out.print("Enter group server port number:");
			 gs_port = scanner.nextInt();

			 groupClient.connect(gs_server_name, gs_port);
			 token = (Token) groupClient.getToken(username); //update token

         System.out.println("Connecting to Group Server Menu");

				 if (groupClient.isConnected()) {
             System.out.println("application is connected to group server");

             if(token != null) groupServerMenu();
             else System.out.println("Couldn't verify your user name");
         }

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

    private static void groupServerMenu() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("********** Client USER MENU **********");
        while (true) {

						token = (Token) groupClient.getToken(token.getSubject()); //update token

            System.out.println("1) create a user \n2) del a user\n3) create a group " +
                    "\n4) delete a group \n5) list group members \n6) Add User to Group \n7) Remove user from Group \n8) logout");
            String input = scanner.next();
            if (!Pattern.matches("[0-9]", input)) System.out.println("invalid input");
            else if (input.equals("1")) createUserInGS();
            else if (input.equals("2")) delUserFromGS();
            else if (input.equals("3")) createGroupInGS();
            else if (input.equals("4")) delGroupInGS();
            else if (input.equals("5")) listMembersGroup();
						else if (input.equals("6")) addUserToGroup();
						else if (input.equals("7")) delUserFromGroup();
            else if (input.equals("8")) {
                System.out.println("logging out");
                groupClient.disconnect();
                return;
            }
        }
    }

    private static void listMembersGroup() {
			try {
					System.out.println("........... list members group menu ..........");
					System.out.println("Enter a group name");
					Scanner scanner = new Scanner(System.in);
					String groupName = scanner.next();
					List<String> members = groupClient.listMembers(groupName, token);
					if (members != null) {
							for (String s : members) {
									System.out.println(s);
							}
					}
					else
							System.out.println("No a such group exist or check permissions");
			}catch (Exception Ignore){
					System.out.println("No a such group exist or check permissions");
			}
    }

    private static void delGroupInGS() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........delete a group menu ..........");
        System.out.println("Enter a group name to delete");
        String groupName = scanner.next();

        if (groupClient.deleteGroup(groupName,token)){
            System.out.println("group " + groupName + " deleted successfully");
						// refresh the server
						groupClient.disconnect();
            groupClient.connect(gs_server_name, gs_port);
				}
        else System.out.println("Error deleting a group");

    }

    private static void createGroupInGS() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........create a group menu ..........");
        System.out.println("Enter a group name to create");

        String groupName = scanner.next();
        if (groupClient.createGroup(groupName,token)){
            System.out.println("group " + groupName + " created successfully");
						// refresh the server
            groupClient.disconnect();
            groupClient.connect(gs_server_name, gs_port);
        }
        else System.out.println("Error creating a group");

		}

    private static void delUserFromGS() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........delete user menu ..........");
        System.out.println("Enter a username to delete");
        String username = scanner.next();
        if (groupClient.deleteUser(username,token)){
            System.out.println("user " + username + " deleted successfully");
						// refresh the server
            groupClient.disconnect();
            groupClient.connect(gs_server_name, gs_port);
				}
        else System.out.println("Error deleting  a user");

    }

    private static void createUserInGS() {
         Scanner scanner = new Scanner(System.in);
         System.out.println("...........Create new user menu ..........");
         System.out.println("Enter a new username");
         String username = scanner.next();
         if (groupClient.createUser(username,token)){
             System.out.println("user " + username + " created successfully");
						 // refresh the server
             groupClient.disconnect();
             groupClient.connect(gs_server_name, gs_port);
				 }
         else System.out.println("Error creating a user");

     }

		 private static void addUserToGroup() {
			 try {
					 System.out.println("........... add user to a group menu ..........");
					 System.out.println("Enter a group name");
					 Scanner scanner = new Scanner(System.in);
					 String groupName = scanner.next();
					 System.out.println("Enter a user name to be added to a group " + groupName);
					 String userToBeAdd = scanner.next();
					 if(groupClient.addUserToGroup(userToBeAdd,groupName,token)){
							 System.out.println("User " + userToBeAdd + " added to group " + groupName + " successfully ");
							 // refresh the server
							 groupClient.disconnect();
							 groupClient.connect(gs_server_name, gs_port);
					 }
					 else
							 System.out.println("Error adding user to a group");

			 }catch (Exception Ignore){
					 System.out.println("Error adding user to a group");
			 }
      }

			private static void delUserFromGroup() {
	        try {
	            System.out.println("........... dell user from a group menu ..........");
	            System.out.println("Enter a group name");
	            Scanner scanner = new Scanner(System.in);
	            String groupName = scanner.next();
	            System.out.println("Enter a user name to be deleted from a group " + groupName);
	            String userToBeDel = scanner.next();
	            if(groupClient.deleteUserFromGroup(userToBeDel,groupName,token)){
	                System.out.println("User " + userToBeDel + " deleted from group " + groupName + " successfully ");
	                // refresh the server
	                groupClient.disconnect();
	                groupClient.connect(gs_server_name, gs_port);
	            }
	            else
	                System.out.println("Error deleting  user from group" + groupName);

	        }catch (Exception Ignore){
	            System.out.println("Error adding user to a group");
	        }
	    }



 }
