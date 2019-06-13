
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;


/* client application  to connect  with group server  */
public class ClientApplication {

    private static String gs_server_name;
    private static String gs_port;
    public static void main (String []args){

        while (true){
            Scanner scanner = new Scanner(System.in);
            System.out.println("1)Login to group server 2) Connect to File Server 3) exit");
            String input = scanner.next();
            if (!input.matches("[0-9]")){
                System.out.println("Invalid input");
                continue;
            }
            else if (input.equals("1")) connectToGroupServer();
            else if (input.equals("2")) connectToFileServer();
            else if (input.equals("3")) break;

            }

        }

    private static void connectToFileServer() {
        {
            // make sure the client is authorized /*.... TO DO .....*/
            FileClient fileClient = new FileClient();
            fileClient.connect("localhost", 7777);
            if (fileClient.isConnected()) System.out.println("application is connected to client server");
            Scanner scanner = new Scanner(System.in);
            while(true){ // while you are in file server
                System.out.println("1) log out");
                String input = scanner.next();
                if (!input.matches("[0-9]")) System.out.println("invalid input");
                if(input.equals("1")) {
                    System.out.println("Logging out");
                    fileClient.disconnect();
                    return;
                }
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
           gs_server_name = scanner.next();
          System.out.println("input port number");
           gs_port = scanner.next();
         if (!gs_port.matches("[0-9]+")){
             System.out.println("Invalid port input ");
             return;
         }
          groupClient.connect(gs_server_name,Integer.parseInt(gs_port)); // need to be check latter
         if (groupClient.isConnected()) {
             System.out.println("application is connected to group server");
             System.out.println("Enter your user name"); // if the user name is in admin group
             String adminUser = scanner.next();
             Token token = (Token) groupClient.getToken(adminUser);
             if (token != null)groupServerAdminMenu(groupClient, adminUser);
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


    private static void groupServerAdminMenu(GroupClient groupClient, String adminUser) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("********** Client Application MENU **********");
        while (true) {
            System.out.println("1) create a user \n2) del a user\n3) create a group " +
                    "\n4) delete a group \n5) list group members\n6) add user to a group\n7) del user from a group" +
                    " \n8) logout");
            String input = scanner.next();
            if (!Pattern.matches("[0-9]", input)) System.out.println("invalid input");

            else if (input.equals("1")) createUserInGS(groupClient, adminUser);
            else if (input.equals("2")) delUserFromGS(groupClient,adminUser);
            else if (input.equals("3")) createGroupInGS(groupClient,adminUser);
            else if (input.equals("4")) delGroupInGS(groupClient,adminUser);
            else if (input.equals("5")) listMembersGroup(groupClient,adminUser);
            else if (input.equals("6")) addUserToGroup(groupClient,adminUser);
            else if (input.equals("7")) delUserFromGroup(groupClient,adminUser);
            else if (input.equals("8")) {
                System.out.println("logging out");
                groupClient.disconnect();
                return;
            }
        }
    }

    private static void delUserFromGroup(GroupClient groupClient, String adminUser) {
        try {
            System.out.println("........... dell user from a group menu ..........");
            System.out.println("Enter a group name");
            Scanner scanner = new Scanner(System.in);
            String groupName = scanner.next();
            System.out.println("Enter a user name to be deleted from a group " + groupName);
            String userToBeDel = scanner.next();
            Token token = (Token) groupClient.getToken(adminUser);
            if(groupClient.deleteUserFromGroup(userToBeDel,groupName,token)){
                System.out.println("User " + userToBeDel + " deleted from group " + groupName + " successfully ");
                // refresh the server
                groupClient.disconnect();
                groupClient.connect(gs_server_name,Integer.parseInt(gs_port));
            }
            else
                System.out.println("Error deleting  user from group" + groupName);

        }catch (Exception Ignore){
            System.out.println("Error adding user to a group");
        }
    }

    private static void addUserToGroup(GroupClient groupClient, String user) {
        try {
            System.out.println("........... add user to a group menu ..........");
            System.out.println("Enter a group name");
            Scanner scanner = new Scanner(System.in);
            String groupName = scanner.next();
            System.out.println("Enter a user name to be added to a group " + groupName);
            String userToBeAdd = scanner.next();
            Token token = (Token) groupClient.getToken(user);
            if(groupClient.addUserToGroup(userToBeAdd,groupName,token)){
                System.out.println("User " + userToBeAdd + " added to group " + groupName + " successfully ");
                // refresh the server
                groupClient.disconnect();
                groupClient.connect(gs_server_name,Integer.parseInt(gs_port));
            }
            else
                System.out.println("Error adding user to a group");

        }catch (Exception Ignore){
            System.out.println("Error adding user to a group");
        }
    }

    private static void listMembersGroup (GroupClient groupClient, String user) {
        try {
            System.out.println("........... list members group menu ..........");
            System.out.println("Enter a group name");
            Scanner scanner = new Scanner(System.in);
            String groupName = scanner.next();
            Token token = (Token) groupClient.getToken(user);
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

    private static void delGroupInGS(GroupClient groupClient, String adminUser) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........delete a group menu ..........");
        System.out.println("Enter a group name to delete");
        String groupName = scanner.next();
        Token token = (Token) groupClient.getToken(adminUser);
        if (groupClient.deleteGroup(groupName,token)){
            System.out.println("group " + groupName + " deleted successfully");
            // refresh the server
            groupClient.disconnect();
            groupClient.connect(gs_server_name,Integer.parseInt(gs_port));
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
            // refresh the server
            groupClient.disconnect();
            groupClient.connect(gs_server_name,Integer.parseInt(gs_port));
        }
        else System.out.println("Error creating a group");
    }

    private static void listAllUsers(GroupClient groupClient, String adminUser) {
        System.out.println("coming soon. This method should return all the users in " +
                "the group server");
    }

    private static void delUserFromGS(GroupClient groupClient,String adminUsername) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("...........delete user menu ..........");
        System.out.println("Enter a username to delete");
        Token token = (Token) groupClient.getToken(adminUsername);
        String username = scanner.next();
        if (groupClient.deleteUser(username,token)){
            System.out.println("user " + username + " deleted successfully");
            // refresh the server
            groupClient.disconnect();
            groupClient.connect(gs_server_name,Integer.parseInt(gs_port));
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
             // refresh the server
             groupClient.disconnect();
             groupClient.connect(gs_server_name,Integer.parseInt(gs_port));
         }
         else System.out.println("Error creating a user");
     }
 }
