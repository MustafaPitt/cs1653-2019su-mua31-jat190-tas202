

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;


/* client application  to connect  with group server  */
public class ClientApplication {


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
          String server = scanner.next();
          System.out.println("input port number");
          String port = scanner.next();
          groupClient.connect(server,Integer.parseInt(port)); // need to be check latter
         if (groupClient.isConnected()) {
             System.out.println("application is connected to group server");
             System.out.println("Enter your admin account");
             String adminUser = scanner.next();
             Token token = (Token) groupClient.getToken(adminUser);
             System.out.println("token is " + token.getGroups() + "issuer  " + token.getIssuer() + "subject"+  token.getSubject());
             if (groupClient.isConnected()){ // check if the user is a member of group admin
                 System.out.println("You are logged in as " + adminUser);
                 groupServerAdminMenu(groupClient);
            }
        }
         else
             System.out.println("Error connecting to a group server");
     }

    private static void groupServerAdminMenu(GroupClient groupClient) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("1) create a user \n2) logout");
            String input = scanner.next();
            if (!Pattern.matches("[0-9]", input)) System.out.println("invalid input");
            else if (input.equals("1")) {
                createUserInGroupServer(groupClient, "admin");
                continue;
            } else if (input.equals("2")) {
                System.out.println("logging out");
                groupClient.disconnect();
                return;
            }
        }
    }

    private static void createUserInGroupServer(GroupClient groupClient, String adminUsername) {
         Scanner scanner = new Scanner(System.in);
         System.out.println("...........Create new user menu ..........");
         System.out.println("Enter a new username");
         Token token = (Token) groupClient.getToken("admin");
         String username = scanner.next();

         if (groupClient.createUser(username,token)) System.out.println("user " + username + " created successfully");
     }
 }
