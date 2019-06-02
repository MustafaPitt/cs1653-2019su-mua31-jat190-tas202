

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


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
            else if (input.equals("2")){
                // make sure the client is authorized /*.... TO DO .....*/
                FileClient fileClient = new FileClient();
                fileClient.connect("localhost", 4321);
                if (fileClient.isConnected()) System.out.println("application is connected to client server");
                while(true){ // while you are in file server



                }

            }

        }

    }


    // handle all group server operations
     private static void connectToGroupServer() {
         // make sure the client is authorized ex only ADMIN can log in /*.... TO DO .....*/
         GroupClient groupClient = new GroupClient();
         System.out.println("Connecting to group server ........");
         Scanner scanner = new Scanner(System.in);
         // simple user and password handler
         System.out.println("Enter your username");
         String username = scanner.next();
         System.out.println("Enter your password");
         String pw = scanner.next();
         if(username.equals("admin")&&pw.equals("admin") ) {
             groupClient.connect("localhost", 8765); // need to be check latter
             if (groupClient.isConnected()) System.out.println("application is connected to group server");
             while (true){
                 System.out.println("1) create a user \n2) logout");
                 String input = scanner.next();
                 System.out.println("DBG input  " + input );
                 if (!input.matches("[0-9]]"))System.out.println("invalid input");

                 if(input.equals("1")) createUserInGroupServer(groupClient,"admin");

             }

         }
         else System.out.println("invalid username or password");
     }

     private static void createUserInGroupServer(GroupClient groupClient, String adminUsername) {
         Scanner scanner = new Scanner(System.in);
         System.out.println("...........Create new user menu ..........");
         System.out.println("Enter new username");
         String username = scanner.next();
         Token token = new Token(adminUsername,"server 1 ", new ArrayList<String>());
         if (groupClient.createUser(username,token)) System.out.println("user " + username + " created successfully");


     }
 }
