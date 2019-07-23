# Running each program
* The file server can be run with the command
  `java .:/path/to/bc.jar
  FileServer <port number>`.
* The group server can be run with the command
  `java .:/path/to/bc.jar
  GroupServer <port number>`.
* The client application can be run with the command
  `java .:/path/to/bc.jar ClientApplication`

# Getting set up
If the programs are running in separate directories or on separate
computers, some preliminary setup is required. These are the out-of-band
communications that are needed to first exchange all of the required
keys.
1. From the group server's directory, run the group server to generate a
   keypair and create the admin user. 
4. Copy the group server's public key to the file server's directory and
the client application's directory.
5. Copy the created user's keypair to the client application directory.
5. From the file server's directory, run the file server to
generate a keypair.
6. Copy the file server's public key to the client application's
directory.

# ClientApplication Operations:
1. Upon starting ClientApplication, you will be asked for your username, enter it.
2. From the initial menu has 3 options, entering 1-3 will select the respective option.
3. Upon selecting 1, you will need to enter the group server address, and port number.
4. Upon selecting 2, you will need to enter the group server's address and port number, followed by the fileserver's address and port number.
5. Upon selecting 3, you will exit the program.

# ClientApplication -> Group Server Operations:
1. The group server menu has 8 operations, entering 1-8 will select the respective option.
2. Entering 1 will prompt you to enter a username to create.
3. Entering 2 will prompt you to enter a username to remove.
4. Entering 3 will prompt you to enter a group name to create.
5. Entering 4 will prompt you to enter a group name to remove.
6. Entering 5 will prompt you to enter a group name to list the members of.
7. Entering 6 will prompt you to enter a group name and a username to add that user to the group.
8. Entering 7 will prompt you to enter a group name and a username to remove that user from the group.
9. Entering 8 will log you out of the group server.

# ClientApplication -> File Server Operations:
1. The file server menu has 5 operations, entering 1-5 will select the respective option.
2. Entering 1 will list the files the current user has access to.
3. Entering 2 will prompt you to enter a source filename, a destination filename, and group name to upload a file to that group.
4. Entering 3 will prompt you to enter a source filename and a destination filename to download a file from the system.
5. Entering 4 will prompt you to enter a filename to delete.
6. Entering 5 will log you out of the file server.
