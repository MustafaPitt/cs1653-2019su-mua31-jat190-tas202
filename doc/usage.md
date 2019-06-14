# Running the program:
1. Open 3 terminals all in the src/ directory.
2. In one run: java RunFileServer <port_num>
3. In another run: java RunGroupServer <port_num>
4. If this is the first time running RunGroupServer, enter a username to be the admin upon request.
5. In the final run: java ClientApplication

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


# Known Error:
1. Reproduction steps: Upload a file to FS, Download same file, Delete same file
2. --> Error deleting file <filename>
3. This, however, doesn't not occur when doing the same steps minus the download.
4. We did not implement upload, download, or delete so I don't think this is our error.
