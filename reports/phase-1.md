# CS 1653 -- Term Project 1

##Mustafa Alazzawi, James Tomko, Tanner Stauffer
##Pitt username: mua31, jat190, tas202
##Due date: 5/27/2019

### Security Properties: 

- **Property 1:**

 1)  Individuality  
 2) Every user in the domain can create a username and password to login.
 3) Individuality is important because we need to have a unique way of identifying  each user. Also, since each user creates their own password, we known they are who they say they are, and this provides a base level of integrity.
 4) We are assuming no two users have same username and no users will share their password.

- **Property  2:**
 1) User Deletion
 2) Each user can delete only his/her own profile.
 3) If a user is only the person who can delete his/her account then the system more secure since the user is the only person able to access this account.
 4) We are assuming the account only used by one person and that the account is not hacked.
 
-  **Property 3:**
 1) Group Creation
 2) Each user can create a group by adding other users.
 3) The creator of a group will designate them the admin of the group. This will give the group a level of control in being able to manage levels of access to files.
 4) We are assuming the other user’s usernames are available to add when we search for them. Also, that each user is who the say they are (they are not being hacked).    

- **Property 4:**
 1) Unique Group Name (ID)
 2) No two group should have same name.
 3) Having no two groups with the same name will help users avoid confusion and from being deceived into providing information to the wrong group.
 4) We are assuming users can be in multiple groups simultaneously and each group works in their own space.      

- **Property 5:**
 1) Permission To Invite
 2) Anyone in the group can invite any existing users to the group.
 3) Each user in the group has the flexibility to expand the size of the group
 4) We are assuming the other user’s usernames are available to add when we search for them. Also, that each user is who they say they are (they are not being hacked).

- **Property 6:**
 1) Permission To Remove
 2) Anyone in the group can remove himself from the group, but cannot remove others.
 3) If a user is only the person who remove his/her account from a group then it’s more secure since the user is the only person able to access this account. Also, this avoids other users from unjustly removing someone from the group.
 4) We are assuming the account only used by one person and we assuming that the account is not hacked.

- **Property 7:**
 1) Admin Permission To Remove
 2) Only the admin, “the creator or the group,” can remove anyone from the group.
 3) This is important the give a level of control to remove users who are threats, not productive, or no longer an active participant of the group.
 4) We are assuming each group has one admin and that the admin account has not been compromised by a hacker.

- **Property 8:**
 1) Admin Assigns File Viewing Permission
 2) The admin can give or remove the group’s users permission for read a file.
 3) This gives the admin control over who is allowed to view the information in each file. It can be restricted if some user in the group is not allowed to see a certain file.
 4) We assume each new user has read access to each file by default. We are assuming each group has one admin and that the admin account has not been compromised by a hacker.
 
- **Property 9:**
 1) Admin Assigns File Writing Permission
 2) The admin can give or remove the group’s users permission for write to a file.
 3) This gives the admin control over who is allowed to edit the information in each file. It can be restricted if some user in the group is not allowed to edit a certain file.
 4) We assume each new user has does not have write access to all files by default.  We are assuming each group has one admin and that the admin account has not been compromised by a hacker.      


- **Property 10:**
 1) Download Permission
 2) Any user in a group can download any file within the group space.
 3) We want users in a group to have access to be able to download files to give a flexibility and increase to work productivity.
 4) We are assuming user have the capability to download files to their system.and that users can only view files of groups they are part of.         

- **Property 11:**
 1) File Write Permission
 2) Only user with write permission can delete or overwrite a file.
 3) This is important to prevent unauthorized people from deleting or overwriting group files.
 4) We are assuming write permission was previously granted to these users and each user with write permissions has not been compromised by a hacker.

- **Property 12:**
 1) Group File Quota
 2) Each group has x initial space that can be increased based on the system configuration.
 3) It’s important to prevent a single group from using all the available space.
 4) We are assuming each user is using only one account, so they are not exploiting the quota. We are assuming the system’s servers have a limited amount of space.

- **Property 13:**
 1) Complete Mediation
 2) Every time a user does any operation then it needs to be checked if that user has the correct permission to perform that.
 3) It’s a good a way to keep the integrity of the system safe and keep it free of deception.
 4) We are assuming the credential server is not compromised, and unauthorized users can’t get access to the token.   
 
- **Property 14:**
 1) Separation Of Privileges
 2) Any user logging into the system needs 2 steps verification.
 3) Add another level of confidentiality and integrity to the login phase.
 4) Adding 2 step verification make it more difficult for another user to access an account that is not theirs.

- **Property 15:**
 1) Login Attempt Limit
 2) Block the user login temporary after 5 times failing access.
 3) It delays brute force passwords hacking algorithms.
 4) We are assuming users know their passwords and passwords has some level of complexity.

- **Property 16:**
 1) Open Design
 2) The system will use public encryption algorithm such RSA , AES etc.
 3) Hackers should know the system and still be unable to break it.
 4) We assuming the algorithms are secured methods of encrypting data and our keys are secrets. Assuming only trusted parties have access to the keys.

- **Property 17:**
 1) Psychological Acceptability
 2) The system should be user-friendly.
 3) If the system is so complicated, the users won’t have interest to use it.
 4) We are assuming our user are human.

### Threat Models:
**Environment 1: Picture-based Group Chat** 

 1) _Environment Description:_ This is a system is an downloadable application where users can create accounts and create or join picture-sharing groups. It will be available internationally. In this application, when a user joins a group they can only view others post, unless they are given posting permission, then they may also post pictures. Any user can download the images in the group chat. Only the user who posted a picture or the creator of the group can delete pictures. The creator can manage the other users of the groups permission to post pictures. 
 2) _Trust Assumptions:_ 
 * The application has been successfully and securely implemented and distributed across all platforms including mobile devices. 
 * The database servers that hold the information for the users, groups, pictures, etc. are properly managed and not able to be hacked.
 * User logging into their accounts will only try to access their own accounts and not others. However, security, encryptions, and other delaying processes will be implemented to delay attacks.
 * There is no way to view the database of users or groups. When groups are created, users can only be added by inputting another users username.
 * Users will not give their account to other users. 
 * Groups only have a limited amount of memory space. After a their space limit is met new messages will delete the oldest post to open space.
3) _List of properties:_
 * Each user will have own username and password to login.
 * The user can delete his/her own account but no one else can.
 * Everyone can create a group.
 * All members of a picture-sharing group can invite more members.
 * Every member can remove themselves from the group.
 * The creator of the group can remove any member of the group.
 * The creator of the group will need to give other members the permission to post new pictures to the group.
 * Everyone can download pictures from the group.
 * User given post permission can post pictures to the group.
 * Each group will have a limited memory amount. Once it is full, the oldest post in the group will be deleted to make space for a new one.
 * All post, deletes, removes, invites, etc. will be checked for permission first.
 * If a user fails to login in five consecutive attempts they will be banned from logging in for fifteen minutes.
 * All information is stored in the company's database encrypted using AES.
 * The application will be user-friendly and accessible on all devices.
 
**Environment 2: School file sharing:**

1) __Environment Description:__ In this system each instructor can create and assign folder project to any student within his class. The student can upload and download file content from shared folder. All users are on the same domain. The system contains two levels of user account, admin and user. User can’t invite other users to his/her file project. Only instructor or admin can add multiple users to the shared folder. Neither admin or user can delete any file or overwrite it in the shared folder. Both admin and user can download or upload any files. Users or students  can’t see any other shared folder except their own. The instructor can set a time to prevent students from upload more files to the folder after set up time expired. 

2) __Trust assumptions:__ We assume all users working in
 * The application has been successfully and securely implemented and can be accessed through different operating system such as windows or mac.
 * All files are stored in server side, nothing on the client side
 * The users can access the system through web application.
 * Users can only see his/her folder
 * Only admin can decide who which user can access the shared file 
 * Users can’t delete or overwrite any file with shared file
 * Users can only upload or download from shared file 
 * Users can’t add any user to his/her shared file
 * User can’t delete any folder from his shared folder
 * User logging into their accounts will only try to access their own accounts and not others. However, security, encryptions, and other delaying processes will be implemented to delay attacks.
 * Users will not give their account to other users. 
 * The application will be user-friendly and accessible on all devices.

3) __List of properties:__
 * Each user will have own username and password to login.
 * Only system admin can delete any user from the system
 * Only admin in the system can invite more members.
 * Users can remove themselves from the group.
 * The admin can remove any member of the group.
 * The admin will need to give other members the permission to upload files.
 * Admin and user can download files from the shared project..
 * Each project file will have a limited memory amount. Once it is full, it can be increased up to admin permission 
 * No available option to delete any file.
 * If a user fails to login in five consecutive attempts they will be banned from logging in for fifteen minutes.
 * All information is stored in the company's database encrypted using AES.
 * The application will be user-friendly and accessible on all devices
