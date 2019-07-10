## Mustafa Alazzawi, James Tomko, Tanner Stauffer
## mua31, jat190 , tas202
## CS1653
## 7/8/19
# Phase 3 Report

#brainstorm
T5 = Message reorder, replay, mod --- idea is to add a submsg to each envelope that has a sequence # and/or a time durration

T6 = File Leakage ----  Files when uploaded will be encrypted w/ with threshold security     //use shamir's ?
    They will be stored encrypted on the file server.
    When a member of the group wants to download the file, it will be sent back to the client and decrypted there with
      part of the threshold key.
    Now information that is leaked will not be readible. Only members of the group will be able to decipher these leaks.

T7 = Token Theft ---- Add a flag to each token that includes the port # of the FS it will immediatly be used on. This port number will be taken in when
    trying to connect and sent to the GS when the token is generated. Then this token will be usable only on the FS
    with the port number it has associated with it. If it is stolen it can still only be used on that FS port. 

### Introduction


### Message Reorder, Replay, and Modification (T5)

### File Leakage (T6)

### Token Theft (T7)



### Client <----> Group Server Overview

### Client <----> File Server Overview


### Conclusion
