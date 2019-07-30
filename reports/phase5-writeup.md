## Mustafa Alazzawi, James Tomko, Tanner Stauffer
## mua31, jat190 , tas202
## CS1653
## 8/5/19
# Phase 5 Report
### Threat Model
* **Group Server:** The group server is entirely trustworthy. In this phase of the project, this means that the group server will only issue tokens to properly authenticated clients and will properly enforce the constraints on group creation, deletion, and management specified in previous phases of the project. The group server is not assumed to share secrets with the file servers in the system.
* **File Server:** The file server is entirely trustworthy. In this phase of the project, this means that the file server will only establish connections with Token's that have the file server's public key. Also, the file server will properly list, upload, download, and delete as long as the token has not expired. The file server does not communicate with the group server.
* **Clients:** We will assume that clients are not trustworthy. Specifically, clients will attempt to repeatedly connect to servers to cause Denial of Service attacks (DoS).
* **Other Principals:** You should assume servers can become overloaded with connection messages.

### Attacks Description

### Countermeasure Description
