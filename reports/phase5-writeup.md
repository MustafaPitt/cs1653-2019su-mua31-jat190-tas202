## Mustafa Alazzawi, James Tomko, Tanner Stauffer
## mua31, jat190 , tas202
## CS1653
## 8/5/19
# Phase 5 Report
### Trust Model / Threats
* **Group Server:** The group server is entirely trustworthy. In this phase of the project, this means that the group server will only issue tokens to properly authenticated clients and will properly enforce the constraints on group creation, deletion, and management specified in previous phases of the project. The group server is not assumed to share secrets with the file servers in the system.
* **File Server:** The file server is entirely trustworthy. In this phase of the project, this means that the file server will only establish connections with Token's that have the file server's public key. Also, the file server will properly list, upload, download, and delete as long as the token has not expired. The file server does not communicate with the group server.
* **Clients:** We will assume that clients are not trustworthy. Specifically, clients will attempt to repeatedly connect to servers to cause Denial of Service attacks (DoS).
* **Other Principals:** You should assume servers can become overloaded with connection attempts.

### Attacks Description
* Every attempt to connect to the group server or a file server takes several steps and much overhead. For the group server a Diffie Hellman key must be created, messages must be encrypted, and a sequence number has to be established. For a file server the same steps are taken accept additionally the server must complete a challenge response. If an attacker were to spam connection attempts from his/her machine, then it is likely that the server could become overloaded, which would be an attack against availability. If this was a constant attack, other users would not be able to access the server when they need to.
* The DoS program we built to attack our program looks like:

### Countermeasure Description
* To address DoS (as well as DDoS) attacks, our plan is to implement a proof-of-work system, specifically a computational puzzle. Now, when a user attempt to connect to either server he/she will first be required to complete a puzzle that is hard and requires time to solve. This puzzle will be one that is quick to generate on the server side, and doesn't need much data saved. This puzzle is an effective countermeasure, because it will drastically slow the rate at which an attacker can send connection attempts, and therefore, will strongly mitigate DoS attacks.
* Our computational puzzle implementation looks like:
