/* Token class
 * Class for storing tokens for users to authenticate themselves to the
 * file servers.
 */

public class Token implements UserToken {
	String       username;
	String       issuingServer;
	List<String> groups;
	
	public Token(String _username, String _server, List<String> _groups) {
		username      = _username;
		issuingServer = _server;
		groups        = _groups;
	}

	public String getIssuer() {
		return issuingServer;
	}

	public String getSubject() {
		return username;
	}

	public List<String> getGroups() {
		return groups;
	}
}
