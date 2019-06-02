/* Token class
 * Class for storing tokens for users to authenticate themselves to the
 * file servers.
 */


import java.util.ArrayList;
import java.util.List;

public class Token implements UserToken {
	 private String       username;
	 private String       issuingServer;
	 private List<String>  groups;

	 Token(String _username, String _server, ArrayList<java.lang.String> _groups) {
		this.username      = _username;
		this.issuingServer = _server;
		this.groups        = _groups;
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
