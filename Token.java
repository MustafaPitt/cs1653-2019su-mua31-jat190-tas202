/* Token class
 * Class for storing tokens for users to authenticate themselves to the
 * file servers.
 */



import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Token implements UserToken, Serializable {
	 private String       username;
	 private String       issuingServer;
	 private List<String>  groups;
	 private List<String>  ownership;

	 // to be an admin, groups for a user must include "ADMIN" group
	 // ownership is a list of groups that user owns
	// groups is just a list of groups the user is part of
	 Token(String _server, String _username, ArrayList<java.lang.String> _groups, ArrayList<String> _ownership) {
		this.username      = _username;
		this.issuingServer = _server;
		this.groups        = _groups;
		this.ownership     = _ownership;
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

	public List<String> getOwnership() {
		return ownership;
	}



	public void  printGroup(){
	 	for(String s : groups){
			System.out.println(s);
		}
	}

	public void  printOwner(){
		for(String s : ownership){
			System.out.println(s);
		}
	}
}
