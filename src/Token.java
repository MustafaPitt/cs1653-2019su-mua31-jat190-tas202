/* Token class
 * Class for storing tokens for users to authenticate themselves to the
 * file servers.
 */



import java.io.*;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.*;

public class Token implements UserToken, Serializable {
	private PublicKey fsPublicKey = null;
	private String       username;
	 private String       issuingServer;
	 private List<String>  groups;
	 private List<String>  ownership;
	 private byte[] 			signed_hash_token;
	 private LocalTime expiredTime;

	 // to be an admin, groups for a user must include "ADMIN" group
	 // ownership is a list of groups that user owns
	// groups is just a list of groups the user is part of
	 Token(String _server, String _username, ArrayList<String> _groups, ArrayList<String> _ownership , LocalTime expiredTime) {
		this.username      = _username;
		this.issuingServer = _server;
		this.groups        = _groups;
		this.ownership     = _ownership;
		this.signed_hash_token = null;
		this.expiredTime = expiredTime;
	}

	Token(String _server, String _username, ArrayList<String> _groups, ArrayList<String> _ownership , LocalTime expiredTime, PublicKey pk) {
		this.username      = _username;
		this.issuingServer = _server;
		this.groups        = _groups;
		this.ownership     = _ownership;
		this.signed_hash_token = null;
		this.expiredTime = expiredTime;
		this.fsPublicKey = pk;
	}



	public String getIssuer() {
		return issuingServer;
	}

	public String getSubject() { return username; }

	public List<String> getGroups() {
		return groups;
	}

	public List<String> getOwnership() {
		return ownership;
	}


	public PublicKey getFsPublicKey (){
	 	return  fsPublicKey;
	}

	public void updateHashToken(PrivateKey key){
		try{
			signed_hash_token = new RSA().generatePkcs1Signature(
				key, getHash());
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	public boolean verifyHash(PublicKey key) {
		try {
			// Decrypt given hash
			return new RSA().verifyPkcs1Signature(
				key, getHash(), signed_hash_token);
		} catch (Exception e) {
			e.printStackTrace();
			return false; // ???
		}
	}

	public byte[] getHash() {
		try {
			MessageDigest d = MessageDigest.getInstance("SHA-256");
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(out);

			os.writeObject(username);
			os.writeObject(issuingServer);
			os.writeObject(groups);
			os.writeObject(ownership);
			os.writeObject(expiredTime);
			os.writeObject(fsPublicKey);
			return d.digest(out.toByteArray());
		} catch (Exception e) {
			return null;
		}
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

	public LocalTime getExpiredTime() {
		return expiredTime;
	}
}
