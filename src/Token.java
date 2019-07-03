/* Token class
 * Class for storing tokens for users to authenticate themselves to the
 * file servers.
 */



import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.*;

public class Token implements UserToken, Serializable {
	 private String       username;
	 private String       issuingServer;
	 private List<String>  groups;
	 private List<String>  ownership;
	 private byte[] 			signed_hash_token;

	 // to be an admin, groups for a user must include "ADMIN" group
	 // ownership is a list of groups that user owns
	// groups is just a list of groups the user is part of
	 Token(String _server, String _username, ArrayList<String> _groups, ArrayList<String> _ownership) {
		this.username      = _username;
		this.issuingServer = _server;
		this.groups        = _groups;
		this.ownership     = _ownership;
		signed_hash_token = null;
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

	public void updateHashToken(PrivateKey key){
			//hash the token
			try{
				MessageDigest d = MessageDigest.getInstance("SHA-256");

				ByteArrayOutputStream out = new ByteArrayOutputStream();
				ObjectOutputStream os = new ObjectOutputStream(out);
				os.writeObject(username);
				os.writeObject(issuingServer);
				os.writeObject(groups);
				os.writeObject(ownership);
				byte[] hashed_token = d.digest(out.toByteArray());
				//sign the token with given key
				RSA rsa = new RSA();
				signed_hash_token = rsa.generatePkcs1Signature(key, hashed_token);
				
			}catch(Exception e){
				e.printStackTrace();
				return;
			}


	}

	public boolean verifyHash(PublicKey key) {
		try {
			// Calculate hash
			MessageDigest d = MessageDigest.getInstance("SHA-256");
			ObjectOutputStream os = new ObjectOutputStream(
				new ByteArrayOutputStream());

			os.writeObject(username);
			os.writeObject(issuingServer);
			os.writeObject(groups);
			os.writeObject(ownership);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] hashed_token = d.digest(out.toByteArray());

			// Decrypt given hash
			RSA rsa = new RSA();
			return rsa.verifyPkcs1Signature(key, hashed_token, signed_hash_token);
		} catch (Exception e) {
			e.printStackTrace();
			return false; // ???
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
}
