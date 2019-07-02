// Diffie-Hellman Key Agreement

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.awt.*;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class DH implements Serializable {
	/* Paramters for Diffie-Hellman group 16. See RFC 3526 */
	public static final BigInteger p = new BigInteger(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
		"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +
		"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +
		"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +
		"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +
		"FFFFFFFFFFFFFFFF", 16
	);
	public static final BigInteger g = new BigInteger("2");

    DH(){
        Security.addProvider(new BouncyCastleProvider());
    }

    // DH Domain Parameter Generation
    public static DHParameterSpec generateParameters()
            throws GeneralSecurityException
    {
/*
        AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", "BC");
        algGen.init(1024);
        AlgorithmParameters dsaParams = algGen.generateParameters();
        return dsaParams.getParameterSpec(DHParameterSpec.class);
*/
		return new DHParameterSpec(p, g);
    }

    //Having agreed on a set of parameters the next step is to generate a key pair using them. This is also
    //very similar to what is done for DSA.
    public static KeyPair generateKeyPair(DHParameterSpec dhParameterSpec)
            throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BC");
        keyPair.initialize(dhParameterSpec);
        return keyPair.generateKeyPair();
    }

    //Now that we have our key pair, and hopefully others have generated theirs, we can now try to generate
    //a shared secret key.
    public static byte[] initiatorAgreementBasic(PrivateKey initiatorPrivate, PublicKey recipientPublic)
            throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
        agreement.init(initiatorPrivate);
        agreement.doPhase(recipientPublic, true);
        SecretKey agreedKey = agreement.generateSecret("AES[128]");
        return agreedKey.getEncoded();
    }


    public static byte[] recipientAgreementBasic(PrivateKey recipientPrivate, PublicKey initiatorPublic)
            throws GeneralSecurityException
    {
        KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
        agreement.init(recipientPrivate);
        agreement.doPhase(initiatorPublic, true);
        SecretKey agreedKey = agreement.generateSecret("AES[128]");
        return agreedKey.getEncoded();
    }



    public static void main (String[]args) throws GeneralSecurityException {

        //setup : add the provider and generate DH parameters
        BouncyCastleProvider bouncyCastleProvider =  new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);

        DHParameterSpec dhParameterSpec = generateParameters(); // these parameters need to delivered to alice and bob it contains G P

        // Alice will generate keypair for her private and public
        KeyPair keyPairAlice = generateKeyPair(dhParameterSpec);
        // Bob will generate keypair for her private and public

        dhParameterSpec = ((DHPublicKey)keyPairAlice.getPublic()).getParams();

        KeyPair keyPairBob = generateKeyPair(dhParameterSpec);

        // Alice will init agreement with bob using his public key and get the agreed key
        byte [] agreedKeyA  = initiatorAgreementBasic(keyPairAlice.getPrivate(),keyPairBob.getPublic());

        // Bob is the recipient  and will get the agreed private key. He will use alice public key
        byte [] agreedKeyB = recipientAgreementBasic(keyPairBob.getPrivate(),keyPairAlice.getPublic());

        // now both alice and bob should have same paired key

        Toolkit.getDefaultToolkit().beep();

        System.out.println("Alic KAB = " + Arrays.toString(agreedKeyA));

        System.out.println("Bob  KAB = " + Arrays.toString(agreedKeyB));

    }
}
