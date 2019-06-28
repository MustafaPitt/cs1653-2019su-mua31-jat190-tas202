// Diffie-Hellman Key Agreement

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.awt.*;
import java.security.*;
import java.util.Arrays;

public class DH {

    DH(){
        Security.addProvider(new BouncyCastleProvider());
    }

    // DH Domain Parameter Generation
    public static DHParameterSpec generateParameters()
            throws GeneralSecurityException
    {
        AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", "BC");
        algGen.init(1024);
        AlgorithmParameters dsaParams = algGen.generateParameters();
        return dsaParams.getParameterSpec(DHParameterSpec.class);
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
        KeyPair keyPairBob = generateKeyPair(dhParameterSpec);

        // Alice will init agreement with bob using his public key and get the agreed key
        byte [] agreedKeyA  = initiatorAgreementBasic(keyPairAlice.getPrivate(),keyPairBob.getPublic());
        // Bob is the recipient  and will get the agreed private key. He will use alice public key

        byte [] agreedKeyB = recipientAgreementBasic(keyPairBob.getPrivate(),keyPairAlice.getPublic());

        // now both alice and bob should have same paired key
        Toolkit.getDefaultToolkit().beep();
        System.out.println("Alic KAB = " + Arrays.toString(agreedKeyA));
        System.out.println("Bob KAB = " + Arrays.toString(agreedKeyB));


    }
}
