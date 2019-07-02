import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;


public class RSA implements Serializable{

    RSA(){
        Security.addProvider(new BouncyCastleProvider());
    }

    static KeyPair generateKeyPair()
            throws GeneralSecurityException
    {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");
        keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return keyPair.generateKeyPair();
    }
//    public  void printByte(byte[] input){
//        for(byte b : input) {
//            System.out.print(b);
//        }
//    }

    byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BC");
        signature.initSign(rsaPrivate);
        signature.update(input);
        return signature.sign();
    }

    boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BC");
        signature.initVerify(rsaPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    byte[] cfbEncrypt(PublicKey key, byte[] data)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data) ;
    }
    byte[] cfbDecrypt(PrivateKey key, byte[] cipherText)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    String bytesToString(byte[] input){
        StringBuilder sb = new StringBuilder();
        for(byte b : input) sb.append((char) (b));
        return sb.toString();
    }


    public  byte[] serialize(Serializable obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }
    public  Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }



    public static void main (String [] args){

//        RSA rsa = new RSA();
//        KeyPair kp = generateKeyPair();
//        String plainText = "Buy 10 google share";
//
//        byte[] encSignature = rsa.generatePkcs1Signature(kp.getPrivate(), plainText.getBytes());
//        System.out.println("Signature " ) ;
//        printByte(encSignature);
//        System.out.println();
//
//
//        if (verifyPkcs1Signature(kp.getPublic(), plainText.getBytes(),encSignature)){
//            System.out.println("Its valid");
//        }
//        else {
//            System.out.println(" signature is no valid");
//        }
//
//        byte [] cipherText = cfbEncrypt(kp.getPublic(),plainText.getBytes());
//
//        printByte(cipherText);
//        System.out.println();
//
//        System.out.println("cipher: " + bytesToString(cipherText));
//
//        byte [] decPlainText =  cfbDecrypt(kp.getPrivate(),cipherText);
//        System.out.println("Message after decrypt: " + bytesToString(decPlainText));

    }



}
