import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class HMAC {


    HMAC(){Security.addProvider(new BouncyCastleProvider());}

    static SecretKey generateKey()
            throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512", "BC");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static byte[] calculateHmac(SecretKey key, byte[] data)
            throws GeneralSecurityException
    {
        Mac hmac = Mac.getInstance("HMacSHA512", "BC");
        hmac.init(key);
        return hmac.doFinal(data);
    }

    public static byte[] calculateHmac(byte[] key, byte[] data)
            throws GeneralSecurityException
    {
        Mac hmac = Mac.getInstance("HMacSHA512", "BC");
        SecretKeySpec k = new SecretKeySpec(key, "HMacSHA512");
        hmac.init(k);
        return hmac.doFinal(data);
    }




}
