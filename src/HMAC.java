import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Security;

class HMAC {


    HMAC(){Security.addProvider(new BouncyCastleProvider());}

    static SecretKey generateKey()
            throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512", "BC");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    static byte[] calculateHmac(SecretKey key, byte[] data)
            throws GeneralSecurityException
    {
        Mac hmac = Mac.getInstance("HMacSHA512", "BC");
        hmac.init(key);
        return hmac.doFinal(data);
    }



}
