import java.math.BigInteger;
import java.util.Base64;
import java.util.Date;

public abstract class Authentication
{
    public static String generateNonce ()
    {
        String dateTime = Long.toString(new Date().getTime());
        byte [] byteNonce = dateTime.getBytes();
        String nonce = Base64.getEncoder().encodeToString(byteNonce);
        return nonce;
    }

    public static String generateChallengeNonce ()
    {
        String dateTime = Long.toString(new Date().getTime());
        return dateTime;
    }

    public static String respondChallenge (BigInteger challenge)
    {
        return challenge.add(BigInteger.ONE).toString();
    }
}
