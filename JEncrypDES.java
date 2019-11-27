import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class JEncrypDES extends Encryption
{
    private KeyGenerator keyGen;
    private SecretKey desKey;

    public JEncrypDES ()
    {
        super ("DES/ECB/PKCS5Padding");
        try
        {
            this.keyGen = KeyGenerator.getInstance("DES");
            this.desKey = keyGen.generateKey();
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println (e.getMessage());
        }
        System.out.println ("DES Key:");
        System.out.println (Base64.getEncoder().encodeToString(this.desKey.getEncoded()));
    }

    public JEncrypDES (String secretKey)
    {
        super ("DES/ECB/PKCS5Padding");
        byte[] decodedKey = Base64.getDecoder().decode(secretKey);
        this.desKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
    }

    public KeyGenerator getKeyGen()
    {
        return keyGen;
    }

    public SecretKey getDesKey()
    {
        return desKey;
    }

    public void setCipherDecrypt ()
    {
        try
        {
            this.getCipher().init(Cipher.DECRYPT_MODE, this.getDesKey());
        }
        catch (InvalidKeyException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void setCipherEncrypt ()
    {
        try
        {
            this.getCipher().init(Cipher.ENCRYPT_MODE, this.getDesKey());
        }
        catch (InvalidKeyException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public static void main (String args[])
    {
        JEncrypDES desObj = new JEncrypDES();
        System.out.println ("Enter the message: No body can see me");
        Scanner inScanner = new Scanner (System.in);
        String input = inScanner.nextLine();
        String encryptedMessage = desObj.encrypt(input);
        System.out.println ("Base 64 Encoded Encrypted Message:");
        System.out.println (encryptedMessage);
        String decrytpedMessage = desObj.decrypt(encryptedMessage);
        System.out.println ("Decrypted Message:");
        System.out.println (decrytpedMessage);
    }
}
