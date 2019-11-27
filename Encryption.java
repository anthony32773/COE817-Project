import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public abstract class Encryption
{
    private Cipher cipher;

    public Encryption(String alg)
    {
        try
        {
            this.cipher = Cipher.getInstance(alg);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public abstract void setCipherDecrypt();

    public abstract void setCipherEncrypt();

    public String encrypt (String message)
    {
        try
        {
            this.setCipherEncrypt();
            byte[] text = message.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = this.getCipher().doFinal(text);
            return Base64.getEncoder().encodeToString(encrypted);
        }
        catch (IllegalBlockSizeException e)
        {
            System.out.println (e.getMessage());
        }
        catch (BadPaddingException e)
        {
            System.out.println (e.getMessage());
        }
        return null;
    }

    public String decrypt (String message)
    {
        try
        {
            this.setCipherDecrypt();
            byte[] text = Base64.getDecoder().decode(message.getBytes(StandardCharsets.UTF_8));
            byte[] decrypted = this.getCipher().doFinal(text);
            return new String (decrypted);
        }
        catch (IllegalBlockSizeException e)
        {
            System.out.println (e.getMessage());
        }
        catch (BadPaddingException e)
        {
            System.out.println (e.getMessage());
        }
        return null;
    }

    public Cipher getCipher()
    {
        return cipher;
    }

    public void setCipher(Cipher cipher)
    {
        this.cipher = cipher;
    }
}
