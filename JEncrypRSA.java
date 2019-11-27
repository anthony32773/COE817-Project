import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JEncrypRSA extends Encryption
{
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyPairGenerator keyGen;
    private KeyPair keyPair;
    private PublicKey otherPublicKey;

    public JEncrypRSA ()
    {
        super ("RSA");
        try
        {
            this.keyGen = KeyPairGenerator.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println (e.getMessage());
        }
        this.keyGen.initialize(1024);
        this.keyPair = this.keyGen.generateKeyPair();
        this.privateKey = this.keyPair.getPrivate();
        this.publicKey = this.keyPair.getPublic();
        System.out.println ("RSA Keys:");
        System.out.println ("Public Key:");
        System.out.println (Base64.getEncoder().encodeToString(this.publicKey.getEncoded()));
        System.out.println ("Private Key:");
        System.out.println (Base64.getEncoder().encodeToString(this.privateKey.getEncoded()));
    }

    public JEncrypRSA (String publicKey, String privateKey)
    {
        super ("RSA");
        this.keyGen = null;
        this.keyPair = null;
        try
        {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey.getBytes()));
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey.getBytes()));
            this.publicKey = kf.generatePublic(publicSpec);
            this.privateKey = kf.generatePrivate(privateSpec);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void setCipherDecrypt ()
    {
        try
        {
            this.getCipher().init(Cipher.DECRYPT_MODE, this.getPrivateKey());
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
            this.getCipher().init(Cipher.ENCRYPT_MODE, this.getOtherPublicKey());
        }
        catch (InvalidKeyException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void recvPublicKey (String recvdKey)
    {
        try
        {
            //System.out.println ("Public Key Received From Other Client:");
            //System.out.println (recvdKey);
            byte[] key = Base64.getDecoder().decode(recvdKey.getBytes(StandardCharsets.UTF_8));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            this.setOtherPublicKey(factory.generatePublic(spec));
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println (e.getMessage());
        }
        catch (InvalidKeySpecException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public void setPublicKey(PublicKey publicKey)
    {
        this.publicKey = publicKey;
    }

    public void setKeyGen(KeyPairGenerator keyGen)
    {
        this.keyGen = keyGen;
    }

    public void setKeyPair(KeyPair keyPair)
    {
        this.keyPair = keyPair;
    }

    public PublicKey getOtherPublicKey()
    {
        return otherPublicKey;
    }

    public void setOtherPublicKey(PublicKey otherPublicKey)
    {
        this.otherPublicKey = otherPublicKey;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public KeyPairGenerator getKeyGen()
    {
        return keyGen;
    }

    public KeyPair getKeyPair()
    {
        return keyPair;
    }
}