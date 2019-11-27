import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Base64;

public class CLAClientThread extends Thread
{
    private Socket clientSocket;
    private CLA cla;
    private JEncrypRSA encryptRSA;
    private JEncrypDES encryptDES;
    private BufferedReader recvFromOther;
    private PrintWriter outputToOther;
    private String nonce;
    private String output;


    public CLAClientThread (Socket clientSocket, CLA cla)
    {
        this.clientSocket = clientSocket;
        this.cla = cla;
        this.encryptRSA = new JEncrypRSA(Base64.getEncoder().encodeToString(this.cla.getEncryptRSA().getPublicKey().getEncoded()), Base64.getEncoder().encodeToString(this.cla.getEncryptRSA().getPrivateKey().getEncoded()));
        try
        {
            this.recvFromOther = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
            this.outputToOther = new PrintWriter(this.clientSocket.getOutputStream(), true);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.output = "--------CLA Client Thread---------\n";
    }

    public void run ()
    {
        this.exchangeRSAKeys();
        this.nonceRecvr();
        this.respondNonceChallenge();
        this.recvDESKey();
        //System.out.println ("Client Success CLA!");
        this.recvStep1();
        System.out.println ("\n\n" + this.output);
    }

    public void recvStep1()
    {
        this.output = this.output + "-----------------\nRecv Starting message From Client:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            //System.out.println ("CLA Client Thread Recvd:\n" + inputBuffer);
            this.output = this.output + "CLA Client Thread Recvd:\n" + inputBuffer + "\n";
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptMessage = this.getEncryptDES().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptMessage + "\n";
        long sendV = this.getCla().generateV(decryptMessage);
        String sendMessage = this.getEncryptDES().encrypt(Long.toString(sendV));
        this.getOutputToOther().println (sendMessage);
        //System.out.println (this.getCla().getvNumberList().get(0).toString());
        this.output = this.output + "Sending Validation Number to CTF:\n" + sendV + "\n";
        this.getCla().getOutputToOther().println (this.getCla().getEncryptDES().encrypt(Long.toString(sendV)));
        this.getOutputToOther().println (this.getEncryptDES().encrypt("Information Sent to CTF"));
    }

    public void sendPublicKey()
    {
        this.output = this.output + "-------------------\nSending Public Key to Client:\n";
        String sendMessage = Base64.getEncoder().encodeToString(this.getEncryptRSA().getPublicKey().getEncoded());
        this.output = this.output + "Sending:\n" + sendMessage + "\n";
        this.getOutputToOther().println(sendMessage);
    }

    public void exchangeRSAKeys()
    {
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            //System.out.println ("CLA Client Thread Recvd:\n" + inputBuffer);
            this.output = this.output + "CLA Client Thread Recvd Client's Public Key:\n" + inputBuffer + "\n";
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.getEncryptRSA().recvPublicKey(inputBuffer);
        this.sendPublicKey();
    }

    public void nonceRecvr()
    {
        this.output = this.output + "-------------------\nReceiving Nonce Verification from Client:\n";
        String inputBuffer = "", decryptBuffer = "";
        //Step 1 - Generate Nonce
        this.setNonce(Authentication.generateNonce());
        this.output = this.output + "Generated Nonce:\n" + this.getNonce() + "\n";
        //System.out.println ("Generated Nonce:");
        //System.out.println (this.getNonce());

        //Step 2 - Recv other client's nonce - Decrypt and seperate nonce and ID
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CLA Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CLA Client Thread Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        int idLocation = decryptBuffer.lastIndexOf("Identity:");
        String otherClientNonce = decryptBuffer.substring(6, idLocation);

        //Step 3 - Send back other clients nonce to them along with our own
        this.output = this.output + "Sending Back:\nOther Nonce: " + otherClientNonce + "\nOur Nonce: " + this.getNonce() + "\n";
        //System.out.println ("Sending Back:");
        //System.out.println ("Other Nonce: " + otherClientNonce + "\nOur Nonce: " + this.getNonce());
        String step3 = this.encryptRSA.encrypt("Nonce:" + otherClientNonce + "Nonce:" + this.getNonce());
        this.output = this.output + "Encrypted Message Sending Back:\n" + step3 + "\n";
        //System.out.println ("Encrypted Message Sending Back:");
        //System.out.println (step3);
        this.getOutputToOther().println(step3);

        //Step 4 - Recv confirmation from other client and verify that our nonce has been sent back to us
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CLA Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CLA Client Thread Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        if (decryptBuffer.equals(this.getNonce()))
        {
            this.output = this.output + "Our Nonce has been found! The other client is Authentic!\n";
            //System.out.println ("Our Nonce has been found! The other client is Authentic!");
        }
        else
        {
            throw new SecurityException("Our nonce has not been found! An attacker is attempting a replay attack! Quitting Program...");
        }
    }

    public void respondNonceChallenge()
    {
        this.output = this.output + "--------------------\nResponding to CTf Nonce Challenge:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CLA Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CLA Client Thread Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptMessage = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptMessage + "\n";
        if (decryptMessage.contains("NONCECHALLENGE:"))
        {
            decryptMessage = decryptMessage.substring(15);
            BigInteger challengeBig = new BigInteger(decryptMessage);
            String response = Authentication.respondChallenge(challengeBig);
            this.output = this.output + "Challenge Recvd, Sending back proper response to Client:\n" + response + "\n";
            //System.out.println ("Response to challenge received generated, Sending back to client...");
            String sendMessage = this.getEncryptRSA().encrypt(response);
            this.getOutputToOther().println(sendMessage);
        }
    }

    public void recvDESKey ()
    {
        this.output = this.output + "---------------\nRecv DES Key From Client:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            //System.out.println ("CLA Client Thread Recvd:\n" + inputBuffer);
            this.output = this.output + "CLA Client Thread Recvd:\n" + inputBuffer + "\n";
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptMessage = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptMessage + "\n";
        this.encryptDES = new JEncrypDES(decryptMessage);
        //System.out.println (Base64.getEncoder().encodeToString(this.getEncryptDES().getDesKey().getEncoded()));
    }

    public Socket getClientSocket()
    {
        return clientSocket;
    }

    public void setClientSocket(Socket clientSocket)
    {
        this.clientSocket = clientSocket;
    }

    public CLA getCla()
    {
        return cla;
    }

    public void setCla(CLA cla)
    {
        this.cla = cla;
    }

    public JEncrypRSA getEncryptRSA()
    {
        return encryptRSA;
    }

    public void setEncryptRSA(JEncrypRSA encryptRSA)
    {
        this.encryptRSA = encryptRSA;
    }

    public JEncrypDES getEncryptDES()
    {
        return encryptDES;
    }

    public void setEncryptDES(JEncrypDES encryptDES)
    {
        this.encryptDES = encryptDES;
    }

    public BufferedReader getRecvFromOther()
    {
        return recvFromOther;
    }

    public void setRecvFromOther(BufferedReader recvFromOther)
    {
        this.recvFromOther = recvFromOther;
    }

    public PrintWriter getOutputToOther()
    {
        return outputToOther;
    }

    public void setOutputToOther(PrintWriter outputToOther)
    {
        this.outputToOther = outputToOther;
    }

    public String getNonce()
    {
        return nonce;
    }

    public void setNonce(String nonce)
    {
        this.nonce = nonce;
    }
}
