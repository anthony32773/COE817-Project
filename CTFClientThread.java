import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Base64;

public class CTFClientThread extends Thread
{
    private Socket clientSocket;
    private CTF ctf;
    private JEncrypRSA encryptRSA;
    private JEncrypDES encryptDES;
    private BufferedReader recvFromOther;
    private PrintWriter outputToOther;
    private String nonce;
    private String output;

    public CTFClientThread(Socket clientSocket, CTF ctf)
    {
        this.clientSocket = clientSocket;
        this.ctf = ctf;
        this.encryptRSA = new JEncrypRSA(Base64.getEncoder().encodeToString(this.ctf.getEncryptRSA().getPublicKey().getEncoded()), Base64.getEncoder().encodeToString(this.ctf.getEncryptRSA().getPrivateKey().getEncoded()));
        try
        {
            this.recvFromOther = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
            this.outputToOther = new PrintWriter(this.clientSocket.getOutputStream(), true);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.output = "--------------CTF Client Thread-------------\n";
    }

    public void run ()
    {
        this.exchangeRSAKeys();
        this.nonceRecvr();
        this.respondNonceChallenge();
        this.recvDESKey();
        this.recvStep4();

        System.out.println ("\n\n" + this.output);
    }

    public void recvStep4()
    {
        this.output = this.output + "--------------Recv Package of Info from Client:\n";
        String inputBuffer = "", decryptBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Client Thread Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptDES().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        long idNumber = Long.parseLong(decryptBuffer);
        this.output = this.output + "ID Number from Client:\n" + idNumber + "\n";
        //System.out.println ("ID number from client:");
        //System.out.println (idNumber);

        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptDES().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        long validationNumber = Long.parseLong(decryptBuffer);
        this.output = this.output + "Validation Number From Client:\n" + validationNumber + "\n";
        //System.out.println ("Validation Number from Client:");
        //System.out.println (validationNumber);

        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Client Thread Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptDES().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        int vote = Integer.parseInt(decryptBuffer);
        this.output = this.output + "Vote from Client:\n" + vote + "\n";
        //System.out.println ("Vote from client:");
        //System.out.println (vote);
        this.getCtf().processVote(idNumber, validationNumber, vote);
    }

    public void sendPublicKey()
    {

        String sendMessage = Base64.getEncoder().encodeToString(this.getEncryptRSA().getPublicKey().getEncoded());
        this.output = this.output + "Sending Public Key to Client:\n" + sendMessage + "\n";
        this.getOutputToOther().println(sendMessage);
    }

    public void exchangeRSAKeys()
    {
        this.output = this.output + "-------------\nExchange RSA Keys with Client:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Client Thread Recvd Client Public Key:\n" + inputBuffer + "\n";
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
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Client Thread Recvd:\n" + inputBuffer);
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
        //System.out.println ("Sending Back:");
        //System.out.println ("Other Nonce: " + otherClientNonce + "\nOur Nonce: " + this.getNonce());
        this.output = this.output + "Sending Back:\nOther Nonce: " + otherClientNonce + "\nOur Nonce: " + this.getNonce() + "\n";
        //System.out.println ("Sending Back:");
        String step3 = this.encryptRSA.encrypt("Nonce:" + otherClientNonce + "Nonce:" + this.getNonce());
        this.output = this.output + "Encrypted Message Sending Back:\n" + step3 + "\n";
        //System.out.println ("Encrypted Message Sending Back:");
        //System.out.println (step3);
        this.getOutputToOther().println(step3);

        //Step 4 - Recv confirmation from other client and verify that our nonce has been sent back to us
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Client Thread Recvd:\n" + inputBuffer);
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
        this.output = this.output + "--------------------\nResponding to Client Nonce Challenge:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Client Thread Recvd:\n" + inputBuffer);
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
            this.output = this.output + "CTF Client Thread Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Client Thread Recvd:\n" + inputBuffer);
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

    public CTF getCtf()
    {
        return ctf;
    }

    public void setCtf(CTF ctf)
    {
        this.ctf = ctf;
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
