//Generate Validation numbers
// Maintain a list of in use validation numbers and which validation numbers belong to who
// Send validation number list to CLA

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;

public class CLA extends Server
{
    private ArrayList<ValidationNumberPackage> vNumberList;
    private long leftLimit;
    private long rightLimit;
    private JEncrypRSA encryptRSA;
    private String ipCTF;
    private int portCTF;
    private JEncrypDES encryptDES;
    private String output;

    public CLA (int port, int portCTF, String ipCTF)
    {
        super (port, "CLA");
        this.portCTF = portCTF;
        this.ipCTF = ipCTF;
        this.leftLimit = 1L;
        this.rightLimit = 10000000000L;
        this.vNumberList = new ArrayList<ValidationNumberPackage>();
        this.encryptRSA = new JEncrypRSA();
        this.encryptDES = new JEncrypDES();
        this.output = "-------CLA---------\n";
    }

    public void connectToCTF()
    {
        try
        {
            this.otherStationSocket = new Socket(ipCTF, portCTF);
            this.recvFromOther = new BufferedReader(new InputStreamReader(this.otherStationSocket.getInputStream()));
            this.outputToOther = new PrintWriter(this.otherStationSocket.getOutputStream(), true);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void exchangeRSAKeysCTF()
    {
        this.output = this.output + "EXCHANGE RSA KEYS WITH CTF:\n";
        String inputBuffer = "";
        //Send Public key to CTF
        this.sendPublicKey();

        //Get public key from CTF
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CLA Recvd CTF Public Key:\n" + inputBuffer + "\n";
            //System.out.println ("CLA Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.getEncryptRSA().recvPublicKey(inputBuffer);
    }

    public void nonceRecvr()
    {
        String inputBuffer = "", decryptBuffer = "";
        //Step 1 - Generate Nonce
        this.setNonce(Authentication.generateNonce());
        System.out.println ("Generated Nonce:");
        System.out.println (this.getNonce());

        //Step 2 - Recv other client's nonce - Decrypt and seperate nonce and ID
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            System.out.println ("CLA Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptRSA().decrypt(inputBuffer);
        int idLocation = decryptBuffer.lastIndexOf("Identity:");
        String otherClientNonce = decryptBuffer.substring(6, idLocation);

        //Step 3 - Send back other clients nonce to them along with our own
        System.out.println ("Sending Back:");
        System.out.println ("Other Nonce: " + otherClientNonce + "\nOur Nonce: " + this.getNonce());
        String step3 = this.encryptRSA.encrypt("Nonce:" + otherClientNonce + "Nonce:" + this.getNonce());
        System.out.println ("Encrypted Message Sending Back:");
        System.out.println (step3);
        this.getOutputToOther().println(step3);

        //Step 4 - Recv confirmation from other client and verify that our nonce has been sent back to us
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            System.out.println ("CLA Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        decryptBuffer = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        if (decryptBuffer.equals(this.getNonce()))
        {
            System.out.println ("Our Nonce has been found! The other client is Authentic!");
        }
        else
        {
            throw new SecurityException("Our nonce has not been found! An attacker is attempting a replay attack! Quitting Program...");
        }
    }

    public void nonceCheckStarter()
    {
        this.output = this.output + "------------------\nCLA Start nonce check with CTF:\n";
        String inputBuffer = "", decryptBuffer = "", messageToSend = "", otherClientNonce = "";
        int locationOfOtherNonce;
        //Step 1 - Generate Nonce
        this.setNonce(Authentication.generateNonce());
        this.output = this.output + "Generated Nonce:\n" + this.getNonce();
        //System.out.println ("Generated Nonce:");
        //System.out.println (this.getNonce());

        //Step 2 - Use other client's public ket and send over our nonce + ID
        this.output = this.output + "\nSending to CTF:\n";
        //System.out.println ("Sending:");
        messageToSend = "Nonce:" + this.getNonce() + "Identity:" + this.getID();
        //System.out.println (messageToSend);
        this.output = this.output + messageToSend + "\n";
        messageToSend = this.getEncryptRSA().encrypt(messageToSend);


        //System.out.println ("Encrypted:");
        //System.out.println (messageToSend);
        this.output = this.output + "Encrypted Message to Send:\n" + messageToSend + "\n";

        this.getOutputToOther().println(messageToSend);

        //Step 3 - Check that our nonce has been sent back to us and save the other client's nonce
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CLA Recvd From CTF:\n" + inputBuffer +"\n";

            //System.out.println ("CLA Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }

        decryptBuffer = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + '\n';
        if (decryptBuffer.contains(this.getNonce()))
        {
            this.output = this.output + "Our nonce has been found! The other client is authentic\n";
            //System.out.println ("Our nonce has been found! The other client is authentic");
        }
        else
        {
            throw new SecurityException("Our nonce has not been found! An attacker is attempting a replay Attack! Quitting program...");
        }
        locationOfOtherNonce = decryptBuffer.lastIndexOf("Nonce:");
        locationOfOtherNonce = locationOfOtherNonce + 6;
        otherClientNonce = decryptBuffer.substring(locationOfOtherNonce);

        this.output = this.output + "CTF's Nonce:\n" + otherClientNonce + "\n";
        //System.out.println ("Other Client's Nonce:");
        //System.out.println (otherClientNonce);

        //Step 4 - Send back other client's nonce

        messageToSend = this.getEncryptRSA().encrypt(otherClientNonce);
        this.output = this.output + "Sending to CTF Encrypted Response:\n" + messageToSend + "\n";
        //System.out.println ("Sending:");
        //System.out.println (otherClientNonce);
        //System.out.println (messageToSend);
        this.getOutputToOther().println(messageToSend);
    }

    public void sendNonceChallenge()
    {
        String inputBuffer = "";
        String challenge = Authentication.generateChallengeNonce();
        BigInteger challengeInt = new BigInteger(challenge);
        challengeInt = challengeInt.add(BigInteger.ONE);
        String messageToSend = this.getEncryptRSA().encrypt("NONCECHALLENGE:" + challenge);
        this.output = this.output + "------------------\nSend Nonce Challenge to CTF\n";
        this.output = this.output + "Nonce Challenge Generated:\n" + challenge + "\nSending Encrypted:\n" + messageToSend + "\n";
        //System.out.println ("Sending Nonce Challenge from CLA");
        this.getOutputToOther().println(messageToSend);
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CLA Recvd from CTF:\n" + inputBuffer + "\n";
            //System.out.println ("CLA Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptMessage = this.getEncryptRSA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptMessage + "\n";
        BigInteger compare = new BigInteger(decryptMessage);
        if (challengeInt.compareTo(compare) == 0)
        {
            this.output = this.output + "Challenge Nonce Successfully Passed!" + "\n";
            //System.out.println ("Challenge Nonce Successfully Passed!");
        }
        else
        {
            throw new SecurityException("NONCE CHALLENGE FAILED, CONNECTION NOT SECURE...");
        }
    }

    public void respondNonceChallenge()
    {
        this.output = this.output + "--------------------\nResponding to CTF Nonce Challenge:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            //System.out.println ("CLA Recvd:\n" + inputBuffer);
            this.output = this.output + "CLA Recvd from CTF:\n" + inputBuffer + "\n";
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
            this.output = this.output + "Challenge Recvd, Sending back proper response to CTF:\n" + response + "\n";
            //System.out.println ("Response to challenge received generated, Sending back to client...");
            String sendMessage = this.getEncryptRSA().encrypt(response);
            this.output = this.output + "Encrypted Response:\n" + sendMessage + "\n";
            this.getOutputToOther().println(sendMessage);
        }
    }

    public void sendDESKeyCTF()
    {
        String sendMessage = this.getEncryptRSA().encrypt(Base64.getEncoder().encodeToString(this.getEncryptDES().getDesKey().getEncoded()));
        this.output = this.output + "----------------------\nSending DES Shared Key to CTF:\n" + sendMessage + "\n";
        this.getOutputToOther().println(sendMessage);
    }

    public void sendDESMessage(String message)
    {
        String sendMessage = this.getEncryptDES().encrypt(message);
        this.getOutputToOther().println(sendMessage);
    }

    public void recvDESMessage()
    {
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            System.out.println ("CLA Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptMessage = this.getEncryptDES().decrypt(inputBuffer);
        System.out.println (decryptMessage);
    }

    public void run ()
    {
        this.connectToCTF();
        //EXCHANGE RSA KEYS WITH CTF
        this.exchangeRSAKeysCTF();
        this.nonceCheckStarter();
        this.sendNonceChallenge();
        this.respondNonceChallenge();
        this.sendDESKeyCTF();

        ArrayList<CLAClientThread> claClientThreads = new ArrayList<>();

        for (int i = 0 ; i < 3 ; i++)
        {
            try
            {
                this.clientSocket = this.getServerSocket().accept();
            }
            catch (IOException e)
            {
                System.out.println (e.getMessage());
            }
            claClientThreads.add(new CLAClientThread(this.clientSocket, this));
            claClientThreads.get(i).start();
        }

        for (int i = 0 ; i < claClientThreads.size() ; i++)
        {
            try
            {
                claClientThreads.get(i).join();
            }
            catch (InterruptedException e)
            {
                System.out.println (e.getMessage());
            }
        }

        System.out.println ("\n\n" + this.output);
    }

    public void sendPublicKey()
    {
        String keyToSend = Base64.getEncoder().encodeToString(this.getEncryptRSA().getPublicKey().getEncoded());
        this.output = this.output + "Sending Public Key to CTF:\n" + keyToSend + "\n";
        //System.out.println ("CLA Sending Public Key To Client...");
        //System.out.println ("Public Key:");
        //System.out.println (keyToSend);
        this.getOutputToOther().println(keyToSend);
    }

    //PROTECT WITH MUTEX, ACCESSING VNUMBER LIST FROM MULTIPLE THREADS
    public long generateV (String id)
    {
        long gen = 0;
        boolean check = false;
        while (check == false)
        {
            check = true;
            gen = this.getLeftLimit() + (long) (Math.random() * (this.getRightLimit() - this.getLeftLimit()));
            for (int i = 0 ; i < this.getvNumberList().size() ; i++)
            {
                if (this.getvNumberList().get(i).getValidationNumber() == gen)
                {
                    check = false;
                    break;
                }
            }
        }
        this.getvNumberList().add(new ValidationNumberPackage(gen, id));
        return gen;
    }

    public JEncrypDES getEncryptDES()
    {
        return encryptDES;
    }

    public JEncrypRSA getEncryptRSA()
    {
        return encryptRSA;
    }

    public void setEncryptRSA(JEncrypRSA encryptRSA)
    {
        this.encryptRSA = encryptRSA;
    }

    public ArrayList<ValidationNumberPackage> getvNumberList()
    {
        return vNumberList;
    }

    public void setvNumberList(ArrayList<ValidationNumberPackage> vNumberList)
    {
        this.vNumberList = vNumberList;
    }

    public long getLeftLimit()
    {
        return leftLimit;
    }

    public void setLeftLimit(long leftLimit)
    {
        this.leftLimit = leftLimit;
    }

    public long getRightLimit()
    {
        return rightLimit;
    }

    public void setRightLimit(long rightLimit)
    {
        this.rightLimit = rightLimit;
    }

    public String toString ()
    {
        String output = "CLA:\nActive Validation Number Packages:";
        for (int i = 0 ; i < this.getvNumberList().size() ; i++)
        {
            output = output + "\n" + this.getvNumberList().get(i);
        }
        return output;
    }
}
