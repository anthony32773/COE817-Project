import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

public class Client implements Runnable
{
    private Socket clientSocketCLA;
    private Socket clientSocketCTF;
    private PrintWriter outCLA;
    private BufferedReader inCLA;
    private PrintWriter outCTF;
    private BufferedReader inCTF;
    private Scanner inputScanner;
    private JEncrypRSA encryptRSA;
    private JEncrypDES encryptDESCLA;
    private JEncrypDES encryptDESCTF;
    private String nonce;
    private String ID;
    private static int IDCounter = 1;
    private String name;
    private long validationNumber;
    private int vote;
    private String output;

    public Client(String claIP, int claPort, String ctfIP, int ctfPort, String name, int vote)
    {
        try
        {
            this.clientSocketCLA = new Socket(claIP, claPort);
            this.clientSocketCTF = new Socket(ctfIP, ctfPort);
            this.outCLA = new PrintWriter(clientSocketCLA.getOutputStream(), true);
            this.inCLA = new BufferedReader(new InputStreamReader(clientSocketCLA.getInputStream()));
            this.outCTF = new PrintWriter(clientSocketCTF.getOutputStream(), true);
            this.inCTF = new BufferedReader(new InputStreamReader(clientSocketCTF.getInputStream()));
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.inputScanner = new Scanner(System.in);
        this.ID = "Client" + this.IDCounter;
        this.encryptRSA = new JEncrypRSA();
        this.encryptDESCLA = new JEncrypDES();
        this.encryptDESCTF = new JEncrypDES();
        this.IDCounter++;
        this.name = name;
        this.vote = vote;
        this.output = "---------" + this.ID + "---------\n";
    }

    public void run()
    {
        //CLA functions First
        this.exchangeRSAKeysCLA();
        this.nonceCheckStarterCLA();
        this.sendNonceChallengeCLA();
        this.sendDESKeyCLA();
        this.sendStep1();
        this.recvStep2();

        //CTF Functions
        this.exchangeRSAKeysCTF();
        this.nonceCheckStarterCTF();
        this.sendNonceChallengeCTF();
        this.sendDESKeyCTF();

        this.recvConfirmationFromCLA();

        this.sendStep2();

        System.out.println ("\n\n" + this.output);
    }

    public void recvConfirmationFromCLA()
    {
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getInCLA().readLine();
            //System.out.println ("Client Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptBuffer = this.getEncryptDESCLA().decrypt(inputBuffer);
        //System.out.println (decryptBuffer);
    }

    public void sendStep2()
    {
        this.output = this.output + "-------------\nSending Information to CTF:\n";
        long leftLimit = 1L;
        long rightLimit = 10000000000L;
        long gen = leftLimit + (long) (Math.random() * (rightLimit - leftLimit));

        //Send ID number
        String sendMessage = this.getEncryptDESCTF().encrypt(Long.toString(gen));
        this.output = this.output + "Sending ID Number:\n" + gen + "\nEncrypted:\n" + sendMessage + "\n";
        this.getOutCTF().println(sendMessage);
        //Send Validation number
        sendMessage = this.getEncryptDESCTF().encrypt(Long.toString(this.getValidationNumber()));
        this.output = this.output + "Sending Validation Number:\n" + this.getValidationNumber() + "\nEncrypted:\n" + sendMessage + "\n";
        this.getOutCTF().println(sendMessage);
        //Send vote
        sendMessage = this.getEncryptDESCTF().encrypt(Integer.toString(this.getVote()));
        this.output = this.output + "Sending Vote:\n" + this.getVote() + "\nEncrypted:\n" + sendMessage + "\n";
        this.getOutCTF().println(sendMessage);
    }

    public void sendStep1()
    {

        String sendMessage = this.getEncryptDESCLA().encrypt(this.getName());
        this.output = this.output + "----------------\nSending Starting Message to CLA:\n" + sendMessage;
        this.getOutCLA().println(sendMessage);
    }

    public void recvStep2()
    {
        this.output = this.output + "--------------\nRecv Validation Number from CLA\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getInCLA().readLine();
            this.output = this.output + this.ID + "Recvd:\n" + inputBuffer + "\n";
            //System.out.println ("Client Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        String decryptBuffer = this.getEncryptDESCLA().decrypt(inputBuffer);
        this.output = this.output + "Decrypted:\n" + decryptBuffer + "\n";
        this.setValidationNumber(Long.parseLong(decryptBuffer));
        try
        {
            this.getClientSocketCLA().close();
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.output = this.output + "Validation Number Recvd From CLA:\n" + this.getValidationNumber();
        //System.out.println ("Validation Number Recvd From CLA:");
        //System.out.println (this.getValidationNumber());
    }

    public void sendPublicKeyCLA()
    {

        String sendMessage = Base64.getEncoder().encodeToString(this.getEncryptRSA().getPublicKey().getEncoded());
        this.output = this.output + "Sending public key to CLA:\n" + sendMessage + "\n";
        this.getOutCLA().println(sendMessage);
    }

    public void sendPublicKeyCTF()
    {
        String sendMessage = Base64.getEncoder().encodeToString(this.getEncryptRSA().getPublicKey().getEncoded());
        this.output = this.output + "Sending public key to CTF:\n" + sendMessage + "\n";
        this.getOutCTF().println(sendMessage);
    }

    public void sendDESKeyCLA()
    {
        String sendMessage = this.getEncryptRSA().encrypt(Base64.getEncoder().encodeToString(this.getEncryptDESCLA().getDesKey().getEncoded()));
        this.output = this.output + "Sending DES key to CLA:\n" + sendMessage + "\n";
        this.getOutCLA().println(sendMessage);
    }

    public void sendDESKeyCTF()
    {
        String sendMessage = this.getEncryptRSA().encrypt(Base64.getEncoder().encodeToString(this.getEncryptDESCTF().getDesKey().getEncoded()));
        this.output = this.output + "Sending DES key to CTF:\n" + sendMessage + "\n";
        this.getOutCTF().println(sendMessage);
    }

    public void exchangeRSAKeysCLA()
    {
        this.output = this.output + "-----------\nExchange Keys with CLA:\n";
        String inputBuffer = "";
        this.sendPublicKeyCLA();
        try
        {
            inputBuffer = this.getInCLA().readLine();
            this.output = this.output + this.ID + " Recvd CLA Public Key:\n" + inputBuffer + "\n";
            //System.out.println ("Client Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.getEncryptRSA().recvPublicKey(inputBuffer);
    }

    public void exchangeRSAKeysCTF()
    {
        this.output = this.output + "-----------\nExchange Keys with CTF:\n";
        String inputBuffer = "";
        this.sendPublicKeyCTF();
        try
        {
            inputBuffer = this.getInCTF().readLine();
            this.output = this.output + this.ID + " Recvd CTF Public Key:\n" + inputBuffer + "\n";
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.getEncryptRSA().recvPublicKey(inputBuffer);
    }

    public void nonceCheckStarterCLA()
    {
        this.output = this.output + "------------------\nStart nonce check with CLA:\n";
        String inputBuffer = "", decryptBuffer = "", messageToSend = "", otherClientNonce = "";
        int locationOfOtherNonce;
        //Step 1 - Generate Nonce
        this.setNonce(Authentication.generateNonce());
        this.output = this.output + "Generated Nonce:\n" + this.getNonce();
        //System.out.println ("Generated Nonce:");
        //System.out.println (this.getNonce());

        //Step 2 - Use other client's public ket and send over our nonce + ID
        this.output = this.output + "\nSending to CLA:\n";
        //System.out.println ("Sending:");
        messageToSend = "Nonce:" + this.getNonce() + "Identity:" + this.getID();
        //System.out.println (messageToSend);
        this.output = this.output + messageToSend + "\n";
        messageToSend = this.getEncryptRSA().encrypt(messageToSend);
        //System.out.println ("Encrypted:");
        //System.out.println (messageToSend);
        this.output = this.output + "Encrypted Message to Send:\n" + messageToSend + "\n";
        this.getOutCLA().println(messageToSend);

        //Step 3 - Check that our nonce has been sent back to us and save the other client's nonce
        try
        {
            inputBuffer = this.getInCLA().readLine();
            this.output = this.output + this.ID + "Recvd:\n" + inputBuffer + "\n";
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
            this.output = this.output + "Our nonce has been found! The CLA is authentic\n";
            //System.out.println ("Our nonce has been found! The other client is authentic");
        }
        else
        {
            throw new SecurityException("Our nonce has not been found! An attacker is attempting a replay Attack! Quitting program...");
        }
        locationOfOtherNonce = decryptBuffer.lastIndexOf("Nonce:");
        locationOfOtherNonce = locationOfOtherNonce + 6;
        otherClientNonce = decryptBuffer.substring(locationOfOtherNonce);
        this.output = this.output + "CLA's Nonce:\n" + otherClientNonce + "\n";

        //System.out.println ("Other Client's Nonce:");
        //System.out.println (otherClientNonce);

        //Step 4 - Send back other client's nonce

        messageToSend = this.getEncryptRSA().encrypt(otherClientNonce);
        this.output = this.output + "Sending to CLA Encrypted Response:\n" + messageToSend + "\n";
        //System.out.println ("Sending:");
        //System.out.println (otherClientNonce);
        //System.out.println (messageToSend);
        this.getOutCLA().println(messageToSend);
    }

    public void nonceCheckStarterCTF()
    {
        this.output = this.output + "------------------\nStart nonce check with CTF:\n";
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
        this.output = this.output + "Encrypted Message to Send:\n" + messageToSend + "\n";
        //System.out.println ("Encrypted:");
        //System.out.println (messageToSend);
        this.getOutCTF().println(messageToSend);

        //Step 3 - Check that our nonce has been sent back to us and save the other client's nonce
        try
        {
            inputBuffer = this.getInCTF().readLine();
            this.output = this.output + this.ID + "Recvd:\n" + inputBuffer + "\n";
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
            this.output = this.output + "Our nonce has been found! The CTF is authentic\n";
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
        this.output = this.output + "Sending to CLA Encrypted Response:\n" + messageToSend + "\n";
        //System.out.println ("Sending:");
        //System.out.println (otherClientNonce);
        //System.out.println (messageToSend);
        this.getOutCTF().println(messageToSend);
    }

    public void sendNonceChallengeCLA()
    {
        String inputBuffer = "";
        String challenge = Authentication.generateChallengeNonce();
        BigInteger challengeInt = new BigInteger(challenge);
        challengeInt = challengeInt.add(BigInteger.ONE);
        String messageToSend = this.getEncryptRSA().encrypt("NONCECHALLENGE:" + challenge);
        this.output = this.output + "------------------\nSend Nonce Challenge to CLA\n";
        this.output = this.output + "Nonce Challenge Generated:\n" + challenge + "\nSending Encrypted:\n" + messageToSend + "\n";
        //System.out.println ("Sending Nonce Challenge from CLA");
        this.getOutCLA().println(messageToSend);
        try
        {
            inputBuffer = this.getInCLA().readLine();
            this.output = this.output + this.ID + "Recvd:\n" + inputBuffer + "\n";
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

    public void sendNonceChallengeCTF()
    {
        String inputBuffer = "";
        String challenge = Authentication.generateChallengeNonce();
        BigInteger challengeInt = new BigInteger(challenge);
        challengeInt = challengeInt.add(BigInteger.ONE);
        String messageToSend = this.getEncryptRSA().encrypt("NONCECHALLENGE:" + challenge);
        this.output = this.output + "------------------\nSend Nonce Challenge to CTF\n";
        this.output = this.output + "Nonce Challenge Generated:\n" + challenge + "\nSending Encrypted:\n" + messageToSend + "\n";
        //System.out.println ("Sending Nonce Challenge from CLA");
        //System.out.println ("Sending Nonce Challenge from CLA");
        this.getOutCTF().println(messageToSend);
        try
        {
            inputBuffer = this.getInCTF().readLine();
            this.output = this.output + this.ID + "Recvd:\n" + inputBuffer + "\n";
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

    public int getVote()
    {
        return vote;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public long getValidationNumber()
    {
        return validationNumber;
    }

    public void setValidationNumber(long validationNumber)
    {
        this.validationNumber = validationNumber;
    }

    public String getName()
    {
        return name;
    }

    public String getNonce()
    {
        return nonce;
    }

    public void setNonce(String nonce)
    {
        this.nonce = nonce;
    }

    public JEncrypRSA getEncryptRSA()
    {
        return encryptRSA;
    }

    public void setEncryptRSA(JEncrypRSA encryptRSA)
    {
        this.encryptRSA = encryptRSA;
    }

    public JEncrypDES getEncryptDESCLA()
    {
        return encryptDESCLA;
    }

    public void setEncryptDESCLA(JEncrypDES encryptDESCLA)
    {
        this.encryptDESCLA = encryptDESCLA;
    }

    public JEncrypDES getEncryptDESCTF()
    {
        return encryptDESCTF;
    }

    public void setEncryptDESCTF(JEncrypDES encryptDESCTF)
    {
        this.encryptDESCTF = encryptDESCTF;
    }

    public String getID()
    {
        return ID;
    }

    public void setID(String ID)
    {
        this.ID = ID;
    }

    public static int getIDCounter()
    {
        return IDCounter;
    }

    public static void setIDCounter(int IDCounter)
    {
        Client.IDCounter = IDCounter;
    }

    public Socket getClientSocketCLA()
    {
        return clientSocketCLA;
    }

    public void setClientSocketCLA(Socket clientSocketCLA)
    {
        this.clientSocketCLA = clientSocketCLA;
    }

    public Socket getClientSocketCTF()
    {
        return clientSocketCTF;
    }

    public void setClientSocketCTF(Socket clientSocketCTF)
    {
        this.clientSocketCTF = clientSocketCTF;
    }

    public PrintWriter getOutCLA()
    {
        return outCLA;
    }

    public void setOutCLA(PrintWriter outCLA)
    {
        this.outCLA = outCLA;
    }

    public BufferedReader getInCLA()
    {
        return inCLA;
    }

    public void setInCLA(BufferedReader inCLA)
    {
        this.inCLA = inCLA;
    }

    public PrintWriter getOutCTF()
    {
        return outCTF;
    }

    public void setOutCTF(PrintWriter outCTF)
    {
        this.outCTF = outCTF;
    }

    public BufferedReader getInCTF()
    {
        return inCTF;
    }

    public void setInCTF(BufferedReader inCTF)
    {
        this.inCTF = inCTF;
    }

    public Scanner getInputScanner()
    {
        return inputScanner;
    }

    public void setInputScanner(Scanner inputScanner)
    {
        this.inputScanner = inputScanner;
    }
}
