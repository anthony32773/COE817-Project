//CTF and CLA Server Client Relationship:
//CTF will act as server for CLA and CTF relationship
//CLA is the client

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.concurrent.Semaphore;

public class CTF extends Server
{
    private JEncrypRSA encryptRSA;
    private JEncrypDES encryptDES;
    private ArrayList<CTFRecord> ctfRecords;
    private ArrayList<Long> validationNumbers;
    private static Semaphore vSemaphore = new Semaphore(1);
    private static Semaphore ctfSemaphore = new Semaphore(1);
    private String output;

    public CTF (int port)
    {
        super (port, "CTF");
        this.encryptRSA = new JEncrypRSA();
        this.ctfRecords = new ArrayList<CTFRecord>();
        this.validationNumbers = new ArrayList<Long>();
        this.output = "-------CTF--------\n";
    }

    public void acceptCLA()
    {
        try
        {
            this.otherStationSocket = this.getServerSocket().accept();
            this.recvFromOther = new BufferedReader(new InputStreamReader(this.otherStationSocket.getInputStream()));
            this.outputToOther = new PrintWriter(this.otherStationSocket.getOutputStream(), true);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void sendPublicKey()
    {
        String keyToSend = Base64.getEncoder().encodeToString(this.getEncryptRSA().getPublicKey().getEncoded());
        this.output = this.output + "CTF Sending Public Key to CLA:\n" + keyToSend + "\n";
        //System.out.println ("CTF Sending Public Key To Client...");
        //System.out.println ("Public Key:");
        //System.out.println (keyToSend);
        this.getOutputToOther().println(keyToSend);
    }

    public void exchangeRSAKeysCLA()
    {
        this.output = this.output + "--------------------\nExchange RSA Keys with CLA:\n";
        String inputBuffer = "";
        //Recv RSA Key from other
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Recvd Public Key from CLA:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Recvd:\n" + inputBuffer);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
        this.getEncryptRSA().recvPublicKey(inputBuffer);
        //Send Public Key
        this.sendPublicKey();
    }

    public void nonceRecvr()
    {
        this.output = this.output + "---------------------\nRecv and Respond to Nonce Auth from CLA\n";
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
            this.output = this.output + "CLA Recvd from CTF:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Recvd:\n" + inputBuffer);
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
        String step3 = this.encryptRSA.encrypt("Nonce:" + otherClientNonce + "Nonce:" + this.getNonce());
        this.output = this.output + "Encrypted Message Sending Back:\n" + step3 + "\n";
        //System.out.println ("Encrypted Message Sending Back:");
        //System.out.println (step3);
        this.getOutputToOther().println(step3);

        //Step 4 - Recv confirmation from other client and verify that our nonce has been sent back to us
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Recvd from CLA:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Recvd:\n" + inputBuffer);
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

    public void sendNonceChallenge()
    {
        this.output = this.output + "--------------------\nSending a Nonce Challenge\n";
        String inputBuffer = "";
        String challenge = Authentication.generateChallengeNonce();
        BigInteger challengeInt = new BigInteger(challenge);
        challengeInt = challengeInt.add(BigInteger.ONE);
        String messageToSend = this.getEncryptRSA().encrypt("NONCECHALLENGE:" + challenge);
        //System.out.println ("Sending Nonce Challenge from CTF");
        this.output = this.output + "Nonce Challenge Generated:\n" + challenge + "\nSending Encrypted:\n" + messageToSend + "\n";
        this.getOutputToOther().println(messageToSend);
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Recvd from CLA:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Recvd:\n" + inputBuffer);
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
        this.output = this.output + "---------------------\nResponding to CLA Nonce Challenge:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Recvd from CLA:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Recvd:\n" + inputBuffer);
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
            this.output = this.output + "Challenge Recvd, Sending back proper response to CLA:\n" + response + "\n";
            //System.out.println ("Response to challenge received generated, Sending back to client...");
            String sendMessage = this.getEncryptRSA().encrypt(response);
            this.output = this.output + "Encrypted Response:\n" + sendMessage + "\n";
            this.getOutputToOther().println(sendMessage);
        }
    }

    public void recvDESKeyCLA ()
    {
        this.output = this.output + "---------------------\nRecv DES Key from CLA:\n";
        String inputBuffer = "";
        try
        {
            inputBuffer = this.getRecvFromOther().readLine();
            this.output = this.output + "CTF Recvd from CLA:\n" + inputBuffer + "\n";
            //System.out.println ("CTF Recvd:\n" + inputBuffer);
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
            System.out.println ("CTF Recvd:\n" + inputBuffer);
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
        this.acceptCLA();
        //EXCHANGE RSA WITH CLA
        this.exchangeRSAKeysCLA();
        this.nonceRecvr();
        this.respondNonceChallenge();
        this.sendNonceChallenge();
        this.recvDESKeyCLA();

        new CTFValidationThread(this.getOtherStationSocket(), this).start();
        ArrayList<CTFClientThread> clientThreadArrayList = new ArrayList<>();
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
            clientThreadArrayList.add(new CTFClientThread(this.clientSocket, this));
            clientThreadArrayList.get(i).start();
        }

        try
        {
            for (int i = 0 ; i < clientThreadArrayList.size() ; i++)
            {
                clientThreadArrayList.get(i).join();
            }
        }
        catch (InterruptedException e)
        {
            System.out.println (e.getMessage());
        }

        this.getResults();

        System.out.println ("\n\n" + this.output);
    }

    public void getResults()
    {
        int can1 = 0, can2 = 0;
        for (int i = 0 ; i < this.getCtfRecords().size() ; i++)
        {
            if (this.getCtfRecords().get(i).getVote() == 1)
            {
                can1++;
            }
            else
            {
                can2++;
            }
        }

        this.output = this.output + "------------------------\nRESULTS:\nCandidate 1:\nNumber of Votes: " + can1 + "\nVoters:\n";
        //System.out.println ("------------------------");
        //System.out.println ("RESULTS:");
        //System.out.println ("Candidate 1:");
        //System.out.println ("Number of Votes: " + can1);
        //System.out.println ("Voters:");
        for (int i = 0 ; i < this.getCtfRecords().size() ; i++)
        {
            if (this.getCtfRecords().get(i).getVote() == 1)
            {
                this.output = this.output + this.getCtfRecords().get(i).getIdNumber() + "\n";
                //System.out.println (this.getCtfRecords().get(i).getIdNumber());
            }
        }

        this.output = this.output + "Candidate 2:\nNumber of Votes: " + can2 + "Voters:\n";
        //System.out.println ("Candidate 2:");
        //System.out.println ("Number of Votes: " + can2);
        //System.out.println ("Voters:");
        for (int i = 0 ; i < this.getCtfRecords().size() ; i++)
        {
            if (this.getCtfRecords().get(i).getVote() == 2)
            {
                this.output = this.output + this.getCtfRecords().get(i).getIdNumber() + "\n";
                //System.out.println (this.getCtfRecords().get(i).getIdNumber());
            }
        }

        if (can1 > can2)
        {
            this.output = this.output + "\nCANDIDATE 1 WON!";
            //System.out.println ("\nCANDIDATE 1 WON!");
        }
        else if (can2 > can1)
        {
            this.output = this.output + "\nCANDIDATE 2 WON!";
            //System.out.println ("\nCANDIDATE 2 WON!");
        }
        else
        {
            this.output = this.output + "\nELECTION WAS A TIE";
            //System.out.println ("\nELECTION WAS A TIE!");
        }
    }

    public void addVNumber(long vNumber)
    {
        try
        {
            vSemaphore.acquire();
            this.getValidationNumbers().add(vNumber);
            vSemaphore.release();
        }
        catch (InterruptedException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void processVote(long IDNum, long vNum, int vote)
    {
        try
        {
            ctfSemaphore.acquire();
            boolean check = false;
            if (this.getValidationNumbers().contains(vNum))
            {
                for (int i = 0 ; i < this.getCtfRecords().size() ; i++)
                {
                    if (this.getCtfRecords().get(i).getValidationNumber() == vNum)
                    {
                        check = true;
                        break;
                    }
                }

                if (check == false)
                {
                    this.getCtfRecords().add(new CTFRecord(vNum, IDNum, vote));
                }
                else
                {
                    this.output = this.output + "User has Already Voted!\n";
                    //System.out.println ("User has already voted!");
                }
            }
            else
            {
                this.output = this.output + "Invalid Validation Number!\n";
                //System.out.println ("Invalid Validation Number!");
            }

        }
        catch (InterruptedException e)
        {
            System.out.println (e.getMessage());
        }
        ctfSemaphore.release();
    }

    public ArrayList<Long> getValidationNumbers()
    {
        return validationNumbers;
    }

    public ArrayList<CTFRecord> getCtfRecords()
    {
        return ctfRecords;
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
}
