import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class CTFValidationThread extends Thread
{
    private Socket recvSocket;
    private BufferedReader recvFromOther;
    private PrintWriter outputToOther;
    private CTF ctf;
    private String output;

    public CTFValidationThread(Socket recvSocket, CTF ctf)
    {
        this.recvSocket = recvSocket;
        this.ctf = ctf;
        this.output = "-------CTF Validation Thread!------\n";
        try
        {
            this.recvFromOther = new BufferedReader(new InputStreamReader(this.recvSocket.getInputStream()));
            this.outputToOther = new PrintWriter(this.recvSocket.getOutputStream(), true);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void run()
    {
        String inputBuffer = "", decryptBuffer = "";
        for (int i = 0 ; i < 3 ; i++)
        {
            try
            {
                inputBuffer = this.getRecvFromOther().readLine();
                this.output = this.output + "CTF Validatation Thread Recvd:\n" + inputBuffer + "\n";
                //System.out.println ("CTF Validation Thread Recvd:\n" + inputBuffer);
            }
            catch (IOException e)
            {
                System.out.println (e.getMessage());
            }
            decryptBuffer = this.getCtf().getEncryptDES().decrypt(inputBuffer);
            this.output = this.output + "Decrypted Message:\n" + decryptBuffer + "\n";
            this.getCtf().addVNumber(Long.parseLong(decryptBuffer));
            this.output = this.output + "VALIDATION NUMBER ADDED TO LIST:\n" + this.getCtf().getValidationNumbers().get(i) + "\n";
            //System.out.println ("VALIDATION NUMBER ADDED TO LIST:");
            //System.out.println (this.getCtf().getValidationNumbers().get(i));
            System.out.println ("\n\n" + this.output);
        }
    }

    public Socket getRecvSocket()
    {
        return recvSocket;
    }

    public BufferedReader getRecvFromOther()
    {
        return recvFromOther;
    }

    public PrintWriter getOutputToOther()
    {
        return outputToOther;
    }

    public CTF getCtf()
    {
        return ctf;
    }
}
