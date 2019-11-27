import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class Server implements Runnable
{
    private ServerSocket serverSocket;
    protected Socket clientSocket;
    protected Socket otherStationSocket;
    protected BufferedReader recvFromOther;
    protected PrintWriter outputToOther;
    private String nonce;
    private String ID;

    public Server (int port, String ID)
    {
        this.ID = ID;
        try
        {
            this.serverSocket = new ServerSocket(port);
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public void acceptConnection ()
    {
        try
        {
            this.clientSocket = this.getServerSocket().accept();
        }
        catch (IOException e)
        {
            System.out.println (e.getMessage());
        }
    }

    public String getID()
    {
        return ID;
    }

    public void setID(String ID)
    {
        this.ID = ID;
    }

    public String getNonce()
    {
        return nonce;
    }

    public void setNonce(String nonce)
    {
        this.nonce = nonce;
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

    public Socket getOtherStationSocket()
    {
        return otherStationSocket;
    }

    public void setOtherStationSocket(Socket otherStationSocket)
    {
        this.otherStationSocket = otherStationSocket;
    }

    public ServerSocket getServerSocket()
    {
        return serverSocket;
    }

    public void setServerSocket(ServerSocket serverSocket)
    {
        this.serverSocket = serverSocket;
    }

    public Socket getClientSocket()
    {
        return clientSocket;
    }

    public void setClientSocket(Socket clientSocket)
    {
        this.clientSocket = clientSocket;
    }
}
