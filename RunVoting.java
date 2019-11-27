public class RunVoting
{
    public static void main (String[] args)
    {
//        CLA testCla = new CLA(4444);
//        CTF testCtf = new CTF(4445);
//        testCla.generateV("Anthony");
//        testCla.generateV("Nicholas");
//        testCla.generateV("Taylor");
//        testCla.generateV("VAnessa");
//        testCla.generateV("Jessica");
//        System.out.println (testCla);
//        testCla.acceptConnection();
//        Client testClient = new Client("127.0.0.1", 4444, "127.0.0.1", 4445);
//        Thread clientThread = new Thread(testClient);
//        clientThread.start();

        CLA testCla = new CLA(4444, 4445, "127.0.0.1");
        CTF testCtf = new CTF(4445);

        Thread claThread = new Thread(testCla);
        Thread ctfThread = new Thread(testCtf);

        ctfThread.start();
        claThread.start();

        Client testClient = new Client("127.0.0.1", 4444, "127.0.0.1", 4445, "Anthony DiRito", 1);
        Client testClient2 = new Client("127.0.0.1", 4444, "127.0.0.1", 4445, "Nicholas DiRito", 2);
        Client testClient3 = new Client("127.0.0.1", 4444, "127.0.0.1", 4445, "Jessica DiRito", 1);

        Thread clientThread = new Thread(testClient);
        Thread clientThread2 = new Thread(testClient2);
        Thread clientThread3 = new Thread (testClient3);
        clientThread.start();
        clientThread2.start();
        clientThread3.start();



//        Client testClient = new Client("127.0.0.1", 4444, "127.0.0.1", 4445);
//        String encrypted = testClient.getRsaEncrypt().encrypt("Hello Faggot");
//        String decrypted = testClient.getRsaEncrypt().decrypt(encrypted);
//
//        System.out.println ("Encrypted:\n" + encrypted);
//        System.out.println ("Decrypted:\n" + decrypted);
//
//        String encrypted2 = testClient.getAesEncrypt().encrypt("Hello Faggot");
//        String decrypted2 = testClient.getAesEncrypt().decrypt(encrypted2);
//
//        System.out.println ("Encrypted:\n" + encrypted2);
//        System.out.println ("Decrypted:\n" + decrypted2);

    }
}
