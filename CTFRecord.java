public class CTFRecord
{
    private long validationNumber;
    private long idNumber;
    private int vote;
    private boolean voted;

    public CTFRecord(long validationNumber, long idNumber, int vote)
    {
        this.validationNumber = validationNumber;
        this.idNumber = idNumber;
        this.vote = vote;
        this.voted = true;
    }

    public boolean isVoted()
    {
        return voted;
    }

    public void setVoted(boolean voted)
    {
        this.voted = voted;
    }

    public long getValidationNumber()
    {
        return validationNumber;
    }

    public void setValidationNumber(long validationNumber)
    {
        this.validationNumber = validationNumber;
    }

    public long getIdNumber()
    {
        return idNumber;
    }

    public void setIdNumber(long idNumber)
    {
        this.idNumber = idNumber;
    }

    public int getVote()
    {
        return vote;
    }

    public void setVote(int vote)
    {
        this.vote = vote;
    }

    @Override
    public String toString ()
    {
        return "CTF Record:\nValidation Number: " + this.getValidationNumber() + "\nID Number: " + this.getIdNumber() + "\nVote: " + this.getVote();
    }
}
