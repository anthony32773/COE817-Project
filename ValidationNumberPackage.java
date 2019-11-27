public class ValidationNumberPackage
{
    private long validationNumber;
    private String belongsTo;

    public ValidationNumberPackage(long validationNumber, String belongsTo)
    {
        this.validationNumber = validationNumber;
        this.belongsTo = belongsTo;
    }

    public long getValidationNumber()
    {
        return validationNumber;
    }

    public void setValidationNumber(long validationNumber)
    {
        this.validationNumber = validationNumber;
    }

    public String getBelongsTo()
    {
        return belongsTo;
    }

    public void setBelongsTo(String belongsTo)
    {
        this.belongsTo = belongsTo;
    }

    public String toString ()
    {
        return "Validation Number Package:\nBelongs To: " + this.getBelongsTo() + "\nValidation Number: " + this.getValidationNumber();
    }
}
