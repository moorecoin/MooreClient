package org.ripple.bouncycastle.asn1.eac;

import java.io.unsupportedencodingexception;

public class certificateholderreference
{
    private static final string referenceencoding = "iso-8859-1";

    private string countrycode;
    private string holdermnemonic;
    private string sequencenumber;

    public certificateholderreference(string countrycode, string holdermnemonic, string sequencenumber)
    {
        this.countrycode = countrycode;
        this.holdermnemonic = holdermnemonic;
        this.sequencenumber = sequencenumber;
    }

    certificateholderreference(byte[] contents)
    {
        try
        {
            string concat = new string(contents, referenceencoding);

            this.countrycode = concat.substring(0, 2);
            this.holdermnemonic = concat.substring(2, concat.length() - 5);

            this.sequencenumber = concat.substring(concat.length() - 5);
        }
        catch (unsupportedencodingexception e)
        {
            throw new illegalstateexception(e.tostring());
        }
    }

    public string getcountrycode()
    {
        return countrycode;
    }

    public string getholdermnemonic()
    {
        return holdermnemonic;
    }

    public string getsequencenumber()
    {
        return sequencenumber;
    }


    public byte[] getencoded()
    {
        string ref = countrycode + holdermnemonic + sequencenumber;

        try
        {
            return ref.getbytes(referenceencoding);
        }
        catch (unsupportedencodingexception e)
        {
            throw new illegalstateexception(e.tostring());
        }
    }
}
