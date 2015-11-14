package org.ripple.bouncycastle.asn1.eac;

public class certificationauthorityreference
    extends certificateholderreference
{
    public certificationauthorityreference(string countrycode, string holdermnemonic, string sequencenumber)
    {
        super(countrycode, holdermnemonic, sequencenumber);
    }

    certificationauthorityreference(byte[] contents)
    {
        super(contents);
    }
}
