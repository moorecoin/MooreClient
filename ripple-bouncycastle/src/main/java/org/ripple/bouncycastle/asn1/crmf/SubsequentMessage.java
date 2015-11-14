package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1integer;

public class subsequentmessage
    extends asn1integer
{
    public static final subsequentmessage encrcert = new subsequentmessage(0);
    public static final subsequentmessage challengeresp = new subsequentmessage(1);
    
    private subsequentmessage(int value)
    {
        super(value);
    }

    public static subsequentmessage valueof(int value)
    {
        if (value == 0)
        {
            return encrcert;
        }
        if (value == 1)
        {
            return challengeresp;
        }

        throw new illegalargumentexception("unknown value: " + value);
    }
}
