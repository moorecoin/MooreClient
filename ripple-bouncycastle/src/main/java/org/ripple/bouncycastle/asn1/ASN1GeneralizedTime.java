package org.ripple.bouncycastle.asn1;

import java.util.date;

public class asn1generalizedtime
    extends dergeneralizedtime
{
    asn1generalizedtime(byte[] bytes)
    {
        super(bytes);
    }

    public asn1generalizedtime(date time)
    {
        super(time);
    }

    public asn1generalizedtime(string time)
    {
        super(time);
    }
}
