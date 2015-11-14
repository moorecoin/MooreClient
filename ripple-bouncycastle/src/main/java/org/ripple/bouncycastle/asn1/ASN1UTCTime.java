package org.ripple.bouncycastle.asn1;

import java.util.date;

public class asn1utctime
    extends derutctime
{
    asn1utctime(byte[] bytes)
    {
        super(bytes);
    }

    public asn1utctime(date time)
    {
        super(time);
    }

    public asn1utctime(string time)
    {
        super(time);
    }
}
