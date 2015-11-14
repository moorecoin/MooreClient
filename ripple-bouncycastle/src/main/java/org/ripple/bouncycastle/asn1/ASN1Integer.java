package org.ripple.bouncycastle.asn1;

import java.math.biginteger;

public class asn1integer
    extends derinteger
{
    asn1integer(byte[] bytes)
    {
        super(bytes);
    }

    public asn1integer(biginteger value)
    {
        super(value);
    }

    public asn1integer(long value)
    {
        super(value);
    }
}
