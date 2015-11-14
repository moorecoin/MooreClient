package org.ripple.bouncycastle.asn1;

import java.math.biginteger;

public class asn1enumerated
    extends derenumerated
{
    asn1enumerated(byte[] bytes)
    {
        super(bytes);
    }

    public asn1enumerated(biginteger value)
    {
        super(value);
    }

    public asn1enumerated(int value)
    {
        super(value);
    }
}
