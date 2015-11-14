package org.ripple.bouncycastle.asn1.misc;

import org.ripple.bouncycastle.asn1.deria5string;

public class verisignczagextension
    extends deria5string
{
    public verisignczagextension(
        deria5string str)
    {
        super(str.getstring());
    }

    public string tostring()
    {
        return "verisignczagextension: " + this.getstring();
    }
}
