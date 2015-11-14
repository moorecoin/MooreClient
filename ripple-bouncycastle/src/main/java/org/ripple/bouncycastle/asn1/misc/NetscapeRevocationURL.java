package org.ripple.bouncycastle.asn1.misc;

import org.ripple.bouncycastle.asn1.deria5string;

public class netscaperevocationurl
    extends deria5string
{
    public netscaperevocationurl(
        deria5string str)
    {
        super(str.getstring());
    }

    public string tostring()
    {
        return "netscaperevocationurl: " + this.getstring();
    }
}
