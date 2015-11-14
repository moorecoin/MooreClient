package org.ripple.bouncycastle.crypto.params;

import java.math.biginteger;

public class rsaprivatecrtkeyparameters
    extends rsakeyparameters
{
    private biginteger  e;
    private biginteger  p;
    private biginteger  q;
    private biginteger  dp;
    private biginteger  dq;
    private biginteger  qinv;

    /**
     * 
     */
    public rsaprivatecrtkeyparameters(
        biginteger  modulus,
        biginteger  publicexponent,
        biginteger  privateexponent,
        biginteger  p,
        biginteger  q,
        biginteger  dp,
        biginteger  dq,
        biginteger  qinv)
    {
        super(true, modulus, privateexponent);

        this.e = publicexponent;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qinv = qinv;
    }

    public biginteger getpublicexponent()
    {
        return e;
    }

    public biginteger getp()
    {
        return p;
    }

    public biginteger getq()
    {
        return q;
    }

    public biginteger getdp()
    {
        return dp;
    }

    public biginteger getdq()
    {
        return dq;
    }

    public biginteger getqinv()
    {
        return qinv;
    }
}
