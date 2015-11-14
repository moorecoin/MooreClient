package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.digest;

/**
 * a combined hash, which implements md5(m) || sha1(m).
 */
class combinedhash
    implements tlshandshakehash
{

    protected tlscontext context;
    protected digest md5;
    protected digest sha1;

    combinedhash()
    {
        this.md5 = tlsutils.createhash(hashalgorithm.md5);
        this.sha1 = tlsutils.createhash(hashalgorithm.sha1);
    }

    combinedhash(combinedhash t)
    {
        this.context = t.context;
        this.md5 = tlsutils.clonehash(hashalgorithm.md5, t.md5);
        this.sha1 = tlsutils.clonehash(hashalgorithm.sha1, t.sha1);
    }

    public void init(tlscontext context)
    {
        this.context = context;
    }

    public tlshandshakehash commit()
    {
        return this;
    }

    public tlshandshakehash fork()
    {
        return new combinedhash(this);
    }

    /**
     * @see org.ripple.bouncycastle.crypto.digest#getalgorithmname()
     */
    public string getalgorithmname()
    {
        return md5.getalgorithmname() + " and " + sha1.getalgorithmname();
    }

    /**
     * @see org.ripple.bouncycastle.crypto.digest#getdigestsize()
     */
    public int getdigestsize()
    {
        return md5.getdigestsize() + sha1.getdigestsize();
    }

    /**
     * @see org.ripple.bouncycastle.crypto.digest#update(byte)
     */
    public void update(byte in)
    {
        md5.update(in);
        sha1.update(in);
    }

    /**
     * @see org.ripple.bouncycastle.crypto.digest#update(byte[], int, int)
     */
    public void update(byte[] in, int inoff, int len)
    {
        md5.update(in, inoff, len);
        sha1.update(in, inoff, len);
    }

    /**
     * @see org.ripple.bouncycastle.crypto.digest#dofinal(byte[], int)
     */
    public int dofinal(byte[] out, int outoff)
    {
        if (context != null && context.getserverversion().isssl())
        {
            ssl3complete(md5, ssl3mac.ipad, ssl3mac.opad, 48);
            ssl3complete(sha1, ssl3mac.ipad, ssl3mac.opad, 40);
        }

        int i1 = md5.dofinal(out, outoff);
        int i2 = sha1.dofinal(out, outoff + i1);
        return i1 + i2;
    }

    /**
     * @see org.ripple.bouncycastle.crypto.digest#reset()
     */
    public void reset()
    {
        md5.reset();
        sha1.reset();
    }

    protected void ssl3complete(digest d, byte[] ipad, byte[] opad, int padlength)
    {
        byte[] secret = context.getsecurityparameters().mastersecret;

        d.update(secret, 0, secret.length);
        d.update(ipad, 0, padlength);

        byte[] tmp = new byte[d.getdigestsize()];
        d.dofinal(tmp, 0);

        d.update(secret, 0, secret.length);
        d.update(opad, 0, padlength);
        d.update(tmp, 0, tmp.length);
    }
}
