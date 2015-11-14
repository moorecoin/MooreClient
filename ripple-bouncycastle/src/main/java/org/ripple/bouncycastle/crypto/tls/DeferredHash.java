package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;

import org.ripple.bouncycastle.crypto.digest;

/**
 * buffers input until the hash algorithm is determined.
 */
class deferredhash
    implements tlshandshakehash
{

    protected tlscontext context;

    private bytearrayoutputstream buf = new bytearrayoutputstream();
    private int prfalgorithm = -1;
    private digest hash = null;

    deferredhash()
    {
        this.buf = new bytearrayoutputstream();
        this.hash = null;
    }

    private deferredhash(digest hash)
    {
        this.buf = null;
        this.hash = hash;
    }

    public void init(tlscontext context)
    {
        this.context = context;
    }

    public tlshandshakehash commit()
    {

        int prfalgorithm = context.getsecurityparameters().getprfalgorithm();

        digest prfhash = tlsutils.createprfhash(prfalgorithm);

        byte[] data = buf.tobytearray();
        prfhash.update(data, 0, data.length);

        if (prfhash instanceof tlshandshakehash)
        {
            tlshandshakehash tlsprfhash = (tlshandshakehash)prfhash;
            tlsprfhash.init(context);
            return tlsprfhash.commit();
        }

        this.prfalgorithm = prfalgorithm;
        this.hash = prfhash;
        this.buf = null;

        return this;
    }

    public tlshandshakehash fork()
    {
        checkhash();
        return new deferredhash(tlsutils.cloneprfhash(prfalgorithm, hash));
    }

    public string getalgorithmname()
    {
        checkhash();
        return hash.getalgorithmname();
    }

    public int getdigestsize()
    {
        checkhash();
        return hash.getdigestsize();
    }

    public void update(byte input)
    {
        if (hash == null)
        {
            buf.write(input);
        }
        else
        {
            hash.update(input);
        }
    }

    public void update(byte[] input, int inoff, int len)
    {
        if (hash == null)
        {
            buf.write(input, inoff, len);
        }
        else
        {
            hash.update(input, inoff, len);
        }
    }

    public int dofinal(byte[] output, int outoff)
    {
        checkhash();
        return hash.dofinal(output, outoff);
    }

    public void reset()
    {
        if (hash == null)
        {
            buf.reset();
        }
        else
        {
            hash.reset();
        }
    }

    protected void checkhash()
    {
        if (hash == null)
        {
            throw new illegalstateexception("no hash algorithm has been set");
        }
    }
}
