package org.ripple.bouncycastle.crypto.digests;

import java.io.bytearrayoutputstream;

import org.ripple.bouncycastle.crypto.digest;


public class nulldigest
    implements digest
{
    private bytearrayoutputstream bout = new bytearrayoutputstream();

    public string getalgorithmname()
    {
        return "null";
    }

    public int getdigestsize()
    {
        return bout.size();
    }

    public void update(byte in)
    {
        bout.write(in);
    }

    public void update(byte[] in, int inoff, int len)
    {
        bout.write(in, inoff, len);
    }

    public int dofinal(byte[] out, int outoff)
    {
        byte[] res = bout.tobytearray();

        system.arraycopy(res, 0, out, outoff, res.length);

        reset();
        
        return res.length;
    }

    public void reset()
    {
        bout.reset();
    }
}