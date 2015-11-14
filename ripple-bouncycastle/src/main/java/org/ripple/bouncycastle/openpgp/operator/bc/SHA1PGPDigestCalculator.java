package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

class sha1pgpdigestcalculator
    implements pgpdigestcalculator
{
    private digest digest = new sha1digest();

    public int getalgorithm()
    {
        return hashalgorithmtags.sha1;
    }

    public outputstream getoutputstream()
    {
        return new digestoutputstream(digest);
    }

    public byte[] getdigest()
    {
        byte[] d = new byte[digest.getdigestsize()];

        digest.dofinal(d, 0);

        return d;
    }

    public void reset()
    {
        digest.reset();
    }

    private class digestoutputstream
        extends outputstream
    {
        private digest dig;

        digestoutputstream(digest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] bytes, int off, int len)
            throws ioexception
        {
            dig.update(bytes, off, len);
        }

        public void write(byte[] bytes)
            throws ioexception
        {
            dig.update(bytes, 0, bytes.length);
        }

        public void write(int b)
            throws ioexception
        {
            dig.update((byte)b);
        }
    }
}
