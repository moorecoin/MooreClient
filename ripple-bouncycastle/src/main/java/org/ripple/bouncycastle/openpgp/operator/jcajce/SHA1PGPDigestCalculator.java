package org.ripple.bouncycastle.openpgp.operator.jcajce;

import java.io.ioexception;
import java.io.outputstream;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;

import org.ripple.bouncycastle.bcpg.hashalgorithmtags;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

class sha1pgpdigestcalculator
    implements pgpdigestcalculator
{
    private messagedigest digest;

    sha1pgpdigestcalculator()
    {
        try
        {
            digest = messagedigest.getinstance("sha1");
        }
        catch (nosuchalgorithmexception e)
        {
            throw new illegalstateexception("cannot find sha-1: " + e.getmessage());
        }
    }

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
        return digest.digest();
    }

    public void reset()
    {
        digest.reset();
    }

    private class digestoutputstream
        extends outputstream
    {
        private messagedigest dig;

        digestoutputstream(messagedigest dig)
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
            dig.update(bytes);
        }

        public void write(int b)
            throws ioexception
        {
            dig.update((byte)b);
        }

        byte[] getdigest()
        {
            return dig.digest();
        }
    }
}
