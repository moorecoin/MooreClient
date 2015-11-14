package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.ioexception;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.openpgp.pgpexception;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculatorprovider;

public class bcpgpdigestcalculatorprovider
    implements pgpdigestcalculatorprovider
{
    public pgpdigestcalculator get(final int algorithm)
        throws pgpexception
    {
        final digest dig = bcimplprovider.createdigest(algorithm);

        final digestoutputstream stream = new digestoutputstream(dig);

        return new pgpdigestcalculator()
        {
            public int getalgorithm()
            {
                return algorithm;
            }

            public outputstream getoutputstream()
            {
                return stream;
            }

            public byte[] getdigest()
            {
                return stream.getdigest();
            }

            public void reset()
            {
                dig.reset();
            }
        };
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

        byte[] getdigest()
        {
            byte[] d = new byte[dig.getdigestsize()];

            dig.dofinal(d, 0);

            return d;
        }
    }
}