package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.wrapper;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.util.arrays;

/**
 * an implementation of the aes key wrapper from the nist key wrap
 * specification as described in rfc 3394.
 * <p>
 * for further details see: <a href="http://www.ietf.org/rfc/rfc3394.txt">http://www.ietf.org/rfc/rfc3394.txt</a>
 * and  <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
 */
public class rfc3394wrapengine
    implements wrapper
{
    private blockcipher     engine;
    private keyparameter    param;
    private boolean         forwrapping;

    private byte[]          iv = {
                              (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6,
                              (byte)0xa6, (byte)0xa6, (byte)0xa6, (byte)0xa6 };

    public rfc3394wrapengine(blockcipher engine)
    {
        this.engine = engine;
    }

    public void init(
        boolean             forwrapping,
        cipherparameters    param)
    {
        this.forwrapping = forwrapping;

        if (param instanceof parameterswithrandom)
        {
            param = ((parameterswithrandom) param).getparameters();
        }

        if (param instanceof keyparameter)
        {
            this.param = (keyparameter)param;
        }
        else if (param instanceof parameterswithiv)
        {
            this.iv = ((parameterswithiv)param).getiv();
            this.param = (keyparameter)((parameterswithiv) param).getparameters();
            if (this.iv.length != 8)
            {
               throw new illegalargumentexception("iv not equal to 8");
            }
        }
    }

    public string getalgorithmname()
    {
        return engine.getalgorithmname();
    }

    public byte[] wrap(
        byte[]  in,
        int     inoff,
        int     inlen)
    {
        if (!forwrapping)
        {
            throw new illegalstateexception("not set for wrapping");
        }

        int     n = inlen / 8;

        if ((n * 8) != inlen)
        {
            throw new datalengthexception("wrap data must be a multiple of 8 bytes");
        }

        byte[]  block = new byte[inlen + iv.length];
        byte[]  buf = new byte[8 + iv.length];

        system.arraycopy(iv, 0, block, 0, iv.length);
        system.arraycopy(in, 0, block, iv.length, inlen);

        engine.init(true, param);

        for (int j = 0; j != 6; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                system.arraycopy(block, 0, buf, 0, iv.length);
                system.arraycopy(block, 8 * i, buf, iv.length, 8);
                engine.processblock(buf, 0, buf, 0);

                int t = n * j + i;
                for (int k = 1; t != 0; k++)
                {
                    byte    v = (byte)t;

                    buf[iv.length - k] ^= v;

                    t >>>= 8;
                }

                system.arraycopy(buf, 0, block, 0, 8);
                system.arraycopy(buf, 8, block, 8 * i, 8);
            }
        }

        return block;
    }

    public byte[] unwrap(
        byte[]  in,
        int     inoff,
        int     inlen)
        throws invalidciphertextexception
    {
        if (forwrapping)
        {
            throw new illegalstateexception("not set for unwrapping");
        }

        int     n = inlen / 8;

        if ((n * 8) != inlen)
        {
            throw new invalidciphertextexception("unwrap data must be a multiple of 8 bytes");
        }

        byte[]  block = new byte[inlen - iv.length];
        byte[]  a = new byte[iv.length];
        byte[]  buf = new byte[8 + iv.length];

        system.arraycopy(in, 0, a, 0, iv.length);
        system.arraycopy(in, iv.length, block, 0, inlen - iv.length);

        engine.init(false, param);

        n = n - 1;

        for (int j = 5; j >= 0; j--)
        {
            for (int i = n; i >= 1; i--)
            {
                system.arraycopy(a, 0, buf, 0, iv.length);
                system.arraycopy(block, 8 * (i - 1), buf, iv.length, 8);

                int t = n * j + i;
                for (int k = 1; t != 0; k++)
                {
                    byte    v = (byte)t;

                    buf[iv.length - k] ^= v;

                    t >>>= 8;
                }

                engine.processblock(buf, 0, buf, 0);
                system.arraycopy(buf, 0, a, 0, 8);
                system.arraycopy(buf, 8, block, 8 * (i - 1), 8);
            }
        }

        if (!arrays.constanttimeareequal(a, iv))
        {
            throw new invalidciphertextexception("checksum failed");
        }

        return block;
    }
}
