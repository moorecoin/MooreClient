package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.wrapper;
import org.ripple.bouncycastle.crypto.modes.cbcblockcipher;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

import java.security.securerandom;

/**
 * an implementation of the rfc 3211 key wrap
 * specification.
 */
public class rfc3211wrapengine
    implements wrapper
{
    private cbcblockcipher   engine;
    private parameterswithiv param;
    private boolean          forwrapping;
    private securerandom     rand;

    public rfc3211wrapengine(blockcipher engine)
    {
        this.engine = new cbcblockcipher(engine);
    }

    public void init(
        boolean          forwrapping,
        cipherparameters param)
    {
        this.forwrapping = forwrapping;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom p = (parameterswithrandom)param;

            rand = p.getrandom();
            this.param = (parameterswithiv)p.getparameters();
        }
        else
        {
            if (forwrapping)
            {
                rand = new securerandom();
            }

            this.param = (parameterswithiv)param;
        }
    }

    public string getalgorithmname()
    {
        return engine.getunderlyingcipher().getalgorithmname() + "/rfc3211wrap";
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

        engine.init(true, param);

        int blocksize = engine.getblocksize();
        byte[] cekblock;

        if (inlen + 4 < blocksize * 2)
        {
            cekblock = new byte[blocksize * 2];
        }
        else
        {
            cekblock = new byte[(inlen + 4) % blocksize == 0 ? inlen + 4 : ((inlen + 4) / blocksize + 1) * blocksize];
        }

        cekblock[0] = (byte)inlen;
        cekblock[1] = (byte)~in[inoff];
        cekblock[2] = (byte)~in[inoff + 1];
        cekblock[3] = (byte)~in[inoff + 2];

        system.arraycopy(in, inoff, cekblock, 4, inlen);

        for (int i = inlen + 4; i < cekblock.length; i++)
        {
            cekblock[i] = (byte)rand.nextint();
        }

        for (int i = 0; i < cekblock.length; i += blocksize)
        {
            engine.processblock(cekblock, i, cekblock, i);
        }

        for (int i = 0; i < cekblock.length; i += blocksize)
        {
            engine.processblock(cekblock, i, cekblock, i);
        }

        return cekblock;
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

        int blocksize = engine.getblocksize();

        if (inlen < 2 * blocksize)
        {
            throw new invalidciphertextexception("input too short");
        }
        
        byte[] cekblock = new byte[inlen];
        byte[] iv = new byte[blocksize];

        system.arraycopy(in, inoff, cekblock, 0, inlen);
        system.arraycopy(in, inoff, iv, 0, iv.length);
        
        engine.init(false, new parameterswithiv(param.getparameters(), iv));

        for (int i = blocksize; i < cekblock.length; i += blocksize)
        {
            engine.processblock(cekblock, i, cekblock, i);    
        }

        system.arraycopy(cekblock, cekblock.length - iv.length, iv, 0, iv.length);

        engine.init(false, new parameterswithiv(param.getparameters(), iv));

        engine.processblock(cekblock, 0, cekblock, 0);

        engine.init(false, param);

        for (int i = 0; i < cekblock.length; i += blocksize)
        {
            engine.processblock(cekblock, i, cekblock, i);
        }

        if ((cekblock[0] & 0xff) > cekblock.length - 4)
        {
            throw new invalidciphertextexception("wrapped key corrupted");
        }

        byte[] key = new byte[cekblock[0] & 0xff];

        system.arraycopy(cekblock, 4, key, 0, cekblock[0]);

        // note: using constant time comparison
        int nonequal = 0;
        for (int i = 0; i != 3; i++)
        {
            byte check = (byte)~cekblock[1 + i];
            nonequal |= (check ^ key[i]);
        }
        if (nonequal != 0)
        {
            throw new invalidciphertextexception("wrapped key fails checksum");
        }

        return key;
    }
}
