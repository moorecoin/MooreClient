package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

import java.math.biginteger;

/**
 * this does your basic rsa algorithm.
 */
class rsacoreengine
{
    private rsakeyparameters key;
    private boolean          forencryption;

    /**
     * initialise the rsa engine.
     *
     * @param forencryption true if we are encrypting, false otherwise.
     * @param param the necessary rsa key parameters.
     */
    public void init(
        boolean          forencryption,
        cipherparameters param)
    {
        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    rparam = (parameterswithrandom)param;

            key = (rsakeyparameters)rparam.getparameters();
        }
        else
        {
            key = (rsakeyparameters)param;
        }

        this.forencryption = forencryption;
    }

    /**
     * return the maximum size for an input block to this engine.
     * for rsa this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getinputblocksize()
    {
        int     bitsize = key.getmodulus().bitlength();

        if (forencryption)
        {
            return (bitsize + 7) / 8 - 1;
        }
        else
        {
            return (bitsize + 7) / 8;
        }
    }

    /**
     * return the maximum size for an output block to this engine.
     * for rsa this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getoutputblocksize()
    {
        int     bitsize = key.getmodulus().bitlength();

        if (forencryption)
        {
            return (bitsize + 7) / 8;
        }
        else
        {
            return (bitsize + 7) / 8 - 1;
        }
    }

    public biginteger convertinput(
        byte[]  in,
        int     inoff,
        int     inlen)
    {
        if (inlen > (getinputblocksize() + 1))
        {
            throw new datalengthexception("input too large for rsa cipher.");
        }
        else if (inlen == (getinputblocksize() + 1) && !forencryption)
        {
            throw new datalengthexception("input too large for rsa cipher.");
        }

        byte[]  block;

        if (inoff != 0 || inlen != in.length)
        {
            block = new byte[inlen];

            system.arraycopy(in, inoff, block, 0, inlen);
        }
        else
        {
            block = in;
        }

        biginteger res = new biginteger(1, block);
        if (res.compareto(key.getmodulus()) >= 0)
        {
            throw new datalengthexception("input too large for rsa cipher.");
        }

        return res;
    }

    public byte[] convertoutput(
        biginteger result)
    {
        byte[]      output = result.tobytearray();

        if (forencryption)
        {
            if (output[0] == 0 && output.length > getoutputblocksize())        // have ended up with an extra zero byte, copy down.
            {
                byte[]  tmp = new byte[output.length - 1];

                system.arraycopy(output, 1, tmp, 0, tmp.length);

                return tmp;
            }

            if (output.length < getoutputblocksize())     // have ended up with less bytes than normal, lengthen
            {
                byte[]  tmp = new byte[getoutputblocksize()];

                system.arraycopy(output, 0, tmp, tmp.length - output.length, output.length);

                return tmp;
            }
        }
        else
        {
            if (output[0] == 0)        // have ended up with an extra zero byte, copy down.
            {
                byte[]  tmp = new byte[output.length - 1];

                system.arraycopy(output, 1, tmp, 0, tmp.length);

                return tmp;
            }
        }

        return output;
    }

    public biginteger processblock(biginteger input)
    {
        if (key instanceof rsaprivatecrtkeyparameters)
        {
            //
            // we have the extra factors, use the chinese remainder theorem - the author
            // wishes to express his thanks to dirk bonekaemper at rtsffm.com for
            // advice regarding the expression of this.
            //
            rsaprivatecrtkeyparameters crtkey = (rsaprivatecrtkeyparameters)key;

            biginteger p = crtkey.getp();
            biginteger q = crtkey.getq();
            biginteger dp = crtkey.getdp();
            biginteger dq = crtkey.getdq();
            biginteger qinv = crtkey.getqinv();

            biginteger mp, mq, h, m;

            // mp = ((input mod p) ^ dp)) mod p
            mp = (input.remainder(p)).modpow(dp, p);

            // mq = ((input mod q) ^ dq)) mod q
            mq = (input.remainder(q)).modpow(dq, q);

            // h = qinv * (mp - mq) mod p
            h = mp.subtract(mq);
            h = h.multiply(qinv);
            h = h.mod(p);               // mod (in java) returns the positive residual

            // m = h * q + mq
            m = h.multiply(q);
            m = m.add(mq);

            return m;
        }
        else
        {
            return input.modpow(
                        key.getexponent(), key.getmodulus());
        }
    }
}
