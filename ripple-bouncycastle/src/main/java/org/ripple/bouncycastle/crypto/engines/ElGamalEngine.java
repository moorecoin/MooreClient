package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.elgamalkeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.util.bigintegers;

import java.math.biginteger;
import java.security.securerandom;

/**
 * this does your basic elgamal algorithm.
 */
public class elgamalengine
    implements asymmetricblockcipher
{
    private elgamalkeyparameters    key;
    private securerandom            random;
    private boolean                 forencryption;
    private int                     bitsize;

    private static final biginteger zero = biginteger.valueof(0);
    private static final biginteger one = biginteger.valueof(1);
    private static final biginteger two = biginteger.valueof(2);

    /**
     * initialise the elgamal engine.
     *
     * @param forencryption true if we are encrypting, false otherwise.
     * @param param the necessary elgamal key parameters.
     */
    public void init(
        boolean             forencryption,
        cipherparameters    param)
    {
        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom    p = (parameterswithrandom)param;

            this.key = (elgamalkeyparameters)p.getparameters();
            this.random = p.getrandom();
        }
        else
        {
            this.key = (elgamalkeyparameters)param;
            this.random = new securerandom();
        }

        this.forencryption = forencryption;

        biginteger p = key.getparameters().getp();

        bitsize = p.bitlength();

        if (forencryption)
        {
            if (!(key instanceof elgamalpublickeyparameters))
            {
                throw new illegalargumentexception("elgamalpublickeyparameters are required for encryption.");
            }
        }
        else
        {
            if (!(key instanceof elgamalprivatekeyparameters))
            {
                throw new illegalargumentexception("elgamalprivatekeyparameters are required for decryption.");
            }
        }
    }

    /**
     * return the maximum size for an input block to this engine.
     * for elgamal this is always one byte less than the size of p on
     * encryption, and twice the length as the size of p on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getinputblocksize()
    {
        if (forencryption)
        {
            return (bitsize - 1) / 8;
        }

        return 2 * ((bitsize + 7) / 8);
    }

    /**
     * return the maximum size for an output block to this engine.
     * for elgamal this is always one byte less than the size of p on
     * decryption, and twice the length as the size of p on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getoutputblocksize()
    {
        if (forencryption)
        {
            return 2 * ((bitsize + 7) / 8);
        }

        return (bitsize - 1) / 8;
    }

    /**
     * process a single block using the basic elgamal algorithm.
     *
     * @param in the input array.
     * @param inoff the offset into the input buffer where the data starts.
     * @param inlen the length of the data to be processed.
     * @return the result of the elgamal process.
     * @exception datalengthexception the input block is too large.
     */
    public byte[] processblock(
        byte[]  in,
        int     inoff,
        int     inlen)
    {
        if (key == null)
        {
            throw new illegalstateexception("elgamal engine not initialised");
        }

        int maxlength = forencryption
            ?   (bitsize - 1 + 7) / 8
            :   getinputblocksize();

        if (inlen > maxlength)
        {
            throw new datalengthexception("input too large for elgamal cipher.\n");
        }

        biginteger  p = key.getparameters().getp();

        if (key instanceof elgamalprivatekeyparameters) // decryption
        {
            byte[]  in1 = new byte[inlen / 2];
            byte[]  in2 = new byte[inlen / 2];

            system.arraycopy(in, inoff, in1, 0, in1.length);
            system.arraycopy(in, inoff + in1.length, in2, 0, in2.length);

            biginteger  gamma = new biginteger(1, in1);
            biginteger  phi = new biginteger(1, in2);

            elgamalprivatekeyparameters  priv = (elgamalprivatekeyparameters)key;
            // a shortcut, which generally relies on p being prime amongst other things.
            // if a problem with this shows up, check the p and g values!
            biginteger  m = gamma.modpow(p.subtract(one).subtract(priv.getx()), p).multiply(phi).mod(p);

            return bigintegers.asunsignedbytearray(m);
        }
        else // encryption
        {
            byte[] block;
            if (inoff != 0 || inlen != in.length)
            {
                block = new byte[inlen];

                system.arraycopy(in, inoff, block, 0, inlen);
            }
            else
            {
                block = in;
            }

            biginteger input = new biginteger(1, block);

            if (input.bitlength() >= p.bitlength())
            {
                throw new datalengthexception("input too large for elgamal cipher.\n");
            }

            elgamalpublickeyparameters  pub = (elgamalpublickeyparameters)key;

            int                         pbitlength = p.bitlength();
            biginteger                  k = new biginteger(pbitlength, random);

            while (k.equals(zero) || (k.compareto(p.subtract(two)) > 0))
            {
                k = new biginteger(pbitlength, random);
            }

            biginteger  g = key.getparameters().getg();
            biginteger  gamma = g.modpow(k, p);
            biginteger  phi = input.multiply(pub.gety().modpow(k, p)).mod(p);

            byte[]  out1 = gamma.tobytearray();
            byte[]  out2 = phi.tobytearray();
            byte[]  output = new byte[this.getoutputblocksize()];

            if (out1.length > output.length / 2)
            {
                system.arraycopy(out1, 1, output, output.length / 2 - (out1.length - 1), out1.length - 1);
            }
            else
            {
                system.arraycopy(out1, 0, output, output.length / 2 - out1.length, out1.length);
            }

            if (out2.length > output.length / 2)
            {
                system.arraycopy(out2, 1, output, output.length - (out2.length - 1), out2.length - 1);
            }
            else
            {
                system.arraycopy(out2, 0, output, output.length - out2.length, out2.length);
            }

            return output;
        }
    }
}
