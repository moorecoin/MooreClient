package org.ripple.bouncycastle.crypto.engines;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsablindingparameters;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;

import java.math.biginteger;

/**
 * this does your basic rsa chaum's blinding and unblinding as outlined in
 * "handbook of applied cryptography", page 475. you need to use this if you are
 * trying to get another party to generate signatures without them being aware
 * of the message they are signing.
 */
public class rsablindingengine
    implements asymmetricblockcipher
{
    private rsacoreengine core = new rsacoreengine();

    private rsakeyparameters key;
    private biginteger blindingfactor;

    private boolean forencryption;

    /**
     * initialise the blinding engine.
     *
     * @param forencryption true if we are encrypting (blinding), false otherwise.
     * @param param         the necessary rsa key parameters.
     */
    public void init(
        boolean forencryption,
        cipherparameters param)
    {
        rsablindingparameters p;

        if (param instanceof parameterswithrandom)
        {
            parameterswithrandom rparam = (parameterswithrandom)param;

            p = (rsablindingparameters)rparam.getparameters();
        }
        else
        {
            p = (rsablindingparameters)param;
        }

        core.init(forencryption, p.getpublickey());

        this.forencryption = forencryption;
        this.key = p.getpublickey();
        this.blindingfactor = p.getblindingfactor();
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
        return core.getinputblocksize();
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
        return core.getoutputblocksize();
    }

    /**
     * process a single block using the rsa blinding algorithm.
     *
     * @param in    the input array.
     * @param inoff the offset into the input buffer where the data starts.
     * @param inlen the length of the data to be processed.
     * @return the result of the rsa process.
     * @throws datalengthexception the input block is too large.
     */
    public byte[] processblock(
        byte[] in,
        int inoff,
        int inlen)
    {
        biginteger msg = core.convertinput(in, inoff, inlen);

        if (forencryption)
        {
            msg = blindmessage(msg);
        }
        else
        {
            msg = unblindmessage(msg);
        }

        return core.convertoutput(msg);
    }

    /*
     * blind message with the blind factor.
     */
    private biginteger blindmessage(
        biginteger msg)
    {
        biginteger blindmsg = blindingfactor;
        blindmsg = msg.multiply(blindmsg.modpow(key.getexponent(), key.getmodulus()));
        blindmsg = blindmsg.mod(key.getmodulus());

        return blindmsg;
    }

    /*
     * unblind the message blinded with the blind factor.
     */
    private biginteger unblindmessage(
        biginteger blindedmsg)
    {
        biginteger m = key.getmodulus();
        biginteger msg = blindedmsg;
        biginteger blindfactorinverse = blindingfactor.modinverse(m);
        msg = msg.multiply(blindfactorinverse);
        msg = msg.mod(m);

        return msg;
    }
}
