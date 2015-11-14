package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.digests.longdigest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.arrays;

/**
 * a generic tls mac implementation, acting as an hmac based on some underlying digest.
 */
public class tlsmac
{

    protected tlscontext context;
    protected byte[] secret;
    protected mac mac;
    protected int digestblocksize;
    protected int digestoverhead;

    /**
     * generate a new instance of an tlsmac.
     *
     * @param context the tls client context
     * @param digest  the digest to use.
     * @param key     a byte-array where the key for this mac is located.
     * @param keyoff  the number of bytes to skip, before the key starts in the buffer.
     * @param len     the length of the key.
     */
    public tlsmac(tlscontext context, digest digest, byte[] key, int keyoff, int keylen)
    {
        this.context = context;

        keyparameter keyparameter = new keyparameter(key, keyoff, keylen);

        this.secret = arrays.clone(keyparameter.getkey());

        // todo this should check the actual algorithm, not rely on the engine type
        if (digest instanceof longdigest)
        {
            this.digestblocksize = 128;
            this.digestoverhead = 16;
        }
        else
        {
            this.digestblocksize = 64;
            this.digestoverhead = 8;
        }

        if (context.getserverversion().isssl())
        {
            this.mac = new ssl3mac(digest);

            // todo this should check the actual algorithm, not assume based on the digest size
            if (digest.getdigestsize() == 20)
            {
                /*
                 * note: when sha-1 is used with the ssl 3.0 mac, the secret + input pad is not
                 * digest block-aligned.
                 */
                this.digestoverhead = 4;
            }
        }
        else
        {
            this.mac = new hmac(digest);

            // note: the input pad for hmac is always a full digest block
        }

        this.mac.init(keyparameter);
    }

    /**
     * @return the mac write secret
     */
    public byte[] getmacsecret()
    {
        return this.secret;
    }

    /**
     * @return the keysize of the mac.
     */
    public int getsize()
    {
        return mac.getmacsize();
    }

    /**
     * calculate the mac for some given data.
     *
     * @param type    the message type of the message.
     * @param message a byte-buffer containing the message.
     * @param offset  the number of bytes to skip, before the message starts.
     * @param length  the length of the message.
     * @return a new byte-buffer containing the mac value.
     */
    public byte[] calculatemac(long seqno, short type, byte[] message, int offset, int length)
    {

        protocolversion serverversion = context.getserverversion();
        boolean isssl = serverversion.isssl();

        bytearrayoutputstream bosmac = new bytearrayoutputstream(isssl ? 11 : 13);
        try
        {
            tlsutils.writeuint64(seqno, bosmac);
            tlsutils.writeuint8(type, bosmac);

            if (!isssl)
            {
                tlsutils.writeversion(serverversion, bosmac);
            }

            tlsutils.writeuint16(length, bosmac);
        }
        catch (ioexception e)
        {
            // this should never happen
            throw new illegalstateexception("internal error during mac calculation");
        }

        byte[] macheader = bosmac.tobytearray();
        mac.update(macheader, 0, macheader.length);
        mac.update(message, offset, length);

        byte[] result = new byte[mac.getmacsize()];
        mac.dofinal(result, 0);
        return result;
    }

    public byte[] calculatemacconstanttime(long seqno, short type, byte[] message, int offset, int length,
                                           int fulllength, byte[] dummydata)
    {

        /*
         * actual mac only calculated on 'length' bytes...
         */
        byte[] result = calculatemac(seqno, type, message, offset, length);

        /*
         * ...but ensure a constant number of complete digest blocks are processed (as many as would
         * be needed for 'fulllength' bytes of input).
         */
        int headerlength = context.getserverversion().isssl() ? 11 : 13;

        // how many extra full blocks do we need to calculate?
        int extra = getdigestblockcount(headerlength + fulllength) - getdigestblockcount(headerlength + length);

        while (--extra >= 0)
        {
            mac.update(dummydata, 0, digestblocksize);
        }

        // one more byte in case the implementation is "lazy" about processing blocks
        mac.update(dummydata[0]);
        mac.reset();

        return result;
    }

    private int getdigestblockcount(int inputlength)
    {
        // note: this calculation assumes a minimum of 1 pad byte
        return (inputlength + digestoverhead) / digestblocksize;
    }
}
