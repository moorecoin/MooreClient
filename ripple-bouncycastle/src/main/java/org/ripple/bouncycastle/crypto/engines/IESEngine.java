package org.ripple.bouncycastle.crypto.engines;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.math.biginteger;

import org.ripple.bouncycastle.crypto.basicagreement;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.ephemeralkeypair;
import org.ripple.bouncycastle.crypto.invalidciphertextexception;
import org.ripple.bouncycastle.crypto.keyparser;
import org.ripple.bouncycastle.crypto.mac;
import org.ripple.bouncycastle.crypto.generators.ephemeralkeypairgenerator;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.iesparameters;
import org.ripple.bouncycastle.crypto.params.ieswithcipherparameters;
import org.ripple.bouncycastle.crypto.params.kdfparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.util.pack;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.bigintegers;

/**
 * support class for constructing integrated encryption ciphers
 * for doing basic message exchanges on top of key agreement ciphers.
 * follows the description given in ieee std 1363a.
 */
public class iesengine
{
    basicagreement agree;
    derivationfunction kdf;
    mac mac;
    bufferedblockcipher cipher;
    byte[] macbuf;

    boolean forencryption;
    cipherparameters privparam, pubparam;
    iesparameters param;

    byte[] v;
    private ephemeralkeypairgenerator keypairgenerator;
    private keyparser keyparser;


    /**
     * set up for use with stream mode, where the key derivation function
     * is used to provide a stream of bytes to xor with the message.
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf   the key derivation function used for byte generation
     * @param mac   the message authentication code generator for the message
     */
    public iesengine(
        basicagreement agree,
        derivationfunction kdf,
        mac mac)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macbuf = new byte[mac.getmacsize()];
        this.cipher = null;
    }


    /**
     * set up for use in conjunction with a block cipher to handle the
     * message.
     *
     * @param agree  the key agreement used as the basis for the encryption
     * @param kdf    the key derivation function used for byte generation
     * @param mac    the message authentication code generator for the message
     * @param cipher the cipher to used for encrypting the message
     */
    public iesengine(
        basicagreement agree,
        derivationfunction kdf,
        mac mac,
        bufferedblockcipher cipher)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macbuf = new byte[mac.getmacsize()];
        this.cipher = cipher;
    }


    /**
     * initialise the encryptor.
     *
     * @param forencryption whether or not this is encryption/decryption.
     * @param privparam     our private key parameters
     * @param pubparam      the recipient's/sender's public key parameters
     * @param param         encoding and derivation parameters.
     */
    public void init(
        boolean forencryption,
        cipherparameters privparam,
        cipherparameters pubparam,
        cipherparameters param)
    {
        this.forencryption = forencryption;
        this.privparam = privparam;
        this.pubparam = pubparam;
        this.param = (iesparameters)param;
        this.v = new byte[0];
    }


    /**
     * initialise the encryptor.
     *
     * @param publickey      the recipient's/sender's public key parameters
     * @param params         encoding and derivation parameters.
     * @param ephemeralkeypairgenerator             the ephemeral key pair generator to use.
     */
    public void init(asymmetrickeyparameter publickey, cipherparameters params, ephemeralkeypairgenerator ephemeralkeypairgenerator)
    {
        this.forencryption = true;
        this.pubparam = publickey;
        this.param = (iesparameters)params;
        this.keypairgenerator = ephemeralkeypairgenerator;
    }

    /**
     * initialise the encryptor.
     *
     * @param privatekey      the recipient's private key.
     * @param params          encoding and derivation parameters.
     * @param publickeyparser the parser for reading the ephemeral public key.
     */
    public void init(asymmetrickeyparameter privatekey, cipherparameters params, keyparser publickeyparser)
    {
        this.forencryption = false;
        this.privparam = privatekey;
        this.param = (iesparameters)params;
        this.keyparser = publickeyparser;
    }

    public bufferedblockcipher getcipher()
    {
        return cipher;
    }

    public mac getmac()
    {
        return mac;
    }

    private byte[] encryptblock(
        byte[] in,
        int inoff,
        int inlen)
        throws invalidciphertextexception
    {
        byte[] c = null, k = null, k1 = null, k2 = null;
        int len;

        if (cipher == null)
        {
            // streaming mode.
            k1 = new byte[inlen];
            k2 = new byte[param.getmackeysize() / 8];
            k = new byte[k1.length + k2.length];

            kdf.generatebytes(k, 0, k.length);

            if (v.length != 0)
            {
                system.arraycopy(k, 0, k2, 0, k2.length);
                system.arraycopy(k, k2.length, k1, 0, k1.length);
            }
            else
            {
                system.arraycopy(k, 0, k1, 0, k1.length);
                system.arraycopy(k, inlen, k2, 0, k2.length);
            }

            c = new byte[inlen];

            for (int i = 0; i != inlen; i++)
            {
                c[i] = (byte)(in[inoff + i] ^ k1[i]);
            }
            len = inlen;
        }
        else
        {
            // block cipher mode.
            k1 = new byte[((ieswithcipherparameters)param).getcipherkeysize() / 8];
            k2 = new byte[param.getmackeysize() / 8];
            k = new byte[k1.length + k2.length];

            kdf.generatebytes(k, 0, k.length);
            system.arraycopy(k, 0, k1, 0, k1.length);
            system.arraycopy(k, k1.length, k2, 0, k2.length);

            cipher.init(true, new keyparameter(k1));
            c = new byte[cipher.getoutputsize(inlen)];
            len = cipher.processbytes(in, inoff, inlen, c, 0);
            len += cipher.dofinal(c, len);
        }


        // convert the length of the encoding vector into a byte array.
        byte[] p2 = param.getencodingv();
        byte[] l2 = new byte[4];
        if (v.length != 0 && p2 != null)
        {
            pack.inttobigendian(p2.length * 8, l2, 0);
        }


        // apply the mac.
        byte[] t = new byte[mac.getmacsize()];

        mac.init(new keyparameter(k2));
        mac.update(c, 0, c.length);
        if (p2 != null)
        {
            mac.update(p2, 0, p2.length);
        }
        if (v.length != 0)
        {
            mac.update(l2, 0, l2.length);
        }
        mac.dofinal(t, 0);


        // output the triple (v,c,t).
        byte[] output = new byte[v.length + len + t.length];
        system.arraycopy(v, 0, output, 0, v.length);
        system.arraycopy(c, 0, output, v.length, len);
        system.arraycopy(t, 0, output, v.length + len, t.length);
        return output;
    }

    private byte[] decryptblock(
        byte[] in_enc,
        int inoff,
        int inlen)
        throws invalidciphertextexception
    {
        byte[] m = null, k = null, k1 = null, k2 = null;
        int len;

        if (cipher == null)
        {
            // streaming mode.
            k1 = new byte[inlen - v.length - mac.getmacsize()];
            k2 = new byte[param.getmackeysize() / 8];
            k = new byte[k1.length + k2.length];

            kdf.generatebytes(k, 0, k.length);

            if (v.length != 0)
            {
                system.arraycopy(k, 0, k2, 0, k2.length);
                system.arraycopy(k, k2.length, k1, 0, k1.length);
            }
            else
            {
                system.arraycopy(k, 0, k1, 0, k1.length);
                system.arraycopy(k, k1.length, k2, 0, k2.length);
            }

            m = new byte[k1.length];

            for (int i = 0; i != k1.length; i++)
            {
                m[i] = (byte)(in_enc[inoff + v.length + i] ^ k1[i]);
            }

            len = k1.length;
        }
        else
        {
            // block cipher mode.        
            k1 = new byte[((ieswithcipherparameters)param).getcipherkeysize() / 8];
            k2 = new byte[param.getmackeysize() / 8];
            k = new byte[k1.length + k2.length];

            kdf.generatebytes(k, 0, k.length);
            system.arraycopy(k, 0, k1, 0, k1.length);
            system.arraycopy(k, k1.length, k2, 0, k2.length);

            cipher.init(false, new keyparameter(k1));

            m = new byte[cipher.getoutputsize(inlen - v.length - mac.getmacsize())];
            len = cipher.processbytes(in_enc, inoff + v.length, inlen - v.length - mac.getmacsize(), m, 0);
            len += cipher.dofinal(m, len);
        }


        // convert the length of the encoding vector into a byte array.
        byte[] p2 = param.getencodingv();
        byte[] l2 = new byte[4];
        if (v.length != 0 && p2 != null)
        {
            pack.inttobigendian(p2.length * 8, l2, 0);
        }


        // verify the mac.
        int end = inoff + inlen;
        byte[] t1 = arrays.copyofrange(in_enc, end - mac.getmacsize(), end);

        byte[] t2 = new byte[t1.length];
        mac.init(new keyparameter(k2));
        mac.update(in_enc, inoff + v.length, inlen - v.length - t2.length);

        if (p2 != null)
        {
            mac.update(p2, 0, p2.length);
        }
        if (v.length != 0)
        {
            mac.update(l2, 0, l2.length);
        }
        mac.dofinal(t2, 0);

        if (!arrays.constanttimeareequal(t1, t2))
        {
            throw new invalidciphertextexception("invalid mac.");
        }


        // output the message.
        return arrays.copyofrange(m, 0, len);
    }


    public byte[] processblock(
        byte[] in,
        int inoff,
        int inlen)
        throws invalidciphertextexception
    {
        if (forencryption)
        {
            if (keypairgenerator != null)
            {
                ephemeralkeypair ephkeypair = keypairgenerator.generate();

                this.privparam = ephkeypair.getkeypair().getprivate();
                this.v = ephkeypair.getencodedpublickey();
            }
        }
        else
        {
            if (keyparser != null)
            {
                bytearrayinputstream bin = new bytearrayinputstream(in, inoff, inlen);

                try
                {
                    this.pubparam = keyparser.readkey(bin);
                }
                catch (ioexception e)
                {
                    throw new invalidciphertextexception("unable to recover ephemeral public key: " + e.getmessage(), e);
                }

                int enclength = (inlen - bin.available());
                this.v = arrays.copyofrange(in, inoff, inoff + enclength);
            }
        }

        // compute the common value and convert to byte array. 
        agree.init(privparam);
        biginteger z = agree.calculateagreement(pubparam);
        byte[] z = bigintegers.asunsignedbytearray(agree.getfieldsize(), z);

        // create input to kdf.  
        byte[] vz;
        if (v.length != 0)
        {
            vz = new byte[v.length + z.length];
            system.arraycopy(v, 0, vz, 0, v.length);
            system.arraycopy(z, 0, vz, v.length, z.length);
        }
        else
        {
            vz = z;
        }

        // initialise the kdf.
        kdfparameters kdfparam = new kdfparameters(vz, param.getderivationv());
        kdf.init(kdfparam);

        return forencryption
            ? encryptblock(in, inoff, inlen)
            : decryptblock(in, inoff, inlen);
    }
}
