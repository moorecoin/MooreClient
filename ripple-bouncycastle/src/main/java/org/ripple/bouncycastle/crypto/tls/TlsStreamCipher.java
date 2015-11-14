package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.streamcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.arrays;

public class tlsstreamcipher
    implements tlscipher
{
    protected tlscontext context;

    protected streamcipher encryptcipher;
    protected streamcipher decryptcipher;

    protected tlsmac writemac;
    protected tlsmac readmac;

    public tlsstreamcipher(tlscontext context, streamcipher clientwritecipher,
                           streamcipher serverwritecipher, digest clientwritedigest, digest serverwritedigest,
                           int cipherkeysize)
        throws ioexception
    {

        boolean isserver = context.isserver();

        this.context = context;

        this.encryptcipher = clientwritecipher;
        this.decryptcipher = serverwritecipher;

        int key_block_size = (2 * cipherkeysize) + clientwritedigest.getdigestsize()
            + serverwritedigest.getdigestsize();

        byte[] key_block = tlsutils.calculatekeyblock(context, key_block_size);

        int offset = 0;

        // init macs
        tlsmac clientwritemac = new tlsmac(context, clientwritedigest, key_block, offset,
            clientwritedigest.getdigestsize());
        offset += clientwritedigest.getdigestsize();
        tlsmac serverwritemac = new tlsmac(context, serverwritedigest, key_block, offset,
            serverwritedigest.getdigestsize());
        offset += serverwritedigest.getdigestsize();

        // build keys
        keyparameter clientwritekey = new keyparameter(key_block, offset, cipherkeysize);
        offset += cipherkeysize;
        keyparameter serverwritekey = new keyparameter(key_block, offset, cipherkeysize);
        offset += cipherkeysize;

        if (offset != key_block_size)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        cipherparameters encryptparams, decryptparams;
        if (isserver)
        {
            this.writemac = serverwritemac;
            this.readmac = clientwritemac;
            this.encryptcipher = serverwritecipher;
            this.decryptcipher = clientwritecipher;
            encryptparams = serverwritekey;
            decryptparams = clientwritekey;
        }
        else
        {
            this.writemac = clientwritemac;
            this.readmac = serverwritemac;
            this.encryptcipher = clientwritecipher;
            this.decryptcipher = serverwritecipher;
            encryptparams = clientwritekey;
            decryptparams = serverwritekey;
        }

        this.encryptcipher.init(true, encryptparams);
        this.decryptcipher.init(false, decryptparams);
    }

    public int getplaintextlimit(int ciphertextlimit)
    {
        return ciphertextlimit - writemac.getsize();
    }

    public byte[] encodeplaintext(long seqno, short type, byte[] plaintext, int offset, int len)
    {
        byte[] mac = writemac.calculatemac(seqno, type, plaintext, offset, len);

        byte[] outbuf = new byte[len + mac.length];

        encryptcipher.processbytes(plaintext, offset, len, outbuf, 0);
        encryptcipher.processbytes(mac, 0, mac.length, outbuf, len);

        return outbuf;
    }

    public byte[] decodeciphertext(long seqno, short type, byte[] ciphertext, int offset, int len)
        throws ioexception
    {
        int macsize = readmac.getsize();
        if (len < macsize)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        byte[] deciphered = new byte[len];
        decryptcipher.processbytes(ciphertext, offset, len, deciphered, 0);

        int macinputlen = len - macsize;

        byte[] receivedmac = arrays.copyofrange(deciphered, macinputlen, len);
        byte[] computedmac = readmac.calculatemac(seqno, type, deciphered, 0, macinputlen);

        if (!arrays.constanttimeareequal(receivedmac, computedmac))
        {
            throw new tlsfatalalert(alertdescription.bad_record_mac);
        }

        return arrays.copyofrange(deciphered, 0, macinputlen);
    }
}
