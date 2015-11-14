package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.util.arrays;

/**
 * a null ciphersuite with optional mac
 */
public class tlsnullcipher
    implements tlscipher
{
    protected tlscontext context;

    protected tlsmac writemac;
    protected tlsmac readmac;

    public tlsnullcipher(tlscontext context)
    {
        this.context = context;
        this.writemac = null;
        this.readmac = null;
    }

    public tlsnullcipher(tlscontext context, digest clientwritedigest, digest serverwritedigest)
        throws ioexception
    {

        if ((clientwritedigest == null) != (serverwritedigest == null))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        this.context = context;

        tlsmac clientwritemac = null, serverwritemac = null;

        if (clientwritedigest != null)
        {

            int key_block_size = clientwritedigest.getdigestsize()
                + serverwritedigest.getdigestsize();
            byte[] key_block = tlsutils.calculatekeyblock(context, key_block_size);

            int offset = 0;

            clientwritemac = new tlsmac(context, clientwritedigest, key_block, offset,
                clientwritedigest.getdigestsize());
            offset += clientwritedigest.getdigestsize();

            serverwritemac = new tlsmac(context, serverwritedigest, key_block, offset,
                serverwritedigest.getdigestsize());
            offset += serverwritedigest.getdigestsize();

            if (offset != key_block_size)
            {
                throw new tlsfatalalert(alertdescription.internal_error);
            }
        }

        if (context.isserver())
        {
            writemac = serverwritemac;
            readmac = clientwritemac;
        }
        else
        {
            writemac = clientwritemac;
            readmac = serverwritemac;
        }
    }

    public int getplaintextlimit(int ciphertextlimit)
    {
        int result = ciphertextlimit;
        if (writemac != null)
        {
            result -= writemac.getsize();
        }
        return result;
    }

    public byte[] encodeplaintext(long seqno, short type, byte[] plaintext, int offset, int len)
        throws ioexception
    {

        if (writemac == null)
        {
            return arrays.copyofrange(plaintext, offset, offset + len);
        }

        byte[] mac = writemac.calculatemac(seqno, type, plaintext, offset, len);
        byte[] ciphertext = new byte[len + mac.length];
        system.arraycopy(plaintext, offset, ciphertext, 0, len);
        system.arraycopy(mac, 0, ciphertext, len, mac.length);
        return ciphertext;
    }

    public byte[] decodeciphertext(long seqno, short type, byte[] ciphertext, int offset, int len)
        throws ioexception
    {

        if (readmac == null)
        {
            return arrays.copyofrange(ciphertext, offset, offset + len);
        }

        int macsize = readmac.getsize();
        if (len < macsize)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        int macinputlen = len - macsize;

        byte[] receivedmac = arrays.copyofrange(ciphertext, offset + macinputlen, offset + len);
        byte[] computedmac = readmac.calculatemac(seqno, type, ciphertext, offset, macinputlen);

        if (!arrays.constanttimeareequal(receivedmac, computedmac))
        {
            throw new tlsfatalalert(alertdescription.bad_record_mac);
        }

        return arrays.copyofrange(ciphertext, offset, offset + macinputlen);
    }
}
