package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.util.arrays;

/**
 * a generic tls 1.0-1.1 / sslv3 block cipher. this can be used for aes or 3des for example.
 */
public class tlsblockcipher
    implements tlscipher
{

    protected tlscontext context;
    protected byte[] randomdata;
    protected boolean useexplicitiv;

    protected blockcipher encryptcipher;
    protected blockcipher decryptcipher;

    protected tlsmac writemac;
    protected tlsmac readmac;

    public tlsmac getwritemac()
    {
        return writemac;
    }

    public tlsmac getreadmac()
    {
        return readmac;
    }

    public tlsblockcipher(tlscontext context, blockcipher clientwritecipher, blockcipher serverwritecipher,
                          digest clientwritedigest, digest serverwritedigest, int cipherkeysize)
        throws ioexception
    {

        this.context = context;

        this.randomdata = new byte[256];
        context.getsecurerandom().nextbytes(randomdata);

        this.useexplicitiv = protocolversion.tlsv11.isequalorearlierversionof(context.getserverversion()
            .getequivalenttlsversion());

        int key_block_size = (2 * cipherkeysize) + clientwritedigest.getdigestsize()
            + serverwritedigest.getdigestsize();

        // from tls 1.1 onwards, block ciphers don't need client_write_iv
        if (!useexplicitiv)
        {
            key_block_size += clientwritecipher.getblocksize() + serverwritecipher.getblocksize();
        }

        byte[] key_block = tlsutils.calculatekeyblock(context, key_block_size);

        int offset = 0;

        tlsmac clientwritemac = new tlsmac(context, clientwritedigest, key_block, offset,
            clientwritedigest.getdigestsize());
        offset += clientwritedigest.getdigestsize();
        tlsmac serverwritemac = new tlsmac(context, serverwritedigest, key_block, offset,
            serverwritedigest.getdigestsize());
        offset += serverwritedigest.getdigestsize();

        keyparameter client_write_key = new keyparameter(key_block, offset, cipherkeysize);
        offset += cipherkeysize;
        keyparameter server_write_key = new keyparameter(key_block, offset, cipherkeysize);
        offset += cipherkeysize;

        byte[] client_write_iv, server_write_iv;
        if (useexplicitiv)
        {
            client_write_iv = new byte[clientwritecipher.getblocksize()];
            server_write_iv = new byte[serverwritecipher.getblocksize()];
        }
        else
        {
            client_write_iv = arrays.copyofrange(key_block, offset, offset + clientwritecipher.getblocksize());
            offset += clientwritecipher.getblocksize();
            server_write_iv = arrays.copyofrange(key_block, offset, offset + serverwritecipher.getblocksize());
            offset += serverwritecipher.getblocksize();
        }

        if (offset != key_block_size)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        cipherparameters encryptparams, decryptparams;
        if (context.isserver())
        {
            this.writemac = serverwritemac;
            this.readmac = clientwritemac;
            this.encryptcipher = serverwritecipher;
            this.decryptcipher = clientwritecipher;
            encryptparams = new parameterswithiv(server_write_key, server_write_iv);
            decryptparams = new parameterswithiv(client_write_key, client_write_iv);
        }
        else
        {
            this.writemac = clientwritemac;
            this.readmac = serverwritemac;
            this.encryptcipher = clientwritecipher;
            this.decryptcipher = serverwritecipher;
            encryptparams = new parameterswithiv(client_write_key, client_write_iv);
            decryptparams = new parameterswithiv(server_write_key, server_write_iv);
        }

        this.encryptcipher.init(true, encryptparams);
        this.decryptcipher.init(false, decryptparams);
    }

    public int getplaintextlimit(int ciphertextlimit)
    {
        int blocksize = encryptcipher.getblocksize();
        int macsize = writemac.getsize();

        int result = ciphertextlimit - (ciphertextlimit % blocksize) - macsize - 1;
        if (useexplicitiv)
        {
            result -= blocksize;
        }

        return result;
    }

    public byte[] encodeplaintext(long seqno, short type, byte[] plaintext, int offset, int len)
    {
        int blocksize = encryptcipher.getblocksize();
        int macsize = writemac.getsize();

        protocolversion version = context.getserverversion();

        int padding_length = blocksize - 1 - ((len + macsize) % blocksize);

        // todo[dtls] consider supporting in dtls (without exceeding send limit though)
        if (!version.isdtls() && !version.isssl())
        {
            // add a random number of extra blocks worth of padding
            int maxextrapadblocks = (255 - padding_length) / blocksize;
            int actualextrapadblocks = chooseextrapadblocks(context.getsecurerandom(), maxextrapadblocks);
            padding_length += actualextrapadblocks * blocksize;
        }

        int totalsize = len + macsize + padding_length + 1;
        if (useexplicitiv)
        {
            totalsize += blocksize;
        }

        byte[] outbuf = new byte[totalsize];
        int outoff = 0;

        if (useexplicitiv)
        {
            byte[] explicitiv = new byte[blocksize];
            context.getsecurerandom().nextbytes(explicitiv);

            encryptcipher.init(true, new parameterswithiv(null, explicitiv));

            system.arraycopy(explicitiv, 0, outbuf, outoff, blocksize);
            outoff += blocksize;
        }

        byte[] mac = writemac.calculatemac(seqno, type, plaintext, offset, len);

        system.arraycopy(plaintext, offset, outbuf, outoff, len);
        system.arraycopy(mac, 0, outbuf, outoff + len, mac.length);

        int padoffset = outoff + len + mac.length;
        for (int i = 0; i <= padding_length; i++)
        {
            outbuf[i + padoffset] = (byte)padding_length;
        }
        for (int i = outoff; i < totalsize; i += blocksize)
        {
            encryptcipher.processblock(outbuf, i, outbuf, i);
        }
        return outbuf;
    }

    public byte[] decodeciphertext(long seqno, short type, byte[] ciphertext, int offset, int len)
        throws ioexception
    {
        int blocksize = decryptcipher.getblocksize();
        int macsize = readmac.getsize();

        int minlen = math.max(blocksize, macsize + 1);
        if (useexplicitiv)
        {
            minlen += blocksize;
        }

        if (len < minlen)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        if (len % blocksize != 0)
        {
            throw new tlsfatalalert(alertdescription.decryption_failed);
        }

        if (useexplicitiv)
        {
            decryptcipher.init(false, new parameterswithiv(null, ciphertext, offset, blocksize));

            offset += blocksize;
            len -= blocksize;
        }

        for (int i = 0; i < len; i += blocksize)
        {
            decryptcipher.processblock(ciphertext, offset + i, ciphertext, offset + i);
        }

        // if there's anything wrong with the padding, this will return zero
        int totalpad = checkpaddingconstanttime(ciphertext, offset, len, blocksize, macsize);

        int macinputlen = len - totalpad - macsize;

        byte[] decryptedmac = arrays.copyofrange(ciphertext, offset + macinputlen, offset + macinputlen + macsize);
        byte[] calculatedmac = readmac.calculatemacconstanttime(seqno, type, ciphertext, offset, macinputlen, len
            - macsize, randomdata);

        boolean badmac = !arrays.constanttimeareequal(calculatedmac, decryptedmac);

        if (badmac || totalpad == 0)
        {
            throw new tlsfatalalert(alertdescription.bad_record_mac);
        }

        return arrays.copyofrange(ciphertext, offset, offset + macinputlen);
    }

    protected int checkpaddingconstanttime(byte[] buf, int off, int len, int blocksize, int macsize)
    {
        int end = off + len;
        byte lastbyte = buf[end - 1];
        int padlen = lastbyte & 0xff;
        int totalpad = padlen + 1;

        int dummyindex = 0;
        byte paddiff = 0;

        if ((context.getserverversion().isssl() && totalpad > blocksize) || (macsize + totalpad > len))
        {
            totalpad = 0;
        }
        else
        {
            int padpos = end - totalpad;
            do
            {
                paddiff |= (buf[padpos++] ^ lastbyte);
            }
            while (padpos < end);

            dummyindex = totalpad;

            if (paddiff != 0)
            {
                totalpad = 0;
            }
        }

        // run some extra dummy checks so the number of checks is always constant
        {
            byte[] dummypad = randomdata;
            while (dummyindex < 256)
            {
                paddiff |= (dummypad[dummyindex++] ^ lastbyte);
            }
            // ensure the above loop is not eliminated
            dummypad[0] ^= paddiff;
        }

        return totalpad;
    }

    protected int chooseextrapadblocks(securerandom r, int max)
    {
        // return r.nextint(max + 1);

        int x = r.nextint();
        int n = lowestbitset(x);
        return math.min(n, max);
    }

    protected int lowestbitset(int x)
    {
        if (x == 0)
        {
            return 32;
        }

        int n = 0;
        while ((x & 1) == 0)
        {
            ++n;
            x >>= 1;
        }
        return n;
    }
}