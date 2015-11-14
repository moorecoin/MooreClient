package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

import org.ripple.bouncycastle.crypto.modes.aeadblockcipher;
import org.ripple.bouncycastle.crypto.params.aeadparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.util.arrays;

public class tlsaeadcipher
    implements tlscipher
{

    protected tlscontext context;
    protected int macsize;
    protected int nonce_explicit_length;

    protected aeadblockcipher encryptcipher;
    protected aeadblockcipher decryptcipher;

    protected byte[] encryptimplicitnonce, decryptimplicitnonce;

    public tlsaeadcipher(tlscontext context, aeadblockcipher clientwritecipher, aeadblockcipher serverwritecipher,
                         int cipherkeysize, int macsize)
        throws ioexception
    {

        if (!protocolversion.tlsv12.isequalorearlierversionof(context.getserverversion().getequivalenttlsversion()))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        this.context = context;
        this.macsize = macsize;

        // note: valid for rfc 5288 ciphers but may need review for other aead ciphers
        this.nonce_explicit_length = 8;

        // todo securityparameters.fixed_iv_length
        int fixed_iv_length = 4;

        int key_block_size = (2 * cipherkeysize) + (2 * fixed_iv_length);

        byte[] key_block = tlsutils.calculatekeyblock(context, key_block_size);

        int offset = 0;

        keyparameter client_write_key = new keyparameter(key_block, offset, cipherkeysize);
        offset += cipherkeysize;
        keyparameter server_write_key = new keyparameter(key_block, offset, cipherkeysize);
        offset += cipherkeysize;
        byte[] client_write_iv = arrays.copyofrange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;
        byte[] server_write_iv = arrays.copyofrange(key_block, offset, offset + fixed_iv_length);
        offset += fixed_iv_length;

        if (offset != key_block_size)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        keyparameter encryptkey, decryptkey;
        if (context.isserver())
        {
            this.encryptcipher = serverwritecipher;
            this.decryptcipher = clientwritecipher;
            this.encryptimplicitnonce = server_write_iv;
            this.decryptimplicitnonce = client_write_iv;
            encryptkey = server_write_key;
            decryptkey = client_write_key;
        }
        else
        {
            this.encryptcipher = clientwritecipher;
            this.decryptcipher = serverwritecipher;
            this.encryptimplicitnonce = client_write_iv;
            this.decryptimplicitnonce = server_write_iv;
            encryptkey = client_write_key;
            decryptkey = server_write_key;
        }

        byte[] dummynonce = new byte[fixed_iv_length + nonce_explicit_length];

        this.encryptcipher.init(true, new aeadparameters(encryptkey, 8 * macsize, dummynonce));
        this.decryptcipher.init(false, new aeadparameters(decryptkey, 8 * macsize, dummynonce));
    }

    public int getplaintextlimit(int ciphertextlimit)
    {
        // todo we ought to be able to ask the decryptcipher (independently of it's current state!)
        return ciphertextlimit - macsize - nonce_explicit_length;
    }

    public byte[] encodeplaintext(long seqno, short type, byte[] plaintext, int offset, int len)
        throws ioexception
    {

        byte[] nonce = new byte[this.encryptimplicitnonce.length + nonce_explicit_length];
        system.arraycopy(encryptimplicitnonce, 0, nonce, 0, encryptimplicitnonce.length);

        /*
         * rfc 5288 the nonce_explicit may be the 64-bit sequence number.
         * 
         * (may need review for other aead ciphers).
         */
        tlsutils.writeuint64(seqno, nonce, encryptimplicitnonce.length);

        int plaintextoffset = offset;
        int plaintextlength = len;
        int ciphertextlength = encryptcipher.getoutputsize(plaintextlength);

        byte[] output = new byte[nonce_explicit_length + ciphertextlength];
        system.arraycopy(nonce, encryptimplicitnonce.length, output, 0, nonce_explicit_length);
        int outputpos = nonce_explicit_length;

        encryptcipher.init(true,
            new aeadparameters(null, 8 * macsize, nonce, getadditionaldata(seqno, type, plaintextlength)));

        outputpos += encryptcipher.processbytes(plaintext, plaintextoffset, plaintextlength, output, outputpos);
        try
        {
            outputpos += encryptcipher.dofinal(output, outputpos);
        }
        catch (exception e)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        if (outputpos != output.length)
        {
            // note: existing aead cipher implementations all give exact output lengths
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        return output;
    }

    public byte[] decodeciphertext(long seqno, short type, byte[] ciphertext, int offset, int len)
        throws ioexception
    {

        if (getplaintextlimit(len) < 0)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        byte[] nonce = new byte[this.decryptimplicitnonce.length + nonce_explicit_length];
        system.arraycopy(decryptimplicitnonce, 0, nonce, 0, decryptimplicitnonce.length);
        system.arraycopy(ciphertext, offset, nonce, decryptimplicitnonce.length, nonce_explicit_length);

        int ciphertextoffset = offset + nonce_explicit_length;
        int ciphertextlength = len - nonce_explicit_length;
        int plaintextlength = decryptcipher.getoutputsize(ciphertextlength);

        byte[] output = new byte[plaintextlength];
        int outputpos = 0;

        decryptcipher.init(false,
            new aeadparameters(null, 8 * macsize, nonce, getadditionaldata(seqno, type, plaintextlength)));

        outputpos += decryptcipher.processbytes(ciphertext, ciphertextoffset, ciphertextlength, output, outputpos);

        try
        {
            outputpos += decryptcipher.dofinal(output, outputpos);
        }
        catch (exception e)
        {
            throw new tlsfatalalert(alertdescription.bad_record_mac);
        }

        if (outputpos != output.length)
        {
            // note: existing aead cipher implementations all give exact output lengths
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        return output;
    }

    protected byte[] getadditionaldata(long seqno, short type, int len)
        throws ioexception
    {
        /*
         * additional_data = seq_num + tlscompressed.type + tlscompressed.version +
         * tlscompressed.length
         */

        byte[] additional_data = new byte[13];
        tlsutils.writeuint64(seqno, additional_data, 0);
        tlsutils.writeuint8(type, additional_data, 8);
        tlsutils.writeversion(context.getserverversion(), additional_data, 9);
        tlsutils.writeuint16(len, additional_data, 11);

        return additional_data;
    }
}
