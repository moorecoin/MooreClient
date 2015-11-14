package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

import org.ripple.bouncycastle.crypto.digest;

/**
 * an implementation of the tls 1.0/1.1/1.2 record layer, allowing downgrade to sslv3.
 */
class recordstream
{

    private static int plaintext_limit = (1 << 14);
    private static int compressed_limit = plaintext_limit + 1024;
    private static int ciphertext_limit = compressed_limit + 1024;

    private tlsprotocol handler;
    private inputstream input;
    private outputstream output;
    private tlscompression pendingcompression = null, readcompression = null, writecompression = null;
    private tlscipher pendingcipher = null, readcipher = null, writecipher = null;
    private long readseqno = 0, writeseqno = 0;
    private bytearrayoutputstream buffer = new bytearrayoutputstream();

    private tlscontext context = null;
    private tlshandshakehash hash = null;

    private protocolversion readversion = null, writeversion = null;
    private boolean restrictreadversion = true;

    recordstream(tlsprotocol handler, inputstream input, outputstream output)
    {
        this.handler = handler;
        this.input = input;
        this.output = output;
        this.readcompression = new tlsnullcompression();
        this.writecompression = this.readcompression;
        this.readcipher = new tlsnullcipher(context);
        this.writecipher = this.readcipher;
    }

    void init(tlscontext context)
    {
        this.context = context;
        this.hash = new deferredhash();
        this.hash.init(context);
    }

    protocolversion getreadversion()
    {
        return readversion;
    }

    void setreadversion(protocolversion readversion)
    {
        this.readversion = readversion;
    }

    void setwriteversion(protocolversion writeversion)
    {
        this.writeversion = writeversion;
    }

    /**
     * rfc 5246 e.1. "earlier versions of the tls specification were not fully clear on what the
     * record layer version number (tlsplaintext.version) should contain when sending clienthello
     * (i.e., before it is known which version of the protocol will be employed). thus, tls servers
     * compliant with this specification must accept any value {03,xx} as the record layer version
     * number for clienthello."
     */
    void setrestrictreadversion(boolean enabled)
    {
        this.restrictreadversion = enabled;
    }

    void notifyhellocomplete()
    {
        this.hash = this.hash.commit();
    }

    void setpendingconnectionstate(tlscompression tlscompression, tlscipher tlscipher)
    {
        this.pendingcompression = tlscompression;
        this.pendingcipher = tlscipher;
    }

    void sentwritecipherspec()
        throws ioexception
    {
        if (pendingcompression == null || pendingcipher == null)
        {
            throw new tlsfatalalert(alertdescription.handshake_failure);
        }
        this.writecompression = this.pendingcompression;
        this.writecipher = this.pendingcipher;
        this.writeseqno = 0;
    }

    void receivedreadcipherspec()
        throws ioexception
    {
        if (pendingcompression == null || pendingcipher == null)
        {
            throw new tlsfatalalert(alertdescription.handshake_failure);
        }
        this.readcompression = this.pendingcompression;
        this.readcipher = this.pendingcipher;
        this.readseqno = 0;
    }

    void finalisehandshake()
        throws ioexception
    {
        if (readcompression != pendingcompression || writecompression != pendingcompression
            || readcipher != pendingcipher || writecipher != pendingcipher)
        {
            throw new tlsfatalalert(alertdescription.handshake_failure);
        }
        pendingcompression = null;
        pendingcipher = null;
    }

    public void readrecord()
        throws ioexception
    {

        short type = tlsutils.readuint8(input);

        // todo in earlier rfcs, it was "should ignore"; should this be version-dependent?
        /*
         * rfc 5246 6. if a tls implementation receives an unexpected record type, it must send an
         * unexpected_message alert.
         */
        checktype(type, alertdescription.unexpected_message);

        if (!restrictreadversion)
        {
            int version = tlsutils.readversionraw(input);
            if ((version & 0xffffff00) != 0x0300)
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
        else
        {
            protocolversion version = tlsutils.readversion(input);
            if (readversion == null)
            {
                readversion = version;
            }
            else if (!version.equals(readversion))
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }

        int length = tlsutils.readuint16(input);
        byte[] plaintext = decodeandverify(type, input, length);
        handler.processrecord(type, plaintext, 0, plaintext.length);
    }

    protected byte[] decodeandverify(short type, inputstream input, int len)
        throws ioexception
    {

        checklength(len, ciphertext_limit, alertdescription.record_overflow);

        byte[] buf = tlsutils.readfully(len, input);
        byte[] decoded = readcipher.decodeciphertext(readseqno++, type, buf, 0, buf.length);

        checklength(decoded.length, compressed_limit, alertdescription.record_overflow);

        /*
         * todo rfc5264 6.2.2. implementation note: decompression functions are responsible for
         * ensuring that messages cannot cause internal buffer overflows.
         */
        outputstream cout = readcompression.decompress(buffer);
        if (cout != buffer)
        {
            cout.write(decoded, 0, decoded.length);
            cout.flush();
            decoded = getbuffercontents();
        }

        /*
         * rfc 5264 6.2.2. if the decompression function encounters a tlscompressed.fragment that
         * would decompress to a length in excess of 2^14 bytes, it should report a fatal
         * decompression failure error.
         */
        checklength(decoded.length, plaintext_limit, alertdescription.decompression_failure);

        return decoded;
    }

    protected void writerecord(short type, byte[] plaintext, int plaintextoffset, int plaintextlength)
        throws ioexception
    {

        /*
         * rfc 5264 6. implementations must not send record types not defined in this document
         * unless negotiated by some extension.
         */
        checktype(type, alertdescription.internal_error);

        /*
         * rfc 5264 6.2.1 the length should not exceed 2^14.
         */
        checklength(plaintextlength, plaintext_limit, alertdescription.internal_error);

        /*
         * rfc 5264 6.2.1 implementations must not send zero-length fragments of handshake, alert,
         * or changecipherspec content types.
         */
        if (plaintextlength < 1 && type != contenttype.application_data)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        if (type == contenttype.handshake)
        {
            updatehandshakedata(plaintext, plaintextoffset, plaintextlength);
        }

        outputstream cout = writecompression.compress(buffer);

        byte[] ciphertext;
        if (cout == buffer)
        {
            ciphertext = writecipher.encodeplaintext(writeseqno++, type, plaintext, plaintextoffset, plaintextlength);
        }
        else
        {
            cout.write(plaintext, plaintextoffset, plaintextlength);
            cout.flush();
            byte[] compressed = getbuffercontents();

            /*
             * rfc5264 6.2.2. compression must be lossless and may not increase the content length
             * by more than 1024 bytes.
             */
            checklength(compressed.length, plaintextlength + 1024, alertdescription.internal_error);

            ciphertext = writecipher.encodeplaintext(writeseqno++, type, compressed, 0, compressed.length);
        }

        /*
         * rfc 5264 6.2.3. the length may not exceed 2^14 + 2048.
         */
        checklength(ciphertext.length, ciphertext_limit, alertdescription.internal_error);

        byte[] record = new byte[ciphertext.length + 5];
        tlsutils.writeuint8(type, record, 0);
        tlsutils.writeversion(writeversion, record, 1);
        tlsutils.writeuint16(ciphertext.length, record, 3);
        system.arraycopy(ciphertext, 0, record, 5, ciphertext.length);
        output.write(record);
        output.flush();
    }

    void updatehandshakedata(byte[] message, int offset, int len)
    {
        hash.update(message, offset, len);
    }

    /**
     * 'sender' only relevant to sslv3
     */
    byte[] getcurrenthash(byte[] sender)
    {
        tlshandshakehash d = hash.fork();

        if (context.getserverversion().isssl())
        {
            if (sender != null)
            {
                d.update(sender, 0, sender.length);
            }
        }

        return dofinal(d);
    }

    protected void close()
        throws ioexception
    {
        ioexception e = null;
        try
        {
            input.close();
        }
        catch (ioexception ex)
        {
            e = ex;
        }
        try
        {
            output.close();
        }
        catch (ioexception ex)
        {
            e = ex;
        }
        if (e != null)
        {
            throw e;
        }
    }

    protected void flush()
        throws ioexception
    {
        output.flush();
    }

    private byte[] getbuffercontents()
    {
        byte[] contents = buffer.tobytearray();
        buffer.reset();
        return contents;
    }

    private static byte[] dofinal(digest d)
    {
        byte[] bs = new byte[d.getdigestsize()];
        d.dofinal(bs, 0);
        return bs;
    }

    private static void checktype(short type, short alertdescription)
        throws ioexception
    {

        switch (type)
        {
        case contenttype.change_cipher_spec:
        case contenttype.alert:
        case contenttype.handshake:
        case contenttype.application_data:
            break;
        default:
            throw new tlsfatalalert(alertdescription);
        }
    }

    private static void checklength(int length, int limit, short alertdescription)
        throws ioexception
    {
        if (length > limit)
        {
            throw new tlsfatalalert(alertdescription);
        }
    }
}
