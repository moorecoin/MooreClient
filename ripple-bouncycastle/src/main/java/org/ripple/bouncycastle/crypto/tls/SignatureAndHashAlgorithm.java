package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

/**
 * rfc 5246 7.4.1.4.1
 */
public class signatureandhashalgorithm
{

    private short hash;
    private short signature;

    /**
     * @param hash      {@link hashalgorithm}
     * @param signature {@link signaturealgorithm}
     */
    public signatureandhashalgorithm(short hash, short signature)
    {

        if (!tlsutils.isvaliduint8(hash))
        {
            throw new illegalargumentexception("'hash' should be a uint8");
        }
        if (!tlsutils.isvaliduint8(signature))
        {
            throw new illegalargumentexception("'signature' should be a uint8");
        }
        if (signature == signaturealgorithm.anonymous)
        {
            throw new illegalargumentexception("'signature' must not be \"anonymous\"");
        }

        this.hash = hash;
        this.signature = signature;
    }

    /**
     * @return {@link hashalgorithm}
     */
    public short gethash()
    {
        return hash;
    }

    /**
     * @return {@link signaturealgorithm}
     */
    public short getsignature()
    {
        return signature;
    }

    public boolean equals(object obj)
    {
        if (!(obj instanceof signatureandhashalgorithm))
        {
            return false;
        }
        signatureandhashalgorithm other = (signatureandhashalgorithm)obj;
        return other.gethash() == gethash() && other.getsignature() == getsignature();
    }

    public int hashcode()
    {
        return (gethash() << 8) | getsignature();
    }

    /**
     * encode this {@link signatureandhashalgorithm} to an {@link outputstream}.
     *
     * @param output the {@link outputstream} to encode to.
     * @throws ioexception
     */
    public void encode(outputstream output)
        throws ioexception
    {
        tlsutils.writeuint8(hash, output);
        tlsutils.writeuint8(signature, output);
    }

    /**
     * parse a {@link signatureandhashalgorithm} from an {@link inputstream}.
     *
     * @param input the {@link inputstream} to parse from.
     * @return a {@link signatureandhashalgorithm} object.
     * @throws ioexception
     */
    public static signatureandhashalgorithm parse(inputstream input)
        throws ioexception
    {
        short hash = tlsutils.readuint8(input);
        short signature = tlsutils.readuint8(input);
        return new signatureandhashalgorithm(hash, signature);
    }
}
