package org.moorecoinlab.crypto.ecdsa;

import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.dersequencegenerator;
import org.ripple.bouncycastle.asn1.dlsequence;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.math.biginteger;

public class ecdsasignature {
    /** the two components of the signature. */
    public biginteger r, s;

    /** constructs a signature with the given components. */
    public ecdsasignature(biginteger r, biginteger s) {
        this.r = r;
        this.s = s;
    }

    /**
     * der is an international standard for serializing data structures which is widely used in cryptography.
     * it's somewhat like protocol buffers but less convenient. this method returns a standard der encoding
     * of the signature, as recognized by openssl and other libraries.
     */
    public byte[] encodetoder() {
        try {
            return derbytestream().tobytearray();
        } catch (ioexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    public static ecdsasignature decodefromder(byte[] bytes) {
        try {
            asn1inputstream decoder = new asn1inputstream(bytes);
            dlsequence seq = (dlsequence) decoder.readobject();
            derinteger r, s;
            try {
                r = (derinteger) seq.getobjectat(0);
                s = (derinteger) seq.getobjectat(1);
            } catch (classcastexception e) {
                return null;
            }
            decoder.close();
            // openssl deviates from the der spec by interpreting these values as unsigned, though they should not be
            // thus, we always use the positive versions. see: http://r6.ca/blog/20111119t211504z.html
            return new ecdsasignature(r.getpositivevalue(), s.getpositivevalue());
        } catch (ioexception e) {
            throw new runtimeexception(e);
        }
    }

    protected bytearrayoutputstream derbytestream() throws ioexception {
        // usually 70-72 bytes.
        bytearrayoutputstream bos = new bytearrayoutputstream(72);
        dersequencegenerator seq = new dersequencegenerator(bos);
        seq.addobject(new derinteger(r));
        seq.addobject(new derinteger(s));
        seq.close();
        return bos;
    }
}
