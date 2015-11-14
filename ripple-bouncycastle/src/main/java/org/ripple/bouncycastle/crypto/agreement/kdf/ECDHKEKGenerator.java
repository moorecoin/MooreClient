package org.ripple.bouncycastle.crypto.agreement.kdf;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.derivationfunction;
import org.ripple.bouncycastle.crypto.derivationparameters;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.generators.kdf2bytesgenerator;
import org.ripple.bouncycastle.crypto.params.kdfparameters;
import org.ripple.bouncycastle.crypto.util.pack;

/**
 * x9.63 based key derivation function for ecdh cms.
 */
public class ecdhkekgenerator
    implements derivationfunction
{
    private derivationfunction kdf;

    private asn1objectidentifier algorithm;
    private int                 keysize;
    private byte[]              z;

    public ecdhkekgenerator(
        digest digest)
    {
        this.kdf = new kdf2bytesgenerator(digest);
    }

    public void init(derivationparameters param)
    {
        dhkdfparameters params = (dhkdfparameters)param;

        this.algorithm = params.getalgorithm();
        this.keysize = params.getkeysize();
        this.z = params.getz();
    }

    public digest getdigest()
    {
        return kdf.getdigest();
    }

    public int generatebytes(byte[] out, int outoff, int len)
        throws datalengthexception, illegalargumentexception
    {
        // todo create an asn.1 class for this (rfc3278)
        // ecc-cms-sharedinfo
        asn1encodablevector v = new asn1encodablevector();

        v.add(new algorithmidentifier(algorithm, dernull.instance));
        v.add(new dertaggedobject(true, 2, new deroctetstring(pack.inttobigendian(keysize))));

        try
        {
            kdf.init(new kdfparameters(z, new dersequence(v).getencoded(asn1encoding.der)));
        }
        catch (ioexception e)
        {
            throw new illegalargumentexception("unable to initialise kdf: " + e.getmessage());
        }

        return kdf.generatebytes(out, outoff, len);
    }
}
