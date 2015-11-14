package org.ripple.bouncycastle.crypto.signers;

import java.io.ioexception;
import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;

public class dsadigestsigner
    implements signer
{
    private final digest digest;
    private final dsa dsasigner;
    private boolean forsigning;

    public dsadigestsigner(
        dsa    signer,
        digest digest)
    {
        this.digest = digest;
        this.dsasigner = signer;
    }

    public void init(
        boolean           forsigning,
        cipherparameters   parameters)
    {
        this.forsigning = forsigning;

        asymmetrickeyparameter k;

        if (parameters instanceof parameterswithrandom)
        {
            k = (asymmetrickeyparameter)((parameterswithrandom)parameters).getparameters();
        }
        else
        {
            k = (asymmetrickeyparameter)parameters;
        }

        if (forsigning && !k.isprivate())
        {
            throw new illegalargumentexception("signing requires private key.");
        }

        if (!forsigning && k.isprivate())
        {
            throw new illegalargumentexception("verification requires public key.");
        }

        reset();

        dsasigner.init(forsigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  input,
        int     inoff,
        int     length)
    {
        digest.update(input, inoff, length);
    }

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generatesignature()
    {
        if (!forsigning)
        {
            throw new illegalstateexception("dsadigestsigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);

        biginteger[] sig = dsasigner.generatesignature(hash);

        try
        {
            return derencode(sig[0], sig[1]);
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unable to encode signature");
        }
    }

    public boolean verifysignature(
        byte[] signature)
    {
        if (forsigning)
        {
            throw new illegalstateexception("dsadigestsigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);

        try
        {
            biginteger[] sig = derdecode(signature);
            return dsasigner.verifysignature(hash, sig[0], sig[1]);
        }
        catch (ioexception e)
        {
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }

    private byte[] derencode(
        biginteger  r,
        biginteger  s)
        throws ioexception
    {
        asn1encodablevector v = new asn1encodablevector();
        v.add(new derinteger(r));
        v.add(new derinteger(s));

        return new dersequence(v).getencoded(asn1encoding.der);
    }

    private biginteger[] derdecode(
        byte[] encoding)
        throws ioexception
    {
        asn1sequence s = (asn1sequence)asn1primitive.frombytearray(encoding);

        return new biginteger[]
        {
            ((derinteger)s.getobjectat(0)).getvalue(),
            ((derinteger)s.getobjectat(1)).getvalue()
        };
    }
}
