package org.ripple.bouncycastle.crypto.signers;

import java.io.ioexception;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.teletrust.teletrustobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.digestinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.datalengthexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.util.arrays;

public class rsadigestsigner
    implements signer
{
    private final asymmetricblockcipher rsaengine = new pkcs1encoding(new rsablindedengine());
    private final algorithmidentifier algid;
    private final digest digest;
    private boolean forsigning;

    private static final hashtable oidmap = new hashtable();

    /*
     * load oid table.
     */
    static
    {
        oidmap.put("ripemd128", teletrustobjectidentifiers.ripemd128);
        oidmap.put("ripemd160", teletrustobjectidentifiers.ripemd160);
        oidmap.put("ripemd256", teletrustobjectidentifiers.ripemd256);

        oidmap.put("sha-1", x509objectidentifiers.id_sha1);
        oidmap.put("sha-224", nistobjectidentifiers.id_sha224);
        oidmap.put("sha-256", nistobjectidentifiers.id_sha256);
        oidmap.put("sha-384", nistobjectidentifiers.id_sha384);
        oidmap.put("sha-512", nistobjectidentifiers.id_sha512);

        oidmap.put("md2", pkcsobjectidentifiers.md2);
        oidmap.put("md4", pkcsobjectidentifiers.md4);
        oidmap.put("md5", pkcsobjectidentifiers.md5);
    }

    public rsadigestsigner(
        digest digest)
    {
        this.digest = digest;

        algid = new algorithmidentifier((asn1objectidentifier)oidmap.get(digest.getalgorithmname()), dernull.instance);
    }

    /**
     * @deprecated
     */
    public string getalgorithmname()
    {
        return digest.getalgorithmname() + "withrsa";
    }

    /**
     * initialise the signer for signing or verification.
     *
     * @param forsigning
     *            true if for signing, false otherwise
     * @param parameters
     *            necessary parameters.
     */
    public void init(
        boolean          forsigning,
        cipherparameters parameters)
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
            throw new illegalargumentexception("signing requires private key");
        }

        if (!forsigning && k.isprivate())
        {
            throw new illegalargumentexception("verification requires public key");
        }

        reset();

        rsaengine.init(forsigning, parameters);
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
     * generate a signature for the message we've been loaded with using the key
     * we were initialised with.
     */
    public byte[] generatesignature()
        throws cryptoexception, datalengthexception
    {
        if (!forsigning)
        {
            throw new illegalstateexception("rsadigestsigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getdigestsize()];
        digest.dofinal(hash, 0);

        try
        {
            byte[] data = derencode(hash);
            return rsaengine.processblock(data, 0, data.length);
        }
        catch (ioexception e)
        {
            throw new cryptoexception("unable to encode signature: " + e.getmessage(), e);
        }
    }

    /**
     * return true if the internal state represents the signature described in
     * the passed in array.
     */
    public boolean verifysignature(
        byte[] signature)
    {
        if (forsigning)
        {
            throw new illegalstateexception("rsadigestsigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getdigestsize()];

        digest.dofinal(hash, 0);

        byte[] sig;
        byte[] expected;

        try
        {
            sig = rsaengine.processblock(signature, 0, signature.length);
            expected = derencode(hash);
        }
        catch (exception e)
        {
            return false;
        }

        if (sig.length == expected.length)
        {
            return arrays.constanttimeareequal(sig, expected);
        }
        else if (sig.length == expected.length - 2)  // null left out
        {
            int sigoffset = sig.length - hash.length - 2;
            int expectedoffset = expected.length - hash.length - 2;

            expected[1] -= 2;      // adjust lengths
            expected[3] -= 2;

            int nonequal = 0;

            for (int i = 0; i < hash.length; i++)
            {
                nonequal |= (sig[sigoffset + i] ^ expected[expectedoffset + i]);
            }

            for (int i = 0; i < sigoffset; i++)
            {
                nonequal |= (sig[i] ^ expected[i]);  // check header less null
            }

            return nonequal == 0;
        }
        else
        {
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }

    private byte[] derencode(
        byte[] hash)
        throws ioexception
    {
        digestinfo dinfo = new digestinfo(algid, hash);

        return dinfo.getencoded(asn1encoding.der);
    }
}
