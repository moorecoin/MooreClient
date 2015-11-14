package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.math.biginteger;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.securerandom;
import java.security.signatureexception;
import java.util.date;

import org.ripple.bouncycastle.bcpg.mpinteger;
import org.ripple.bouncycastle.bcpg.onepasssignaturepacket;
import org.ripple.bouncycastle.bcpg.publickeyalgorithmtags;
import org.ripple.bouncycastle.bcpg.signaturepacket;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsigner;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;

/**
 * generator for old style pgp v3 signatures.
 */
public class pgpv3signaturegenerator
{
    private byte            lastb;
    private outputstream    sigout;
    private pgpcontentsignerbuilder contentsignerbuilder;
    private pgpcontentsigner contentsigner;
    private int              sigtype;
    private int              providedkeyalgorithm = -1;

    /**
     * create a generator for the passed in keyalgorithm and hashalgorithm codes.
     * 
     * @param keyalgorithm
     * @param hashalgorithm
     * @param provider
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated   use constructor taking pgpcontentsignerbuilder.
     */
     public pgpv3signaturegenerator(
        int  keyalgorithm,
        int  hashalgorithm,
        string provider)
        throws nosuchalgorithmexception, nosuchproviderexception, pgpexception
    {
        this(keyalgorithm, hashalgorithm, pgputil.getprovider(provider));
    }

 /**
     *
     * @param keyalgorithm
     * @param hashalgorithm
     * @param provider
     * @throws nosuchalgorithmexception
     * @throws pgpexception
     * @deprecated use constructor taking pgpcontentsignerbuilder.
     */
    public pgpv3signaturegenerator(
        int      keyalgorithm,
        int      hashalgorithm,
        provider provider)
        throws nosuchalgorithmexception, pgpexception
    {
        this.providedkeyalgorithm = keyalgorithm;
        this.contentsignerbuilder = new jcapgpcontentsignerbuilder(keyalgorithm, hashalgorithm).setprovider(provider);
    }

    /**
     * create a signature generator built on the passed in contentsignerbuilder.
     *
     * @param contentsignerbuilder  builder to produce pgpcontentsigner objects for generating signatures.
     */
    public pgpv3signaturegenerator(
        pgpcontentsignerbuilder contentsignerbuilder)
    {
        this.contentsignerbuilder = contentsignerbuilder;
    }
    
    /**
     * initialise the generator for signing.
     * 
     * @param signaturetype
     * @param key
     * @throws pgpexception
     */
    public void init(
        int           signaturetype,
        pgpprivatekey key)
        throws pgpexception
    {
        contentsigner = contentsignerbuilder.build(signaturetype, key);
        sigout = contentsigner.getoutputstream();
        sigtype = contentsigner.gettype();
        lastb = 0;

        if (providedkeyalgorithm >= 0 && providedkeyalgorithm != contentsigner.getkeyalgorithm())
        {
            throw new pgpexception("key algorithm mismatch");
        }
    }

    /**
     * initialise the generator for signing.
     * 
     * @param signaturetype
     * @param key
     * @param random
     * @throws pgpexception
     * @deprecated random now ignored - set random in pgpcontentsignerbuilder
     */
    public void initsign(
        int           signaturetype,
        pgpprivatekey key,
        securerandom  random)
        throws pgpexception
    {
        init(signaturetype, key);
    }

    /**
     * initialise the generator for signing.
     *
     * @param signaturetype
     * @param key
     * @throws pgpexception
     * @deprecated use init()
     */
    public void initsign(
        int           signaturetype,
        pgpprivatekey key)
        throws pgpexception
    {
        init(signaturetype, key);
    }

    public void update(
        byte b) 
        throws signatureexception
    {
        if (sigtype == pgpsignature.canonical_text_document)
        {
            if (b == '\r')
            {
                byteupdate((byte)'\r');
                byteupdate((byte)'\n');
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    byteupdate((byte)'\r');
                    byteupdate((byte)'\n');
                }
            }
            else
            {
                byteupdate(b);
            }
            
            lastb = b;
        }
        else
        {
            byteupdate(b);
        }
    }
    
    public void update(
        byte[] b) 
        throws signatureexception
    {
        this.update(b, 0, b.length);
    }
    
    public void update(
        byte[]  b,
        int     off,
        int     len) 
        throws signatureexception
    {
        if (sigtype == pgpsignature.canonical_text_document)
        {
            int finish = off + len;
            
            for (int i = off; i != finish; i++)
            {
                this.update(b[i]);
            }
        }
        else
        {
            blockupdate(b, off, len);
        }
    }

    private void byteupdate(byte b)
        throws signatureexception
    {
        try
        {
            sigout.write(b);
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unable to update signature");
        }
    }

    private void blockupdate(byte[] block, int off, int len)
        throws signatureexception
    {
        try
        {
            sigout.write(block, off, len);
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("unable to update signature");
        }
    }

    /**
     * return the one pass header associated with the current signature.
     * 
     * @param isnested
     * @return pgponepasssignature
     * @throws pgpexception
     */
    public pgponepasssignature generateonepassversion(
        boolean isnested)
        throws pgpexception
    {
        return new pgponepasssignature(new onepasssignaturepacket(sigtype, contentsigner.gethashalgorithm(), contentsigner.getkeyalgorithm(), contentsigner.getkeyid(), isnested));
    }
    
    /**
     * return a v3 signature object containing the current signature state.
     * 
     * @return pgpsignature
     * @throws pgpexception
     * @throws signatureexception
     */
    public pgpsignature generate()
        throws pgpexception, signatureexception
    {
        long creationtime = new date().gettime() / 1000;

        bytearrayoutputstream sout = new bytearrayoutputstream();

        sout.write(sigtype);
        sout.write((byte)(creationtime >> 24));
        sout.write((byte)(creationtime >> 16));
        sout.write((byte)(creationtime >> 8));
        sout.write((byte)creationtime);

        byte[] hdata = sout.tobytearray();

        blockupdate(hdata, 0, hdata.length);

        mpinteger[] sigvalues;
        if (contentsigner.getkeyalgorithm() == publickeyalgorithmtags.rsa_sign
            || contentsigner.getkeyalgorithm() == publickeyalgorithmtags.rsa_general)
            // an rsa signature
        {
            sigvalues = new mpinteger[1];
            sigvalues[0] = new mpinteger(new biginteger(1, contentsigner.getsignature()));
        }
        else
        {
            sigvalues = pgputil.dsasigtompi(contentsigner.getsignature());
        }

        byte[] digest = contentsigner.getdigest();
        byte[] fingerprint = new byte[2];

        fingerprint[0] = digest[0];
        fingerprint[1] = digest[1];

        return new pgpsignature(new signaturepacket(3, contentsigner.gettype(), contentsigner.getkeyid(), contentsigner.getkeyalgorithm(), contentsigner.gethashalgorithm(), creationtime * 1000, fingerprint, sigvalues));
    }
}
