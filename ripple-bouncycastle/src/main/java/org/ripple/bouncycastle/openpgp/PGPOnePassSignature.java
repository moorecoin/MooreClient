package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.signatureexception;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.onepasssignaturepacket;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifier;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilderprovider;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentverifierbuilderprovider;

/**
 * a one pass signature object.
 */
public class pgponepasssignature
{
    private onepasssignaturepacket sigpack;
    private int                    signaturetype;

    private pgpcontentverifier verifier;
    private byte               lastb;
    private outputstream       sigout;

    pgponepasssignature(
        bcpginputstream    pin)
        throws ioexception, pgpexception
    {
        this((onepasssignaturepacket)pin.readpacket());
    }
    
    pgponepasssignature(
        onepasssignaturepacket    sigpack)
        throws pgpexception
    {
        this.sigpack = sigpack;
        this.signaturetype = sigpack.getsignaturetype();
    }
    
    /**
     * initialise the signature object for verification.
     * 
     * @param pubkey
     * @param provider
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated use init() method.
     */
    public void initverify(
        pgppublickey    pubkey,
        string          provider)
        throws nosuchproviderexception, pgpexception
    {
        initverify(pubkey, pgputil.getprovider(provider));
    }

        /**
     * initialise the signature object for verification.
     *
     * @param pubkey
     * @param provider
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated use init() method.
     */
    public void initverify(
        pgppublickey    pubkey,
        provider        provider)
        throws pgpexception
    {
        init(new jcapgpcontentverifierbuilderprovider().setprovider(provider), pubkey);
    }

    /**
     * initialise the signature object for verification.
     *
     * @param verifierbuilderprovider   provider for a content verifier builder for the signature type of interest.
     * @param pubkey  the public key to use for verification
     * @throws pgpexception if there's an issue with creating the verifier.
     */
    public void init(pgpcontentverifierbuilderprovider verifierbuilderprovider, pgppublickey pubkey)
        throws pgpexception
    {
        pgpcontentverifierbuilder verifierbuilder = verifierbuilderprovider.get(sigpack.getkeyalgorithm(), sigpack.gethashalgorithm());

        verifier = verifierbuilder.build(pubkey);

        lastb = 0;
        sigout = verifier.getoutputstream();
    }

    public void update(
        byte    b)
        throws signatureexception
    {
        if (signaturetype == pgpsignature.canonical_text_document)
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
        byte[]    bytes)
        throws signatureexception
    {
        if (signaturetype == pgpsignature.canonical_text_document)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                this.update(bytes[i]);
            }
        }
        else
        {
            blockupdate(bytes, 0, bytes.length);
        }
    }
    
    public void update(
        byte[]    bytes,
        int       off,
        int       length)
        throws signatureexception
    {
        if (signaturetype == pgpsignature.canonical_text_document)
        {
            int finish = off + length;
            
            for (int i = off; i != finish; i++)
            {
                this.update(bytes[i]);
            }
        }
        else
        {
            blockupdate(bytes, off, length);
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
        {             // todo: we really should get rid of signature exception next....
            throw new signatureexception(e.getmessage());
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
            throw new illegalstateexception(e.getmessage());
        }
    }

    /**
     * verify the calculated signature against the passed in pgpsignature.
     * 
     * @param pgpsig
     * @return boolean
     * @throws pgpexception
     * @throws signatureexception
     */
    public boolean verify(
        pgpsignature    pgpsig)
        throws pgpexception, signatureexception
    {
        try
        {
            sigout.write(pgpsig.getsignaturetrailer());

            sigout.close();
        }
        catch (ioexception e)
        {
            throw new pgpexception("unable to add trailer: " + e.getmessage(), e);
        }

        return verifier.verify(pgpsig.getsignature());
    }
    
    public long getkeyid()
    {
        return sigpack.getkeyid();
    }
    
    public int getsignaturetype()
    {
        return sigpack.getsignaturetype();
    }

    public int gethashalgorithm()
    {
        return sigpack.gethashalgorithm();
    }

    public int getkeyalgorithm()
    {
        return sigpack.getkeyalgorithm();
    }

    public byte[] getencoded()
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        this.encode(bout);
        
        return bout.tobytearray();
    }
    
    public void encode(
        outputstream    outstream) 
        throws ioexception
    {
        bcpgoutputstream    out;
        
        if (outstream instanceof bcpgoutputstream)
        {
            out = (bcpgoutputstream)outstream;
        }
        else
        {
            out = new bcpgoutputstream(outstream);
        }

        out.writepacket(sigpack);
    }
}
