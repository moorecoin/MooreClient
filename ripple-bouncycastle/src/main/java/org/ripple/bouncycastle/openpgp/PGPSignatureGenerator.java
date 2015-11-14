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
import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;
import org.ripple.bouncycastle.bcpg.userattributesubpacket;
import org.ripple.bouncycastle.bcpg.sig.issuerkeyid;
import org.ripple.bouncycastle.bcpg.sig.signaturecreationtime;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsigner;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentsignerbuilder;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentsignerbuilder;
import org.ripple.bouncycastle.util.strings;

/**
 * generator for pgp signatures.
 */
public class pgpsignaturegenerator
{
    private signaturesubpacket[]    unhashed = new signaturesubpacket[0];
    private signaturesubpacket[]    hashed = new signaturesubpacket[0];
    private outputstream sigout;
    private pgpcontentsignerbuilder contentsignerbuilder;
    private pgpcontentsigner contentsigner;
    private int             sigtype;
    private byte            lastb;
    private int providedkeyalgorithm = -1;

    /**
     * create a generator for the passed in keyalgorithm and hashalgorithm codes.
     *
     * @param keyalgorithm keyalgorithm to use for signing
     * @param hashalgorithm algorithm to use for digest
     * @param provider provider to use for digest algorithm
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated use method taking a pgpcontentsignerbuilder
     */
    public pgpsignaturegenerator(
        int     keyalgorithm,
        int     hashalgorithm,
        string  provider)
        throws nosuchalgorithmexception, nosuchproviderexception, pgpexception
    {
        this(keyalgorithm, provider, hashalgorithm, provider);
    }

    /**
     * create a generator for the passed in keyalgorithm and hashalgorithm codes.
     *
     * @deprecated use method taking a pgpcontentsignerbuilder
     */
    public pgpsignaturegenerator(
        int      keyalgorithm,
        int      hashalgorithm,
        provider provider)
        throws nosuchalgorithmexception, pgpexception
    {
        this(keyalgorithm, provider, hashalgorithm, provider);
    }

    /**
     * create a generator for the passed in keyalgorithm and hashalgorithm codes.
     *
     * @param keyalgorithm keyalgorithm to use for signing
     * @param sigprovider provider to use for signature generation
     * @param hashalgorithm algorithm to use for digest
     * @param digprovider provider to use for digest algorithm
     * @throws nosuchalgorithmexception
     * @throws nosuchproviderexception
     * @throws pgpexception
     * @deprecated use method taking a pgpcontentsignerbuilder
     */
    public pgpsignaturegenerator(
        int     keyalgorithm,
        string  sigprovider,
        int     hashalgorithm,
        string  digprovider)
        throws nosuchalgorithmexception, nosuchproviderexception, pgpexception
    {
        this(keyalgorithm, pgputil.getprovider(sigprovider), hashalgorithm, pgputil.getprovider(digprovider));
    }

    /**
     *
     * @param keyalgorithm
     * @param sigprovider
     * @param hashalgorithm
     * @param digprovider
     * @throws nosuchalgorithmexception
     * @throws pgpexception
     * @deprecated use constructor taking pgpcontentsignerbuilder.
     */
    public pgpsignaturegenerator(
        int      keyalgorithm,
        provider sigprovider,
        int      hashalgorithm,
        provider digprovider)
        throws nosuchalgorithmexception, pgpexception
    {
        this.providedkeyalgorithm = keyalgorithm;
        this.contentsignerbuilder = new jcapgpcontentsignerbuilder(keyalgorithm, hashalgorithm).setprovider(sigprovider).setdigestprovider(digprovider);
    }

    /**
     * create a signature generator built on the passed in contentsignerbuilder.
     *
     * @param contentsignerbuilder  builder to produce pgpcontentsigner objects for generating signatures.
     */
    public pgpsignaturegenerator(
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
     * @deprecated use init() method
     */
    public void initsign(
        int             signaturetype,
        pgpprivatekey   key)
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
     * @throws pgpexception
     */
    public void init(
        int             signaturetype,
        pgpprivatekey   key)
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
     * @deprecated random parameter now ignored.
     */
    public void initsign(
        int             signaturetype,
        pgpprivatekey   key,
        securerandom    random)
        throws pgpexception
    {
        initsign(signaturetype, key);
    }
    
    public void update(
        byte    b) 
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
        byte[]    b) 
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

    public void sethashedsubpackets(
        pgpsignaturesubpacketvector    hashedpcks)
    {
        if (hashedpcks == null)
        {
            hashed = new signaturesubpacket[0];
            return;
        }
        
        hashed = hashedpcks.tosubpacketarray();
    }
    
    public void setunhashedsubpackets(
        pgpsignaturesubpacketvector    unhashedpcks)
    {
        if (unhashedpcks == null)
        {
            unhashed = new signaturesubpacket[0];
            return;
        }

        unhashed = unhashedpcks.tosubpacketarray();
    }
    
    /**
     * return the one pass header associated with the current signature.
     * 
     * @param isnested
     * @return pgponepasssignature
     * @throws pgpexception
     */
    public pgponepasssignature generateonepassversion(
        boolean    isnested)
        throws pgpexception
    {
        return new pgponepasssignature(new onepasssignaturepacket(sigtype, contentsigner.gethashalgorithm(), contentsigner.getkeyalgorithm(), contentsigner.getkeyid(), isnested));
    }
    
    /**
     * return a signature object containing the current signature state.
     * 
     * @return pgpsignature
     * @throws pgpexception
     * @throws signatureexception
     */
    public pgpsignature generate()
        throws pgpexception, signatureexception
    {
        mpinteger[]             sigvalues;
        int                     version = 4;
        bytearrayoutputstream   sout = new bytearrayoutputstream();
        signaturesubpacket[]    hpkts, unhpkts;

        if (!packetpresent(hashed, signaturesubpackettags.creation_time))
        {
            hpkts = insertsubpacket(hashed, new signaturecreationtime(false, new date()));
        }
        else
        {
            hpkts = hashed;
        }
        
        if (!packetpresent(hashed, signaturesubpackettags.issuer_key_id) && !packetpresent(unhashed, signaturesubpackettags.issuer_key_id))
        {
            unhpkts = insertsubpacket(unhashed, new issuerkeyid(false, contentsigner.getkeyid()));
        }
        else
        {
            unhpkts = unhashed;
        }
        
        try
        {
            sout.write((byte)version);
            sout.write((byte)sigtype);
            sout.write((byte)contentsigner.getkeyalgorithm());
            sout.write((byte)contentsigner.gethashalgorithm());
            
            bytearrayoutputstream    hout = new bytearrayoutputstream();
            
            for (int i = 0; i != hpkts.length; i++)
            {
                hpkts[i].encode(hout);
            }
                
            byte[]                            data = hout.tobytearray();
    
            sout.write((byte)(data.length >> 8));
            sout.write((byte)data.length);
            sout.write(data);
        }
        catch (ioexception e)
        {
            throw new pgpexception("exception encoding hashed data.", e);
        }
        
        byte[]    hdata = sout.tobytearray();
        
        sout.write((byte)version);
        sout.write((byte)0xff);
        sout.write((byte)(hdata.length >> 24));
        sout.write((byte)(hdata.length >> 16));
        sout.write((byte)(hdata.length >> 8));
        sout.write((byte)(hdata.length));
        
        byte[]    trailer = sout.tobytearray();

        blockupdate(trailer, 0, trailer.length);

        if (contentsigner.getkeyalgorithm() == publickeyalgorithmtags.rsa_sign
            || contentsigner.getkeyalgorithm() == publickeyalgorithmtags.rsa_general)    // an rsa signature
        {
            sigvalues = new mpinteger[1];
            sigvalues[0] = new mpinteger(new biginteger(1, contentsigner.getsignature()));
        }
        else
        {   
            sigvalues = pgputil.dsasigtompi(contentsigner.getsignature());
        }
        
        byte[]                        digest = contentsigner.getdigest();
        byte[]                        fingerprint = new byte[2];

        fingerprint[0] = digest[0];
        fingerprint[1] = digest[1];
        
        return new pgpsignature(new signaturepacket(sigtype, contentsigner.getkeyid(), contentsigner.getkeyalgorithm(), contentsigner.gethashalgorithm(), hpkts, unhpkts, fingerprint, sigvalues));
    }

    /**
     * generate a certification for the passed in id and key.
     * 
     * @param id the id we are certifying against the public key.
     * @param pubkey the key we are certifying against the id.
     * @return the certification.
     * @throws signatureexception
     * @throws pgpexception
     */
    public pgpsignature generatecertification(
        string          id,
        pgppublickey    pubkey) 
        throws signatureexception, pgpexception
    {
        updatewithpublickey(pubkey);

        //
        // hash in the id
        //
        updatewithiddata(0xb4, strings.toutf8bytearray(id));

        return this.generate();
    }

    /**
     * generate a certification for the passed in userattributes
     * @param userattributes the id we are certifying against the public key.
     * @param pubkey the key we are certifying against the id.
     * @return the certification.
     * @throws signatureexception
     * @throws pgpexception
     */
    public pgpsignature generatecertification(
        pgpuserattributesubpacketvector userattributes,
        pgppublickey                    pubkey)
        throws signatureexception, pgpexception
    {
        updatewithpublickey(pubkey);

        //
        // hash in the attributes
        //
        try
        {
            bytearrayoutputstream bout = new bytearrayoutputstream();
            userattributesubpacket[] packets = userattributes.tosubpacketarray();
            for (int i = 0; i != packets.length; i++)
            {
                packets[i].encode(bout);
            }
            updatewithiddata(0xd1, bout.tobytearray());
        }
        catch (ioexception e)
        {
            throw new pgpexception("cannot encode subpacket array", e);
        }

        return this.generate();
    }

    /**
     * generate a certification for the passed in key against the passed in
     * master key.
     * 
     * @param masterkey the key we are certifying against.
     * @param pubkey the key we are certifying.
     * @return the certification.
     * @throws signatureexception
     * @throws pgpexception
     */
    public pgpsignature generatecertification(
        pgppublickey    masterkey,
        pgppublickey    pubkey) 
        throws signatureexception, pgpexception
    {
        updatewithpublickey(masterkey);
        updatewithpublickey(pubkey);
        
        return this.generate();
    }
    
    /**
     * generate a certification, such as a revocation, for the passed in key.
     * 
     * @param pubkey the key we are certifying.
     * @return the certification.
     * @throws signatureexception
     * @throws pgpexception
     */
    public pgpsignature generatecertification(
        pgppublickey    pubkey)
        throws signatureexception, pgpexception
    {
        updatewithpublickey(pubkey);

        return this.generate();
    }
    
    private byte[] getencodedpublickey(
        pgppublickey pubkey) 
        throws pgpexception
    {
        byte[]    keybytes;
        
        try
        {
            keybytes = pubkey.publicpk.getencodedcontents();
        }
        catch (ioexception e)
        {
            throw new pgpexception("exception preparing key.", e);
        }
        
        return keybytes;
    }

    private boolean packetpresent(
        signaturesubpacket[] packets,
        int type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].gettype() == type)
            {
                return true;
            }
        }

        return false;
    }

    private signaturesubpacket[] insertsubpacket(
        signaturesubpacket[] packets,
        signaturesubpacket subpacket)
    {
        signaturesubpacket[] tmp = new signaturesubpacket[packets.length + 1];

        tmp[0] = subpacket;
        system.arraycopy(packets, 0, tmp, 1, packets.length);

        return tmp;
    }

    private void updatewithiddata(int header, byte[] idbytes)
        throws signatureexception
    {
        this.update((byte)header);
        this.update((byte)(idbytes.length >> 24));
        this.update((byte)(idbytes.length >> 16));
        this.update((byte)(idbytes.length >> 8));
        this.update((byte)(idbytes.length));
        this.update(idbytes);
    }

    private void updatewithpublickey(pgppublickey key)
        throws pgpexception, signatureexception
    {
        byte[] keybytes = getencodedpublickey(key);

        this.update((byte)0x99);
        this.update((byte)(keybytes.length >> 8));
        this.update((byte)(keybytes.length));
        this.update(keybytes);
    }
}
