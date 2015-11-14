package org.ripple.bouncycastle.openpgp;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.outputstream;
import java.security.nosuchproviderexception;
import java.security.provider;
import java.security.signatureexception;
import java.util.date;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.derinteger;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.bcpgoutputstream;
import org.ripple.bouncycastle.bcpg.mpinteger;
import org.ripple.bouncycastle.bcpg.signaturepacket;
import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.trustpacket;
import org.ripple.bouncycastle.bcpg.userattributesubpacket;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifier;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilder;
import org.ripple.bouncycastle.openpgp.operator.pgpcontentverifierbuilderprovider;
import org.ripple.bouncycastle.openpgp.operator.jcajce.jcapgpcontentverifierbuilderprovider;
import org.ripple.bouncycastle.util.bigintegers;
import org.ripple.bouncycastle.util.strings;

/**
 *a pgp signature object.
 */
public class pgpsignature
{
    public static final int    binary_document = 0x00;
    public static final int    canonical_text_document = 0x01;
    public static final int    stand_alone = 0x02;
    
    public static final int    default_certification = 0x10;
    public static final int    no_certification = 0x11;
    public static final int    casual_certification = 0x12;
    public static final int    positive_certification = 0x13;
    
    public static final int    subkey_binding = 0x18;
    public static final int    primarykey_binding = 0x19;
    public static final int    direct_key = 0x1f;
    public static final int    key_revocation = 0x20;
    public static final int    subkey_revocation = 0x28;
    public static final int    certification_revocation = 0x30;
    public static final int    timestamp = 0x40;
    
    private signaturepacket    sigpck;
    private int                signaturetype;
    private trustpacket        trustpck;
    private pgpcontentverifier verifier;
    private byte               lastb;
    private outputstream       sigout;

    pgpsignature(
        bcpginputstream    pin)
        throws ioexception, pgpexception
    {
        this((signaturepacket)pin.readpacket());
    }
    
    pgpsignature(
        signaturepacket    sigpacket)
        throws pgpexception
    {
        sigpck = sigpacket;
        signaturetype = sigpck.getsignaturetype();
        trustpck = null;
    }
    
    pgpsignature(
        signaturepacket    sigpacket,
        trustpacket        trustpacket)
        throws pgpexception
    {
        this(sigpacket);
        
        this.trustpck = trustpacket;
    }

    /**
     * return the openpgp version number for this signature.
     * 
     * @return signature version number.
     */
    public int getversion()
    {
        return sigpck.getversion();
    }
    
    /**
     * return the key algorithm associated with this signature.
     * @return signature key algorithm.
     */
    public int getkeyalgorithm()
    {
        return sigpck.getkeyalgorithm();
    }
    
    /**
     * return the hash algorithm associated with this signature.
     * @return signature hash algorithm.
     */
    public int gethashalgorithm()
    {
        return sigpck.gethashalgorithm();
    }

    /**
     * @deprecated use init(pgpcontentverifierbuilderprovider, pgppublickey)
     */
    public void initverify(
        pgppublickey    pubkey,
        string          provider)
        throws nosuchproviderexception, pgpexception
    {
        initverify(pubkey, pgputil.getprovider(provider));
    }

        /**
     * @deprecated use init(pgpcontentverifierbuilderprovider, pgppublickey)
     */
    public void initverify(
        pgppublickey    pubkey,
        provider        provider)
        throws pgpexception
    {    
        init(new jcapgpcontentverifierbuilderprovider().setprovider(provider), pubkey);
    }

    public void init(pgpcontentverifierbuilderprovider verifierbuilderprovider, pgppublickey pubkey)
        throws pgpexception
    {
        pgpcontentverifierbuilder verifierbuilder = verifierbuilderprovider.get(sigpck.getkeyalgorithm(), sigpck.gethashalgorithm());

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
        this.update(bytes, 0, bytes.length);
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

    public boolean verify()
        throws pgpexception, signatureexception
    {
        try
        {
            sigout.write(this.getsignaturetrailer());

            sigout.close();
        }
        catch (ioexception e)
        {
            throw new signatureexception(e.getmessage());
        }

        return verifier.verify(this.getsignature());
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

    /**
     * verify the signature as certifying the passed in public key as associated
     * with the passed in user attributes.
     *
     * @param userattributes user attributes the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws pgpexception
     * @throws signatureexception
     */
    public boolean verifycertification(
        pgpuserattributesubpacketvector userattributes,
        pgppublickey    key)
        throws pgpexception, signatureexception
    {
        if (verifier == null)
        {
            throw new pgpexception("pgpsignature not initialised - call init().");
        }

        updatewithpublickey(key);

        //
        // hash in the userattributes
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

        addtrailer();

        return verifier.verify(this.getsignature());
    }

    /**
     * verify the signature as certifying the passed in public key as associated
     * with the passed in id.
     * 
     * @param id id the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws pgpexception
     * @throws signatureexception
     */
    public boolean verifycertification(
        string          id,
        pgppublickey    key)
        throws pgpexception, signatureexception
    {
        if (verifier == null)
        {
            throw new pgpexception("pgpsignature not initialised - call init().");
        }

        updatewithpublickey(key);
            
        //
        // hash in the id
        //
        updatewithiddata(0xb4, strings.toutf8bytearray(id));

        addtrailer();

        return verifier.verify(this.getsignature());
    }

    /**
     * verify a certification for the passed in key against the passed in
     * master key.
     * 
     * @param masterkey the key we are verifying against.
     * @param pubkey the key we are verifying.
     * @return true if the certification is valid, false otherwise.
     * @throws signatureexception
     * @throws pgpexception
     */
    public boolean verifycertification(
        pgppublickey    masterkey,
        pgppublickey    pubkey) 
        throws signatureexception, pgpexception
    {
        if (verifier == null)
        {
            throw new pgpexception("pgpsignature not initialised - call init().");
        }

        updatewithpublickey(masterkey);
        updatewithpublickey(pubkey);

        addtrailer();

        return verifier.verify(this.getsignature());
    }

    private void addtrailer()
        throws signatureexception
    {
        try
        {
            sigout.write(sigpck.getsignaturetrailer());

            sigout.close();
        }
        catch (ioexception e)
        {
            throw new signatureexception(e.getmessage());
        }
    }

    /**
     * verify a key certification, such as a revocation, for the passed in key.
     * 
     * @param pubkey the key we are checking.
     * @return true if the certification is valid, false otherwise.
     * @throws signatureexception
     * @throws pgpexception
     */
    public boolean verifycertification(
        pgppublickey    pubkey) 
        throws signatureexception, pgpexception
    {
        if (verifier == null)
        {
            throw new pgpexception("pgpsignature not initialised - call init().");
        }

        if (this.getsignaturetype() != key_revocation
            && this.getsignaturetype() != subkey_revocation)
        {
            throw new pgpexception("signature is not a key signature");
        }

        updatewithpublickey(pubkey);

        addtrailer();

        return verifier.verify(this.getsignature());
    }

    public int getsignaturetype()
    {
         return sigpck.getsignaturetype();
    }
    
    /**
     * return the id of the key that created the signature.
     * @return keyid of the signatures corresponding key.
     */
    public long getkeyid()
    {
         return sigpck.getkeyid();
    }
    
    /**
     * return the creation time of the signature.
     * 
     * @return the signature creation time.
     */
    public date getcreationtime()
    {
        return new date(sigpck.getcreationtime());
    }
    
    public byte[] getsignaturetrailer()
    {
        return sigpck.getsignaturetrailer();
    }

    /**
     * return true if the signature has either hashed or unhashed subpackets.
     * 
     * @return true if either hashed or unhashed subpackets are present, false otherwise.
     */
    public boolean hassubpackets()
    {
        return sigpck.gethashedsubpackets() != null || sigpck.getunhashedsubpackets() != null;
    }

    public pgpsignaturesubpacketvector gethashedsubpackets()
    {
        return createsubpacketvector(sigpck.gethashedsubpackets());
    }

    public pgpsignaturesubpacketvector getunhashedsubpackets()
    {
        return createsubpacketvector(sigpck.getunhashedsubpackets());
    }
    
    private pgpsignaturesubpacketvector createsubpacketvector(signaturesubpacket[] pcks)
    {
        if (pcks != null)
        {
            return new pgpsignaturesubpacketvector(pcks);
        }
        
        return null;
    }
    
    public byte[] getsignature()
        throws pgpexception
    {
        mpinteger[]    sigvalues = sigpck.getsignature();
        byte[]         signature;

        if (sigvalues != null)
        {
            if (sigvalues.length == 1)    // an rsa signature
            {
                signature = bigintegers.asunsignedbytearray(sigvalues[0].getvalue());
            }
            else
            {
                try
                {
                    asn1encodablevector v = new asn1encodablevector();
                    v.add(new derinteger(sigvalues[0].getvalue()));
                    v.add(new derinteger(sigvalues[1].getvalue()));

                    signature = new dersequence(v).getencoded();
                }
                catch (ioexception e)
                {
                    throw new pgpexception("exception encoding dsa sig.", e);
                }
            }
        }
        else
        {
            signature = sigpck.getsignaturebytes();
        }
        
        return signature;
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

        out.writepacket(sigpck);
        if (trustpck != null)
        {
            out.writepacket(trustpck);
        }
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
}
