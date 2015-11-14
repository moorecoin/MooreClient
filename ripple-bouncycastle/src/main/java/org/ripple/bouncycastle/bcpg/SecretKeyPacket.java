package org.ripple.bouncycastle.bcpg;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * basic packet for a pgp secret key
 */
public class secretkeypacket 
    extends containedpacket implements publickeyalgorithmtags
{
    public static final int usage_none = 0x00;
    public static final int usage_checksum = 0xff;
    public static final int usage_sha1 = 0xfe;

    private publickeypacket    pubkeypacket;
    private byte[]             seckeydata;
    private int                s2kusage;
    private int                encalgorithm;
    private s2k                s2k;
    private byte[]             iv;
    
    /**
     * 
     * @param in
     * @throws ioexception
     */
    secretkeypacket(
        bcpginputstream    in)
        throws ioexception
    {
        if (this instanceof secretsubkeypacket)
        {
            pubkeypacket = new publicsubkeypacket(in);
        }
        else
        {
            pubkeypacket = new publickeypacket(in);
        }

        s2kusage = in.read();

        if (s2kusage == usage_checksum || s2kusage == usage_sha1)
        {
            encalgorithm = in.read();
            s2k = new s2k(in);
        }
        else
        {
            encalgorithm = s2kusage;
        }

        if (!(s2k != null && s2k.gettype() == s2k.gnu_dummy_s2k && s2k.getprotectionmode() == 0x01))
        {
            if (s2kusage != 0) 
            {
                if (encalgorithm < 7)
                {
                    iv = new byte[8];
                }
                else
                {
                    iv = new byte[16];
                }
                in.readfully(iv, 0, iv.length);
            }
        }

        this.seckeydata = in.readall();
    }

    /**
     * 
     * @param pubkeypacket
     * @param encalgorithm
     * @param s2k
     * @param iv
     * @param seckeydata
     */
    public secretkeypacket(
        publickeypacket pubkeypacket,
        int             encalgorithm,
        s2k             s2k,
        byte[]          iv,
        byte[]          seckeydata)
    {
        this.pubkeypacket = pubkeypacket;
        this.encalgorithm = encalgorithm;
        
        if (encalgorithm != symmetrickeyalgorithmtags.null)
        {
            this.s2kusage = usage_checksum;
        }
        else
        {
            this.s2kusage = usage_none;
        }
        
        this.s2k = s2k;
        this.iv = iv;
        this.seckeydata = seckeydata;
    }
    
    public secretkeypacket(
        publickeypacket pubkeypacket,
        int             encalgorithm,
        int             s2kusage,
        s2k             s2k,
        byte[]          iv,
        byte[]          seckeydata)
    {
        this.pubkeypacket = pubkeypacket;
        this.encalgorithm = encalgorithm;
        this.s2kusage = s2kusage;
        this.s2k = s2k;
        this.iv = iv;
        this.seckeydata = seckeydata;
    }

    public int getencalgorithm()
    {
        return encalgorithm;
    }
    
    public int gets2kusage()
    {
        return s2kusage;
    }

    public byte[] getiv()
    {
        return iv;
    }
    
    public s2k gets2k()
    {
        return s2k;
    }
    
    public publickeypacket getpublickeypacket()
    {
        return pubkeypacket;
    }
    
    public byte[] getsecretkeydata()
    {
        return seckeydata;
    }
    
    public byte[] getencodedcontents()
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        bcpgoutputstream         pout = new bcpgoutputstream(bout);
        
        pout.write(pubkeypacket.getencodedcontents());
        
        pout.write(s2kusage);

        if (s2kusage == usage_checksum || s2kusage == usage_sha1)
        {
            pout.write(encalgorithm);
            pout.writeobject(s2k);
        }
        
        if (iv != null)
        {
            pout.write(iv);
        }
        
        if (seckeydata != null && seckeydata.length > 0)
        {
            pout.write(seckeydata);
        }

        return bout.tobytearray();
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(secret_key, getencodedcontents(), true);
    }
}
