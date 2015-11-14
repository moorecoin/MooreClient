package org.ripple.bouncycastle.bcpg;

import java.io.bytearrayoutputstream;
import java.io.ioexception;

/**
 * basic type for a symmetric encrypted session key packet
 */
public class symmetrickeyencsessionpacket 
    extends containedpacket
{
    private int       version;
    private int       encalgorithm;
    private s2k       s2k;
    private byte[]    seckeydata;
    
    public symmetrickeyencsessionpacket(
        bcpginputstream  in)
        throws ioexception
    {
        version = in.read();
        encalgorithm = in.read();

        s2k = new s2k(in);

        this.seckeydata = in.readall();
    }

    public symmetrickeyencsessionpacket(
        int       encalgorithm,
        s2k       s2k,
        byte[]    seckeydata)
    {
        this.version = 4;
        this.encalgorithm = encalgorithm;
        this.s2k = s2k;
        this.seckeydata = seckeydata;
    }
    
    /**
     * @return int
     */
    public int getencalgorithm()
    {
        return encalgorithm;
    }

    /**
     * @return s2k
     */
    public s2k gets2k()
    {
        return s2k;
    }

    /**
     * @return byte[]
     */
    public byte[] getseckeydata()
    {
        return seckeydata;
    }

    /**
     * @return int
     */
    public int getversion()
    {
        return version;
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        bytearrayoutputstream   bout = new bytearrayoutputstream();
        bcpgoutputstream        pout = new bcpgoutputstream(bout);

        pout.write(version);
        pout.write(encalgorithm);
        pout.writeobject(s2k);
        
        if (seckeydata != null && seckeydata.length > 0)
        {
            pout.write(seckeydata);
        }
        
        out.writepacket(symmetric_key_enc_session, bout.tobytearray(), true);
    }
}
