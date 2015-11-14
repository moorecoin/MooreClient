package org.ripple.bouncycastle.bcpg;

import java.io.*;

/**
 * generic signature object
 */
public class onepasssignaturepacket 
    extends containedpacket
{
    private int  version;
    private int  sigtype;
    private int  hashalgorithm;
    private int  keyalgorithm;
    private long keyid;
    private int  nested;
    
    onepasssignaturepacket(
        bcpginputstream    in)
        throws ioexception
    {
        version = in.read();
        sigtype = in.read();
        hashalgorithm = in.read();
        keyalgorithm = in.read();
        
        keyid |= (long)in.read() << 56;
        keyid |= (long)in.read() << 48;
        keyid |= (long)in.read() << 40;
        keyid |= (long)in.read() << 32;
        keyid |= (long)in.read() << 24;
        keyid |= (long)in.read() << 16;
        keyid |= (long)in.read() << 8;
        keyid |= in.read();
        
        nested = in.read();
    }
    
    public onepasssignaturepacket(
        int        sigtype,
        int        hashalgorithm,
        int        keyalgorithm,
        long       keyid,
        boolean    isnested)
    {
        this.version = 3;
        this.sigtype = sigtype;
        this.hashalgorithm = hashalgorithm;
        this.keyalgorithm = keyalgorithm;
        this.keyid = keyid;
        this.nested = (isnested) ? 0 : 1;
    }
    
    /**
     * return the signature type.
     * @return the signature type
     */
    public int getsignaturetype()
    {
        return sigtype;
    }
    
    /**
     * return the encryption algorithm tag
     */
    public int getkeyalgorithm()
    {
        return keyalgorithm;
    }
    
    /**
     * return the hashalgorithm tag
     */
    public int gethashalgorithm()
    {
        return hashalgorithm;
    }
    
    /**
     * @return long
     */
    public long getkeyid()
    {
        return keyid;
    }
    
    /**
     * 
     */
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        bcpgoutputstream            pout = new bcpgoutputstream(bout);
  
        pout.write(version);
        pout.write(sigtype);
        pout.write(hashalgorithm);
        pout.write(keyalgorithm);

        pout.write((byte)(keyid >> 56));
        pout.write((byte)(keyid >> 48));
        pout.write((byte)(keyid >> 40));
        pout.write((byte)(keyid >> 32));
        pout.write((byte)(keyid >> 24));
        pout.write((byte)(keyid >> 16));
        pout.write((byte)(keyid >> 8));
        pout.write((byte)(keyid));
        
        pout.write(nested);
        
        out.writepacket(one_pass_signature, bout.tobytearray(), true);
    }
}
