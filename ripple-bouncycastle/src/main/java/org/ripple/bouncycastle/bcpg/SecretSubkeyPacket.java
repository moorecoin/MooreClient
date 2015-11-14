package org.ripple.bouncycastle.bcpg;

import java.io.*;

/**
 * basic packet for a pgp secret key
 */
public class secretsubkeypacket 
    extends secretkeypacket
{
    /**
     * 
     * @param in
     * @throws ioexception
     */
    secretsubkeypacket(
        bcpginputstream    in)
        throws ioexception
    { 
        super(in);
    }
    
    /**
     * 
     * @param pubkeypacket
     * @param encalgorithm
     * @param s2k
     * @param iv
     * @param seckeydata
     */
    public secretsubkeypacket(
        publickeypacket  pubkeypacket,
        int              encalgorithm,
        s2k              s2k,
        byte[]           iv,
        byte[]           seckeydata)
    {
        super(pubkeypacket, encalgorithm, s2k, iv, seckeydata);
    }
 
    public secretsubkeypacket(
        publickeypacket  pubkeypacket,
        int              encalgorithm,
        int              s2kusage,
        s2k              s2k,
        byte[]           iv,
        byte[]           seckeydata)
    {
        super(pubkeypacket, encalgorithm, s2kusage, s2k, iv, seckeydata);
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(secret_subkey, getencodedcontents(), true);
    }
}
