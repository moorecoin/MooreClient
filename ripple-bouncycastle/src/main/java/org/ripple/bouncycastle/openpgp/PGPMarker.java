/*
 * created on mar 6, 2004
 *
 * to change this generated comment go to 
 * window>preferences>java>code generation>code and comments
 */
package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.markerpacket;

/**
 * a pgp marker packet - in general these should be ignored other than where
 * the idea is to preserve the original input stream.
 */
public class pgpmarker
{
    private markerpacket p;
    
    /**
     * default constructor.
     * 
     * @param in
     * @throws ioexception
     */
    public pgpmarker(
        bcpginputstream in) 
        throws ioexception
    {
        p = (markerpacket)in.readpacket();
    }
}
