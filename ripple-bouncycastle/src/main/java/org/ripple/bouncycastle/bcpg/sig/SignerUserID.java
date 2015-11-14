package org.ripple.bouncycastle.bcpg.sig;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;

/**
 * packet giving the user id of the signer.
 */
public class signeruserid 
    extends signaturesubpacket
{    
    private static byte[] useridtobytes(
        string    id)
    {
        byte[] iddata = new byte[id.length()];
        
        for (int i = 0; i != id.length(); i++)
        {
            iddata[i] = (byte)id.charat(i);
        }
        
        return iddata;
    }
    
    public signeruserid(
        boolean    critical,
        byte[]     data)
    {
        super(signaturesubpackettags.signer_user_id, critical, data);
    }
    
    public signeruserid(
        boolean    critical,
        string     userid)
    {
        super(signaturesubpackettags.signer_user_id, critical, useridtobytes(userid));
    }
    
    public string getid()
    {
        char[]    chars = new char[data.length];
        
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(data[i] & 0xff);
        }
        
        return new string(chars);
    }
}
