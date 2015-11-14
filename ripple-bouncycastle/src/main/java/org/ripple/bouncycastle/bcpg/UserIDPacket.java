package org.ripple.bouncycastle.bcpg;

import java.io.ioexception;

import org.ripple.bouncycastle.util.strings;

/**
 * basic type for a user id packet.
 */
public class useridpacket 
    extends containedpacket
{    
    private byte[]    iddata;
    
    public useridpacket(
        bcpginputstream  in)
        throws ioexception
    {
        this.iddata = in.readall();
    }

    public useridpacket(
        string    id)
    {
        this.iddata = strings.toutf8bytearray(id);
    }
    
    public string getid()
    {
        return strings.fromutf8bytearray(iddata);
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        out.writepacket(user_id, iddata, true);
    }
}
