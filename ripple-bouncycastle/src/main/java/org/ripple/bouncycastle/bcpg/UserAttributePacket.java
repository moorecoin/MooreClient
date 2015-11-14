package org.ripple.bouncycastle.bcpg;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.vector;

/**
 * basic type for a user attribute packet.
 */
public class userattributepacket 
    extends containedpacket
{    
    private userattributesubpacket[]    subpackets;
    
    public userattributepacket(
        bcpginputstream  in)
        throws ioexception
    {
        userattributesubpacketinputstream     sin = new userattributesubpacketinputstream(in);
        userattributesubpacket                sub;
                                        
        vector    v= new vector();
        while ((sub = sin.readpacket()) != null)
        {
            v.addelement(sub);
        }
        
        subpackets = new userattributesubpacket[v.size()];
            
        for (int i = 0; i != subpackets.length; i++)
        {
            subpackets[i] = (userattributesubpacket)v.elementat(i);
        }
    }
    
    public userattributepacket(
        userattributesubpacket[]    subpackets)
    {
        this.subpackets = subpackets;
    }
    
    public userattributesubpacket[] getsubpackets()
    {
        return subpackets;
    }
    
    public void encode(
        bcpgoutputstream    out)
        throws ioexception
    {
        bytearrayoutputstream    bout = new bytearrayoutputstream();
        
        for (int i = 0; i != subpackets.length; i++)
        {
            subpackets[i].encode(bout);
        }

        out.writepacket(user_attribute, bout.tobytearray(), false);
    }
}
