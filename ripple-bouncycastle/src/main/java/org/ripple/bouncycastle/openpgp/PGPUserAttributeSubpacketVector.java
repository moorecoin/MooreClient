package org.ripple.bouncycastle.openpgp;

import org.ripple.bouncycastle.bcpg.userattributesubpacket;
import org.ripple.bouncycastle.bcpg.userattributesubpackettags;
import org.ripple.bouncycastle.bcpg.attr.imageattribute;

/**
 * container for a list of user attribute subpackets.
 */
public class pgpuserattributesubpacketvector
{
    userattributesubpacket[]        packets;
    
    pgpuserattributesubpacketvector(
        userattributesubpacket[]    packets)
    {
        this.packets = packets;
    }
    
    public userattributesubpacket getsubpacket(
        int    type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].gettype() == type)
            {
                return packets[i];
            }
        }
        
        return null;
    }
    
    public imageattribute getimageattribute()
    {
        userattributesubpacket    p = this.getsubpacket(userattributesubpackettags.image_attribute);
        
        if (p == null)
        {
            return null;
        }
                    
        return (imageattribute)p;
    }
    
    userattributesubpacket[] tosubpacketarray()
    {
        return packets;
    }
    
    public boolean equals(
        object o)
    {
        if (o == this)
        {
            return true;
        }
        
        if (o instanceof pgpuserattributesubpacketvector)
        {
            pgpuserattributesubpacketvector    other = (pgpuserattributesubpacketvector)o;
            
            if (other.packets.length != packets.length)
            {
                return false;
            }
            
            for (int i = 0; i != packets.length; i++)
            {
                if (!other.packets[i].equals(packets[i]))
                {
                    return false;
                }
            }
            
            return true;
        }
        
        return false;
    }
    
    public int hashcode()
    {
        int    code = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            code ^= packets[i].hashcode();
        }
        
        return code;
    }
}
