package org.ripple.bouncycastle.openpgp;

import java.io.ioexception;
import java.util.arraylist;
import java.util.iterator;
import java.util.list;

import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.inputstreampacket;
import org.ripple.bouncycastle.bcpg.packettags;
import org.ripple.bouncycastle.bcpg.publickeyencsessionpacket;
import org.ripple.bouncycastle.bcpg.symmetrickeyencsessionpacket;

/**
 * a holder for a list of pgp encryption method packets.
 */
public class pgpencrypteddatalist
{
    list                 list = new arraylist();
    inputstreampacket    data;
    
    public pgpencrypteddatalist(
        bcpginputstream    pin)
        throws ioexception
    {
        while (pin.nextpackettag() == packettags.public_key_enc_session
            || pin.nextpackettag() == packettags.symmetric_key_enc_session)
        {
            list.add(pin.readpacket());
        }

        data = (inputstreampacket)pin.readpacket();
        
        for (int i = 0; i != list.size(); i++)
        {
            if (list.get(i) instanceof symmetrickeyencsessionpacket)
            {
                list.set(i, new pgppbeencrypteddata((symmetrickeyencsessionpacket)list.get(i), data));
            }
            else 
            {
                list.set(i, new pgppublickeyencrypteddata((publickeyencsessionpacket)list.get(i), data));
            }
        }
    }
    
    public object get(
        int    index)
    {
        return list.get(index);
    }
    
    public int size()
    {
        return list.size();
    }
    
    public boolean isempty()
    {
        return list.isempty();
    }
    
    /**
     * @deprecated misspelt - use getencrypteddataobjects()
     */
    public iterator getencypteddataobjects()
    {
        return list.iterator();
    }
    
    public iterator getencrypteddataobjects()
    {
        return list.iterator();
    }
}
