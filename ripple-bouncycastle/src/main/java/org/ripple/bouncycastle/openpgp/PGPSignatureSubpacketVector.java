package org.ripple.bouncycastle.openpgp;

import java.util.arraylist;
import java.util.date;
import java.util.list;

import org.ripple.bouncycastle.bcpg.signaturesubpacket;
import org.ripple.bouncycastle.bcpg.signaturesubpackettags;
import org.ripple.bouncycastle.bcpg.sig.features;
import org.ripple.bouncycastle.bcpg.sig.issuerkeyid;
import org.ripple.bouncycastle.bcpg.sig.keyexpirationtime;
import org.ripple.bouncycastle.bcpg.sig.keyflags;
import org.ripple.bouncycastle.bcpg.sig.notationdata;
import org.ripple.bouncycastle.bcpg.sig.preferredalgorithms;
import org.ripple.bouncycastle.bcpg.sig.primaryuserid;
import org.ripple.bouncycastle.bcpg.sig.signaturecreationtime;
import org.ripple.bouncycastle.bcpg.sig.signatureexpirationtime;
import org.ripple.bouncycastle.bcpg.sig.signeruserid;

/**
 * container for a list of signature subpackets.
 */
public class pgpsignaturesubpacketvector
{
    signaturesubpacket[]    packets;
    
    pgpsignaturesubpacketvector(
        signaturesubpacket[]    packets)
    {
        this.packets = packets;
    }
    
    public signaturesubpacket getsubpacket(
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

    /**
     * return true if a particular subpacket type exists.
     *
     * @param type type to look for.
     * @return true if present, false otherwise.
     */
    public boolean hassubpacket(
        int type)
    {
        return getsubpacket(type) != null;
    }

    /**
     * return all signature subpackets of the passed in type.
     * @param type subpacket type code
     * @return an array of zero or more matching subpackets.
     */
    public signaturesubpacket[] getsubpackets(
        int    type)
    {
        list list = new arraylist();

        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].gettype() == type)
            {
                list.add(packets[i]);
            }
        }

        return (signaturesubpacket[])list.toarray(new signaturesubpacket[]{});
    }

    public notationdata[] getnotationdataoccurences()
    {
        signaturesubpacket[] notations = getsubpackets(signaturesubpackettags.notation_data);
        notationdata[] vals = new notationdata[notations.length];
        for (int i = 0; i < notations.length; i++)
        {
            vals[i] = (notationdata)notations[i];
        }

        return vals;
    }

    public long getissuerkeyid()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.issuer_key_id);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((issuerkeyid)p).getkeyid();
    }
    
    public date getsignaturecreationtime()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.creation_time);
        
        if (p == null)
        {
            return null;
        }
        
        return ((signaturecreationtime)p).gettime();
    }
    
    /**
     * return the number of seconds a signature is valid for after its creation date. a value of zero means
     * the signature never expires.
     * 
     * @return seconds a signature is valid for.
     */
    public long getsignatureexpirationtime()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.expire_time);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((signatureexpirationtime)p).gettime();
    }
    
    /**
     * return the number of seconds a key is valid for after its creation date. a value of zero means
     * the key never expires.
     * 
     * @return seconds a key is valid for.
     */
    public long getkeyexpirationtime()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.key_expire_time);
        
        if (p == null)
        {
            return 0;
        }
        
        return ((keyexpirationtime)p).gettime();
    }
    
    public int[] getpreferredhashalgorithms()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.preferred_hash_algs);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((preferredalgorithms)p).getpreferences();
    }
    
    public int[] getpreferredsymmetricalgorithms()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.preferred_sym_algs);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((preferredalgorithms)p).getpreferences();
    }
    
    public int[] getpreferredcompressionalgorithms()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.preferred_comp_algs);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((preferredalgorithms)p).getpreferences();
    }
    
    public int getkeyflags()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.key_flags);
        
        if (p == null)
        {
            return 0;
        }
                    
        return ((keyflags)p).getflags();
    }
    
    public string getsigneruserid()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.signer_user_id);
        
        if (p == null)
        {
            return null;
        }
                    
        return ((signeruserid)p).getid();
    }

    public boolean isprimaryuserid()
    {
        primaryuserid primaryid = (primaryuserid)this.getsubpacket(signaturesubpackettags.primary_user_id);

        if (primaryid != null)
        {
            return primaryid.isprimaryuserid();
        }

        return false;
    }

    public int[] getcriticaltags()
    {
        int    count = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].iscritical())
            {
                count++;
            }
        }
        
        int[]    list = new int[count];
        
        count = 0;
        
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].iscritical())
            {
                list[count++] = packets[i].gettype();
            }
        }
        
        return list;
    }

    public features getfeatures()
    {
        signaturesubpacket    p = this.getsubpacket(signaturesubpackettags.features);

        if (p == null)
        {
            return null;
        }

        return new features(p.iscritical(), p.getdata());
    }

    /**
     * return the number of packets this vector contains.
     * 
     * @return size of the packet vector.
     */
    public int size()
    {
        return packets.length;
    }
    
    signaturesubpacket[] tosubpacketarray()
    {
        return packets;
    }
}
