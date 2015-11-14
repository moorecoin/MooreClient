package org.ripple.bouncycastle.asn1.icao;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * the ldssecurityobject object (v1.8).
 * <pre>
 * ldssecurityobject ::= sequence {
 *   version                ldssecurityobjectversion,
 *   hashalgorithm          digestalgorithmidentifier,
 *   datagrouphashvalues    sequence size (2..ub-datagroups) of datahashgroup,
 *   ldsversioninfo         ldsversioninfo optional
 *   -- if present, version must be v1 }
 *   
 * digestalgorithmidentifier ::= algorithmidentifier,
 * 
 * ldssecurityobjectversion :: integer {v0(0)}
 * </pre>
 */

public class ldssecurityobject 
    extends asn1object
    implements icaoobjectidentifiers    
{
    public static final int ub_datagroups = 16;
    
    private asn1integer version = new asn1integer(0);
    private algorithmidentifier digestalgorithmidentifier;
    private datagrouphash[] datagrouphash;
    private ldsversioninfo versioninfo;

    public static ldssecurityobject getinstance(
        object obj)
    {
        if (obj instanceof ldssecurityobject)
        {
            return (ldssecurityobject)obj;
        }
        else if (obj != null)
        {
            return new ldssecurityobject(asn1sequence.getinstance(obj));            
        }
        
        return null;
    }    
    
    private ldssecurityobject(
        asn1sequence seq)
    {
        if (seq == null || seq.size() == 0)
        {
            throw new illegalargumentexception("null or empty sequence passed.");
        }
        
        enumeration e = seq.getobjects();

        // version
        version = asn1integer.getinstance(e.nextelement());
        // digestalgorithmidentifier
        digestalgorithmidentifier = algorithmidentifier.getinstance(e.nextelement());
      
        asn1sequence datagrouphashseq = asn1sequence.getinstance(e.nextelement());

        if (version.getvalue().intvalue() == 1)
        {
            versioninfo = ldsversioninfo.getinstance(e.nextelement());
        }

        checkdatagrouphashseqsize(datagrouphashseq.size());        
        
        datagrouphash = new datagrouphash[datagrouphashseq.size()];
        for (int i= 0; i< datagrouphashseq.size();i++)
        {
            datagrouphash[i] = datagrouphash.getinstance(datagrouphashseq.getobjectat(i));
        }
    }

    public ldssecurityobject(
        algorithmidentifier digestalgorithmidentifier, 
        datagrouphash[]       datagrouphash)
    {
        this.version = new asn1integer(0);
        this.digestalgorithmidentifier = digestalgorithmidentifier;
        this.datagrouphash = datagrouphash;
        
        checkdatagrouphashseqsize(datagrouphash.length);                      
    }    

    public ldssecurityobject(
        algorithmidentifier digestalgorithmidentifier,
        datagrouphash[]     datagrouphash,
        ldsversioninfo      versioninfo)
    {
        this.version = new asn1integer(1);
        this.digestalgorithmidentifier = digestalgorithmidentifier;
        this.datagrouphash = datagrouphash;
        this.versioninfo = versioninfo;

        checkdatagrouphashseqsize(datagrouphash.length);
    }

    private void checkdatagrouphashseqsize(int size)
    {
        if ((size < 2) || (size > ub_datagroups))
        {
               throw new illegalargumentexception("wrong size in datagrouphashvalues : not in (2.."+ ub_datagroups +")");
        }
    }  

    public int getversion()
    {
        return version.getvalue().intvalue();
    }

    public algorithmidentifier getdigestalgorithmidentifier()
    {
        return digestalgorithmidentifier;
    }
    
    public datagrouphash[] getdatagrouphash()
    {
        return datagrouphash;
    }

    public ldsversioninfo getversioninfo()
    {
        return versioninfo;
    }

    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        
        seq.add(version);
        seq.add(digestalgorithmidentifier);
                
        asn1encodablevector seqname = new asn1encodablevector();
        for (int i = 0; i < datagrouphash.length; i++) 
        {
            seqname.add(datagrouphash[i]);
        }            
        seq.add(new dersequence(seqname));                   

        if (versioninfo != null)
        {
            seq.add(versioninfo);
        }

        return new dersequence(seq);
    }
}
