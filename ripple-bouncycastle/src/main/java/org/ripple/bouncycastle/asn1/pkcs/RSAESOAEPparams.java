package org.ripple.bouncycastle.asn1.pkcs;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class rsaesoaepparams
    extends asn1object
{
    private algorithmidentifier hashalgorithm;
    private algorithmidentifier maskgenalgorithm;
    private algorithmidentifier psourcealgorithm;
    
    public final static algorithmidentifier default_hash_algorithm = new algorithmidentifier(oiwobjectidentifiers.idsha1, dernull.instance);
    public final static algorithmidentifier default_mask_gen_function = new algorithmidentifier(pkcsobjectidentifiers.id_mgf1, default_hash_algorithm);
    public final static algorithmidentifier default_p_source_algorithm = new algorithmidentifier(pkcsobjectidentifiers.id_pspecified, new deroctetstring(new byte[0]));
    
    public static rsaesoaepparams getinstance(
        object  obj)
    {
        if (obj instanceof rsaesoaepparams)
        {
            return (rsaesoaepparams)obj;
        }
        else if (obj != null)
        {
            return new rsaesoaepparams(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    /**
     * the default version
     */
    public rsaesoaepparams()
    {
        hashalgorithm = default_hash_algorithm;
        maskgenalgorithm = default_mask_gen_function;
        psourcealgorithm = default_p_source_algorithm;
    }
    
    public rsaesoaepparams(
        algorithmidentifier hashalgorithm,
        algorithmidentifier maskgenalgorithm,
        algorithmidentifier psourcealgorithm)
    {
        this.hashalgorithm = hashalgorithm;
        this.maskgenalgorithm = maskgenalgorithm;
        this.psourcealgorithm = psourcealgorithm;
    }
    
    public rsaesoaepparams(
        asn1sequence seq)
    {
        hashalgorithm = default_hash_algorithm;
        maskgenalgorithm = default_mask_gen_function;
        psourcealgorithm = default_p_source_algorithm;
        
        for (int i = 0; i != seq.size(); i++)
        {
            asn1taggedobject    o = (asn1taggedobject)seq.getobjectat(i);
            
            switch (o.gettagno())
            {
            case 0:
                hashalgorithm = algorithmidentifier.getinstance(o, true);
                break;
            case 1:
                maskgenalgorithm = algorithmidentifier.getinstance(o, true);
                break;
            case 2:
                psourcealgorithm = algorithmidentifier.getinstance(o, true);
                break;
            default:
                throw new illegalargumentexception("unknown tag");
            }
        }
    }
    
    public algorithmidentifier gethashalgorithm()
    {
        return hashalgorithm;
    }
    
    public algorithmidentifier getmaskgenalgorithm()
    {
        return maskgenalgorithm;
    }
    
    public algorithmidentifier getpsourcealgorithm()
    {
        return psourcealgorithm;
    }
    
    /**
     * <pre>
     *  rsaes-oaep-params ::= sequence {
     *     hashalgorithm      [0] oaep-pssdigestalgorithms     default sha1,
     *     maskgenalgorithm   [1] pkcs1mgfalgorithms  default mgf1sha1,
     *     psourcealgorithm   [2] pkcs1psourcealgorithms  default pspecifiedempty
     *   }
     *  
     *   oaep-pssdigestalgorithms    algorithm-identifier ::= {
     *     { oid id-sha1 parameters null   }|
     *     { oid id-sha256 parameters null }|
     *     { oid id-sha384 parameters null }|
     *     { oid id-sha512 parameters null },
     *     ...  -- allows for future expansion --
     *   }
     *   pkcs1mgfalgorithms    algorithm-identifier ::= {
     *     { oid id-mgf1 parameters oaep-pssdigestalgorithms },
     *    ...  -- allows for future expansion --
     *   }
     *   pkcs1psourcealgorithms    algorithm-identifier ::= {
     *     { oid id-pspecified parameters octet string },
     *     ...  -- allows for future expansion --
     *  }
     * </pre>
     * @return the asn1 primitive representing the parameters.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();
        
        if (!hashalgorithm.equals(default_hash_algorithm))
        {
            v.add(new dertaggedobject(true, 0, hashalgorithm));
        }
        
        if (!maskgenalgorithm.equals(default_mask_gen_function))
        {
            v.add(new dertaggedobject(true, 1, maskgenalgorithm));
        }
        
        if (!psourcealgorithm.equals(default_p_source_algorithm))
        {
            v.add(new dertaggedobject(true, 2, psourcealgorithm));
        }
        
        return new dersequence(v);
    }
}
