package org.ripple.bouncycastle.asn1.pkcs;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class rsassapssparams
    extends asn1object
{
    private algorithmidentifier hashalgorithm;
    private algorithmidentifier maskgenalgorithm;
    private asn1integer          saltlength;
    private asn1integer          trailerfield;
    
    public final static algorithmidentifier default_hash_algorithm = new algorithmidentifier(oiwobjectidentifiers.idsha1, dernull.instance);
    public final static algorithmidentifier default_mask_gen_function = new algorithmidentifier(pkcsobjectidentifiers.id_mgf1, default_hash_algorithm);
    public final static asn1integer          default_salt_length = new asn1integer(20);
    public final static asn1integer          default_trailer_field = new asn1integer(1);
    
    public static rsassapssparams getinstance(
        object  obj)
    {
        if (obj instanceof rsassapssparams)
        {
            return (rsassapssparams)obj;
        }
        else if (obj != null)
        {
            return new rsassapssparams(asn1sequence.getinstance(obj));
        }

        return null;
    }
    
    /**
     * the default version
     */
    public rsassapssparams()
    {
        hashalgorithm = default_hash_algorithm;
        maskgenalgorithm = default_mask_gen_function;
        saltlength = default_salt_length;
        trailerfield = default_trailer_field;
    }
    
    public rsassapssparams(
        algorithmidentifier hashalgorithm,
        algorithmidentifier maskgenalgorithm,
        asn1integer          saltlength,
        asn1integer          trailerfield)
    {
        this.hashalgorithm = hashalgorithm;
        this.maskgenalgorithm = maskgenalgorithm;
        this.saltlength = saltlength;
        this.trailerfield = trailerfield;
    }
    
    private rsassapssparams(
        asn1sequence seq)
    {
        hashalgorithm = default_hash_algorithm;
        maskgenalgorithm = default_mask_gen_function;
        saltlength = default_salt_length;
        trailerfield = default_trailer_field;
        
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
                saltlength = asn1integer.getinstance(o, true);
                break;
            case 3:
                trailerfield = asn1integer.getinstance(o, true);
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
    
    public biginteger getsaltlength()
    {
        return saltlength.getvalue();
    }
    
    public biginteger gettrailerfield()
    {
        return trailerfield.getvalue();
    }
    
    /**
     * <pre>
     * rsassa-pss-params ::= sequence {
     *   hashalgorithm      [0] oaep-pssdigestalgorithms  default sha1,
     *    maskgenalgorithm   [1] pkcs1mgfalgorithms  default mgf1sha1,
     *    saltlength         [2] integer  default 20,
     *    trailerfield       [3] trailerfield  default trailerfieldbc
     *  }
     *
     * oaep-pssdigestalgorithms    algorithm-identifier ::= {
     *    { oid id-sha1 parameters null   }|
     *    { oid id-sha256 parameters null }|
     *    { oid id-sha384 parameters null }|
     *    { oid id-sha512 parameters null },
     *    ...  -- allows for future expansion --
     * }
     *
     * pkcs1mgfalgorithms    algorithm-identifier ::= {
     *   { oid id-mgf1 parameters oaep-pssdigestalgorithms },
     *    ...  -- allows for future expansion --
     * }
     * 
     * trailerfield ::= integer { trailerfieldbc(1) }
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
        
        if (!saltlength.equals(default_salt_length))
        {
            v.add(new dertaggedobject(true, 2, saltlength));
        }
        
        if (!trailerfield.equals(default_trailer_field))
        {
            v.add(new dertaggedobject(true, 3, trailerfield));
        }
        
        return new dersequence(v);
    }
}
