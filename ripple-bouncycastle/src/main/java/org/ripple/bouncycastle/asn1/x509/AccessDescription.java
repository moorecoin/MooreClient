package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the accessdescription object.
 * <pre>
 * accessdescription  ::=  sequence {
 *       accessmethod          object identifier,
 *       accesslocation        generalname  }
 * </pre>
 */
public class accessdescription
    extends asn1object
{
    public final static asn1objectidentifier id_ad_caissuers = new asn1objectidentifier("1.3.6.1.5.5.7.48.2");
    
    public final static asn1objectidentifier id_ad_ocsp = new asn1objectidentifier("1.3.6.1.5.5.7.48.1");
        
    asn1objectidentifier accessmethod = null;
    generalname accesslocation = null;

    public static accessdescription getinstance(
        object  obj)
    {
        if (obj instanceof accessdescription)
        {
            return (accessdescription)obj;
        }
        else if (obj != null)
        {
            return new accessdescription(asn1sequence.getinstance(obj));
        }

        return null;
    }
 
    private accessdescription(
        asn1sequence   seq)
    {
        if (seq.size() != 2) 
        {
            throw new illegalargumentexception("wrong number of elements in sequence");
        }
        
        accessmethod = asn1objectidentifier.getinstance(seq.getobjectat(0));
        accesslocation = generalname.getinstance(seq.getobjectat(1));
    }

    /**
     * create an accessdescription with the oid and location provided.
     */
    public accessdescription(
        asn1objectidentifier oid,
        generalname location)
    {
        accessmethod = oid;
        accesslocation = location;
    }

    /**
     * 
     * @return the access method.
     */
    public asn1objectidentifier getaccessmethod()
    {
        return accessmethod;
    }
    
    /**
     * 
     * @return the access location
     */
    public generalname getaccesslocation()
    {
        return accesslocation;
    }
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector accessdescription  = new asn1encodablevector();
        
        accessdescription.add(accessmethod);
        accessdescription.add(accesslocation);

        return new dersequence(accessdescription);
    }

    public string tostring()
    {
        return ("accessdescription: oid(" + this.accessmethod.getid() + ")");
    }
}
