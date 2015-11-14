package org.ripple.bouncycastle.asn1.x509;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the authorityinformationaccess object.
 * <pre>
 * id-pe-authorityinfoaccess object identifier ::= { id-pe 1 }
 *
 * authorityinfoaccesssyntax  ::=
 *      sequence size (1..max) of accessdescription
 * accessdescription  ::=  sequence {
 *       accessmethod          object identifier,
 *       accesslocation        generalname  }
 *
 * id-ad object identifier ::= { id-pkix 48 }
 * id-ad-caissuers object identifier ::= { id-ad 2 }
 * id-ad-ocsp object identifier ::= { id-ad 1 }
 * </pre>
 */
public class authorityinformationaccess
    extends asn1object
{
    private accessdescription[]    descriptions;

    public static authorityinformationaccess getinstance(
        object  obj)
    {
        if (obj instanceof authorityinformationaccess)
        {
            return (authorityinformationaccess)obj;
        }

        if (obj != null)
        {
            return new authorityinformationaccess(asn1sequence.getinstance(obj));
        }

        return null;
    }
 
    private authorityinformationaccess(
        asn1sequence   seq)
    {
        if (seq.size() < 1) 
        {
            throw new illegalargumentexception("sequence may not be empty");
        }

        descriptions = new accessdescription[seq.size()];
        
        for (int i = 0; i != seq.size(); i++)
        {
            descriptions[i] = accessdescription.getinstance(seq.getobjectat(i));
        }
    }

    /**
     * create an authorityinformationaccess with the oid and location provided.
     */
    public authorityinformationaccess(
        asn1objectidentifier oid,
        generalname location)
    {
        descriptions = new accessdescription[1];
        
        descriptions[0] = new accessdescription(oid, location);
    }


    /**
     * 
     * @return the access descriptions contained in this object.
     */
    public accessdescription[] getaccessdescriptions()
    {
        return descriptions;
    }
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        
        for (int i = 0; i != descriptions.length; i++)
        {
            vec.add(descriptions[i]);
        }
        
        return new dersequence(vec);
    }

    public string tostring()
    {
        return ("authorityinformationaccess: oid(" + this.descriptions[0].getaccessmethod().getid() + ")");
    }
}
