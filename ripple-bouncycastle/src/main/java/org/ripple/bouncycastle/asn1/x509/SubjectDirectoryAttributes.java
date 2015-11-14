package org.ripple.bouncycastle.asn1.x509;

import java.util.enumeration;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * this extension may contain further x.500 attributes of the subject. see also
 * rfc 3039.
 * 
 * <pre>
 *     subjectdirectoryattributes ::= attributes
 *     attributes ::= sequence size (1..max) of attribute
 *     attribute ::= sequence 
 *     {
 *       type attributetype 
 *       values set of attributevalue 
 *     }
 *     
 *     attributetype ::= object identifier
 *     attributevalue ::= any defined by attributetype
 * </pre>
 * 
 * @see org.ripple.bouncycastle.asn1.x500.style.bcstyle for attributetype objectidentifiers.
 */
public class subjectdirectoryattributes 
    extends asn1object
{
    private vector attributes = new vector();

    public static subjectdirectoryattributes getinstance(
        object obj)
    {
        if (obj instanceof subjectdirectoryattributes)
        {
            return (subjectdirectoryattributes)obj;
        }

        if (obj != null)
        {
            return new subjectdirectoryattributes(asn1sequence.getinstance(obj));
        }

        return null;
    }

    /**
     * constructor from asn1sequence.
     * 
     * the sequence is of type subjectdirectoryattributes:
     * 
     * <pre>
     *      subjectdirectoryattributes ::= attributes
     *      attributes ::= sequence size (1..max) of attribute
     *      attribute ::= sequence 
     *      {
     *        type attributetype 
     *        values set of attributevalue 
     *      }
     *      
     *      attributetype ::= object identifier
     *      attributevalue ::= any defined by attributetype
     * </pre>
     * 
     * @param seq
     *            the asn.1 sequence.
     */
    private subjectdirectoryattributes(asn1sequence seq)
    {
        enumeration e = seq.getobjects();

        while (e.hasmoreelements())
        {
            asn1sequence s = asn1sequence.getinstance(e.nextelement());
            attributes.addelement(attribute.getinstance(s));
        }
    }

    /**
     * constructor from a vector of attributes.
     * 
     * the vector consists of attributes of type {@link attribute attribute}
     * 
     * @param attributes
     *            the attributes.
     * 
     */
    public subjectdirectoryattributes(vector attributes)
    {
        enumeration e = attributes.elements();

        while (e.hasmoreelements())
        {
            this.attributes.addelement(e.nextelement());
        }
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * 
     * returns:
     * 
     * <pre>
     *      subjectdirectoryattributes ::= attributes
     *      attributes ::= sequence size (1..max) of attribute
     *      attribute ::= sequence 
     *      {
     *        type attributetype 
     *        values set of attributevalue 
     *      }
     *      
     *      attributetype ::= object identifier
     *      attributevalue ::= any defined by attributetype
     * </pre>
     * 
     * @return a asn1primitive
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector vec = new asn1encodablevector();
        enumeration e = attributes.elements();

        while (e.hasmoreelements())
        {

            vec.add((attribute)e.nextelement());
        }

        return new dersequence(vec);
    }

    /**
     * @return returns the attributes.
     */
    public vector getattributes()
    {
        return attributes;
    }
}
