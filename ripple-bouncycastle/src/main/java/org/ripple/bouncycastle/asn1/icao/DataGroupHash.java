package org.ripple.bouncycastle.asn1.icao;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the datagrouphash object.
 * <pre>
 * datagrouphash  ::=  sequence {
 *      datagroupnumber         datagroupnumber,
 *      datagrouphashvalue     octet string }
 * 
 * datagroupnumber ::= integer {
 *         datagroup1    (1),
 *         datagroup1    (2),
 *         datagroup1    (3),
 *         datagroup1    (4),
 *         datagroup1    (5),
 *         datagroup1    (6),
 *         datagroup1    (7),
 *         datagroup1    (8),
 *         datagroup1    (9),
 *         datagroup1    (10),
 *         datagroup1    (11),
 *         datagroup1    (12),
 *         datagroup1    (13),
 *         datagroup1    (14),
 *         datagroup1    (15),
 *         datagroup1    (16) }
 * 
 * </pre>
 */
public class datagrouphash 
    extends asn1object
{
    asn1integer datagroupnumber;    
    asn1octetstring    datagrouphashvalue;
    
    public static datagrouphash getinstance(
        object obj)
    {
        if (obj instanceof datagrouphash)
        {
            return (datagrouphash)obj;
        }
        else if (obj != null)
        {
            return new datagrouphash(asn1sequence.getinstance(obj));
        }

        return null;
    }                
            
    private datagrouphash(asn1sequence seq)
    {
        enumeration e = seq.getobjects();

        // datagroupnumber
        datagroupnumber = asn1integer.getinstance(e.nextelement());
        // datagrouphashvalue
        datagrouphashvalue = asn1octetstring.getinstance(e.nextelement());   
    }
    
    public datagrouphash(
        int datagroupnumber,        
        asn1octetstring     datagrouphashvalue)
    {
        this.datagroupnumber = new asn1integer(datagroupnumber);
        this.datagrouphashvalue = datagrouphashvalue; 
    }    

    public int getdatagroupnumber()
    {
        return datagroupnumber.getvalue().intvalue();
    }
    
    public asn1octetstring getdatagrouphashvalue()
    {
        return datagrouphashvalue;
    }     
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        seq.add(datagroupnumber);
        seq.add(datagrouphashvalue);  

        return new dersequence(seq);
    }
}
