package org.ripple.bouncycastle.asn1.x509.qualified;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.derprintablestring;

/**
 * the iso4217currencycode object.
 * <pre>
 * iso4217currencycode  ::=  choice {
 *       alphabetic              printablestring (size 3), --recommended
 *       numeric              integer (1..999) }
 * -- alphabetic or numeric currency code as defined in iso 4217
 * -- it is recommended that the alphabetic form is used
 * </pre>
 */
public class iso4217currencycode 
    extends asn1object
    implements asn1choice
{
    final int alphabetic_maxsize = 3;
    final int numeric_minsize = 1;
    final int numeric_maxsize = 999;
    
    asn1encodable obj;
    int          numeric;
    
    public static iso4217currencycode getinstance(
        object obj)
    {
        if (obj == null || obj instanceof iso4217currencycode)
        {
            return (iso4217currencycode)obj;
        }

        if (obj instanceof asn1integer)
        {
            asn1integer numericobj = asn1integer.getinstance(obj);
            int numeric = numericobj.getvalue().intvalue();  
            return new iso4217currencycode(numeric);            
        }
        else
        if (obj instanceof derprintablestring)
        {
            derprintablestring alphabetic = derprintablestring.getinstance(obj);
            return new iso4217currencycode(alphabetic.getstring());
        }
        throw new illegalargumentexception("unknown object in getinstance");
    }
            
    public iso4217currencycode(
        int numeric)
    {
        if (numeric > numeric_maxsize || numeric < numeric_minsize)
        {
            throw new illegalargumentexception("wrong size in numeric code : not in (" +numeric_minsize +".."+ numeric_maxsize +")");
        }
        obj = new asn1integer(numeric);
    }
    
    public iso4217currencycode(
        string alphabetic)
    {
        if (alphabetic.length() > alphabetic_maxsize)
        {
            throw new illegalargumentexception("wrong size in alphabetic code : max size is " + alphabetic_maxsize);
        }
        obj = new derprintablestring(alphabetic);
    }            

    public boolean isalphabetic()
    {
        return obj instanceof derprintablestring;
    }
    
    public string getalphabetic()
    {
        return ((derprintablestring)obj).getstring();
    }
    
    public int getnumeric()
    {
        return ((asn1integer)obj).getvalue().intvalue();
    }
    
    public asn1primitive toasn1primitive()
    {    
        return obj.toasn1primitive();
    }
}
