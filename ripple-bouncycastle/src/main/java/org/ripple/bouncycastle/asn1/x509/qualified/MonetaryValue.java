package org.ripple.bouncycastle.asn1.x509.qualified;

import java.math.biginteger;
import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;

/**
 * the monetaryvalue object.
 * <pre>
 * monetaryvalue  ::=  sequence {
 *       currency              iso4217currencycode,
 *       amount               integer, 
 *       exponent             integer }
 * -- value = amount * 10^exponent
 * </pre>
 */
public class monetaryvalue 
    extends asn1object
{
    private iso4217currencycode currency;
    private asn1integer         amount;
    private asn1integer         exponent;
        
    public static monetaryvalue getinstance(
        object obj)
    {
        if (obj instanceof monetaryvalue)
        {
            return (monetaryvalue)obj;
        }

        if (obj != null)
        {
            return new monetaryvalue(asn1sequence.getinstance(obj));            
        }
        
        return null;
    }
        
    private monetaryvalue(
        asn1sequence seq)
    {
        enumeration e = seq.getobjects();    
        // currency
        currency = iso4217currencycode.getinstance(e.nextelement());
        // hashalgorithm
        amount = asn1integer.getinstance(e.nextelement());
        // exponent
        exponent = asn1integer.getinstance(e.nextelement());            
    }
        
    public monetaryvalue(
        iso4217currencycode currency, 
        int                 amount, 
        int                 exponent)
    {    
        this.currency = currency;
        this.amount = new asn1integer(amount);
        this.exponent = new asn1integer(exponent);
    }                    
             
    public iso4217currencycode getcurrency()
    {
        return currency;
    }
        
    public biginteger getamount()
    {
        return amount.getvalue();
    }
        
    public biginteger getexponent()
    {
        return exponent.getvalue();
    }   
    
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector seq = new asn1encodablevector();
        seq.add(currency);
        seq.add(amount);
        seq.add(exponent); 
        
        return new dersequence(seq);
    }
}
