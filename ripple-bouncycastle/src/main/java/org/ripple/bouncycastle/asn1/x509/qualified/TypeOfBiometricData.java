package org.ripple.bouncycastle.asn1.x509.qualified;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;

/**
 * the typeofbiometricdata object.
 * <pre>
 * typeofbiometricdata ::= choice {
 *   predefinedbiometrictype   predefinedbiometrictype,
 *   biometricdataoid          object identifier }
 *
 * predefinedbiometrictype ::= integer {
 *   picture(0),handwritten-signature(1)}
 *   (picture|handwritten-signature)
 * </pre>
 */
public class typeofbiometricdata  
    extends asn1object
    implements asn1choice
{
    public static final int picture                     = 0;
    public static final int handwritten_signature       = 1;

    asn1encodable      obj;

    public static typeofbiometricdata getinstance(object obj)
    {
        if (obj == null || obj instanceof typeofbiometricdata)
        {
            return (typeofbiometricdata)obj;
        }

        if (obj instanceof asn1integer)
        {
            asn1integer predefinedbiometrictypeobj = asn1integer.getinstance(obj);
            int  predefinedbiometrictype = predefinedbiometrictypeobj.getvalue().intvalue();

            return new typeofbiometricdata(predefinedbiometrictype);
        }
        else if (obj instanceof asn1objectidentifier)
        {
            asn1objectidentifier biometricdataid = asn1objectidentifier.getinstance(obj);
            return new typeofbiometricdata(biometricdataid);
        }

        throw new illegalargumentexception("unknown object in getinstance");
    }
        
    public typeofbiometricdata(int predefinedbiometrictype)
    {
        if (predefinedbiometrictype == picture || predefinedbiometrictype == handwritten_signature)
        {
                obj = new asn1integer(predefinedbiometrictype);
        }
        else
        {
            throw new illegalargumentexception("unknow predefinedbiometrictype : " + predefinedbiometrictype);
        }        
    }
    
    public typeofbiometricdata(asn1objectidentifier biometricdataid)
    {
        obj = biometricdataid;
    }
    
    public boolean ispredefined()
    {
        return obj instanceof asn1integer;
    }
    
    public int getpredefinedbiometrictype()
    {
        return ((asn1integer)obj).getvalue().intvalue();
    }
    
    public asn1objectidentifier getbiometricdataoid()
    {
        return (asn1objectidentifier)obj;
    }
    
    public asn1primitive toasn1primitive()
    {        
        return obj.toasn1primitive();
    }
}
