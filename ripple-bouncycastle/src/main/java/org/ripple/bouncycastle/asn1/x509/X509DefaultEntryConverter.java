package org.ripple.bouncycastle.asn1.x509;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.dergeneralizedtime;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.derutf8string;

/**
 * the default converter for x509 dn entries when going from their
 * string value to asn.1 strings.
 */
public class x509defaultentryconverter
    extends x509nameentryconverter
{
    /**
     * apply default coversion for the given value depending on the oid
     * and the character range of the value.
     * 
     * @param oid the object identifier for the dn entry
     * @param value the value associated with it
     * @return the asn.1 equivalent for the string value.
     */
    public asn1primitive getconvertedvalue(
        asn1objectidentifier  oid,
        string               value)
    {
        if (value.length() != 0 && value.charat(0) == '#')
        {
            try
            {
                return converthexencoded(value, 1);
            }
            catch (ioexception e)
            {
                throw new runtimeexception("can't recode value for oid " + oid.getid());
            }
        }
        else
        {
            if (value.length() != 0 && value.charat(0) == '\\')
            {
                value = value.substring(1);
            }
            if (oid.equals(x509name.emailaddress) || oid.equals(x509name.dc))
            {
                return new deria5string(value);
            }
            else if (oid.equals(x509name.date_of_birth))  // accept time string as well as # (for compatibility)
            {
                return new dergeneralizedtime(value);
            }
            else if (oid.equals(x509name.c) || oid.equals(x509name.sn) || oid.equals(x509name.dn_qualifier)
                || oid.equals(x509name.telephone_number))
            {
                 return new derprintablestring(value);
            }
        }
        
        return new derutf8string(value);
    }
}
