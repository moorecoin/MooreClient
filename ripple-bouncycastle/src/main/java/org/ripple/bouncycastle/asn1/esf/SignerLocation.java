package org.ripple.bouncycastle.asn1.esf;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.x500.directorystring;

/**
 * signer-location attribute (rfc3126).
 * 
 * <pre>
 *   signerlocation ::= sequence {
 *       countryname        [0] directorystring optional,
 *       localityname       [1] directorystring optional,
 *       postaladdress      [2] postaladdress optional }
 *
 *   postaladdress ::= sequence size(1..6) of directorystring
 * </pre>
 */
public class signerlocation
    extends asn1object
{
    private derutf8string   countryname;
    private derutf8string   localityname;
    private asn1sequence    postaladdress;
    
    private signerlocation(
        asn1sequence seq)
    {
        enumeration     e = seq.getobjects();

        while (e.hasmoreelements())
        {
            dertaggedobject o = (dertaggedobject)e.nextelement();

            switch (o.gettagno())
            {
            case 0:
                directorystring countrynamedirectorystring = directorystring.getinstance(o, true);
                this.countryname = new derutf8string(countrynamedirectorystring.getstring());
                break;
            case 1:
                directorystring localitynamedirectorystring = directorystring.getinstance(o, true);
                this.localityname = new derutf8string(localitynamedirectorystring.getstring());
                break;
            case 2:
                if (o.isexplicit())
                {
                    this.postaladdress = asn1sequence.getinstance(o, true);
                }
                else    // handle erroneous implicitly tagged sequences
                {
                    this.postaladdress = asn1sequence.getinstance(o, false);
                }
                if (postaladdress != null && postaladdress.size() > 6)
                {
                    throw new illegalargumentexception("postal address must contain less than 6 strings");
                }
                break;
            default:
                throw new illegalargumentexception("illegal tag");
            }
        }
    }

    public signerlocation(
        derutf8string   countryname,
        derutf8string   localityname,
        asn1sequence    postaladdress)
    {
        if (postaladdress != null && postaladdress.size() > 6)
        {
            throw new illegalargumentexception("postal address must contain less than 6 strings");
        }

        if (countryname != null)
        {
            this.countryname = derutf8string.getinstance(countryname.toasn1primitive());
        }

        if (localityname != null)
        {
            this.localityname = derutf8string.getinstance(localityname.toasn1primitive());
        }

        if (postaladdress != null)
        {
            this.postaladdress = asn1sequence.getinstance(postaladdress.toasn1primitive());
        }
    }

    public static signerlocation getinstance(
        object obj)
    {
        if (obj == null || obj instanceof signerlocation)
        {
            return (signerlocation)obj;
        }

        return new signerlocation(asn1sequence.getinstance(obj));
    }

    public derutf8string getcountryname()
    {
        return countryname;
    }

    public derutf8string getlocalityname()
    {
        return localityname;
    }

    public asn1sequence getpostaladdress()
    {
        return postaladdress;
    }

    /**
     * <pre>
     *   signerlocation ::= sequence {
     *       countryname        [0] directorystring optional,
     *       localityname       [1] directorystring optional,
     *       postaladdress      [2] postaladdress optional }
     *
     *   postaladdress ::= sequence size(1..6) of directorystring
     *   
     *   directorystring ::= choice {
     *         teletexstring           teletexstring (size (1..max)),
     *         printablestring         printablestring (size (1..max)),
     *         universalstring         universalstring (size (1..max)),
     *         utf8string              utf8string (size (1.. max)),
     *         bmpstring               bmpstring (size (1..max)) }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        if (countryname != null)
        {
            v.add(new dertaggedobject(true, 0, countryname));
        }

        if (localityname != null)
        {
            v.add(new dertaggedobject(true, 1, localityname));
        }

        if (postaladdress != null)
        {
            v.add(new dertaggedobject(true, 2, postaladdress));
        }

        return new dersequence(v);
    }
}
