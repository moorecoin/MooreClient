package org.ripple.bouncycastle.asn1.x500;

import org.ripple.bouncycastle.asn1.asn1choice;
import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.derbmpstring;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dert61string;
import org.ripple.bouncycastle.asn1.derutf8string;
import org.ripple.bouncycastle.asn1.deruniversalstring;

public class directorystring
    extends asn1object
    implements asn1choice, asn1string
{
    private asn1string string;

    public static directorystring getinstance(object o)
    {
        if (o == null || o instanceof directorystring)
        {
            return (directorystring)o;
        }

        if (o instanceof dert61string)
        {
            return new directorystring((dert61string)o);
        }

        if (o instanceof derprintablestring)
        {
            return new directorystring((derprintablestring)o);
        }

        if (o instanceof deruniversalstring)
        {
            return new directorystring((deruniversalstring)o);
        }

        if (o instanceof derutf8string)
        {
            return new directorystring((derutf8string)o);
        }

        if (o instanceof derbmpstring)
        {
            return new directorystring((derbmpstring)o);
        }

        throw new illegalargumentexception("illegal object in getinstance: " + o.getclass().getname());
    }

    public static directorystring getinstance(asn1taggedobject o, boolean explicit)
    {
        if (!explicit)
        {
            throw new illegalargumentexception("choice item must be explicitly tagged");
        }

        return getinstance(o.getobject());
    }

    private directorystring(
        dert61string string)
    {
        this.string = string;
    }

    private directorystring(
        derprintablestring string)
    {
        this.string = string;
    }

    private directorystring(
        deruniversalstring string)
    {
        this.string = string;
    }

    private directorystring(
        derutf8string string)
    {
        this.string = string;
    }

    private directorystring(
        derbmpstring string)
    {
        this.string = string;
    }

    public directorystring(string string)
    {
        this.string = new derutf8string(string);
    }

    public string getstring()
    {
        return string.getstring();
    }

    public string tostring()
    {
        return string.getstring();
    }

    /**
     * <pre>
     *  directorystring ::= choice {
     *    teletexstring               teletexstring (size (1..max)),
     *    printablestring             printablestring (size (1..max)),
     *    universalstring             universalstring (size (1..max)),
     *    utf8string                  utf8string (size (1..max)),
     *    bmpstring                   bmpstring (size (1..max))  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        return ((asn1encodable)string).toasn1primitive();
    }
}
