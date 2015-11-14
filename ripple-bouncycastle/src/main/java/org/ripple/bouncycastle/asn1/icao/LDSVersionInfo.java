package org.ripple.bouncycastle.asn1.icao;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.derprintablestring;
import org.ripple.bouncycastle.asn1.dersequence;

public class ldsversioninfo
    extends asn1object
{
    private derprintablestring ldsversion;
    private derprintablestring unicodeversion;

    public ldsversioninfo(string ldsversion, string unicodeversion)
    {
        this.ldsversion = new derprintablestring(ldsversion);
        this.unicodeversion = new derprintablestring(unicodeversion);
    }

    private ldsversioninfo(asn1sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new illegalargumentexception("sequence wrong size for ldsversioninfo");
        }

        this.ldsversion = derprintablestring.getinstance(seq.getobjectat(0));
        this.unicodeversion = derprintablestring.getinstance(seq.getobjectat(1));
    }

    public static ldsversioninfo getinstance(object obj)
    {
        if (obj instanceof ldsversioninfo)
        {
            return (ldsversioninfo)obj;
        }
        else if (obj != null)
        {
            return new ldsversioninfo(asn1sequence.getinstance(obj));
        }

        return null;
    }

    public string getldsversion()
    {
        return ldsversion.getstring();
    }

    public string getunicodeversion()
    {
        return unicodeversion.getstring();
    }

    /**
     * <pre>
     * ldsversioninfo ::= sequence {
     *    ldsversion printable string
     *    unicodeversion printable string
     *  }
     * </pre>
     * @return
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(ldsversion);
        v.add(unicodeversion);

        return new dersequence(v);
    }
}
