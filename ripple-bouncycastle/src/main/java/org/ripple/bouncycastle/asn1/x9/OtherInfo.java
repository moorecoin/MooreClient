package org.ripple.bouncycastle.asn1.x9;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;

/**
 * ans.1 def for diffie-hellman key exchange otherinfo structure. see
 * rfc 2631, or x9.42, for further details.
 */
public class otherinfo
    extends asn1object
{
    private keyspecificinfo     keyinfo;
    private asn1octetstring     partyainfo;
    private asn1octetstring     supppubinfo;

    public otherinfo(
        keyspecificinfo     keyinfo,
        asn1octetstring     partyainfo,
        asn1octetstring     supppubinfo)
    {
        this.keyinfo = keyinfo;
        this.partyainfo = partyainfo;
        this.supppubinfo = supppubinfo;
    }

    public otherinfo(
        asn1sequence  seq)
    {
        enumeration e = seq.getobjects();

        keyinfo = new keyspecificinfo((asn1sequence)e.nextelement());

        while (e.hasmoreelements())
        {
            dertaggedobject o = (dertaggedobject)e.nextelement();

            if (o.gettagno() == 0)
            {
                partyainfo = (asn1octetstring)o.getobject();
            }
            else if (o.gettagno() == 2)
            {
                supppubinfo = (asn1octetstring)o.getobject();
            }
        }
    }

    public keyspecificinfo getkeyinfo()
    {
        return keyinfo;
    }

    public asn1octetstring getpartyainfo()
    {
        return partyainfo;
    }

    public asn1octetstring getsupppubinfo()
    {
        return supppubinfo;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  otherinfo ::= sequence {
     *      keyinfo keyspecificinfo,
     *      partyainfo [0] octet string optional,
     *      supppubinfo [2] octet string
     *  }
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector  v = new asn1encodablevector();

        v.add(keyinfo);

        if (partyainfo != null)
        {
            v.add(new dertaggedobject(0, partyainfo));
        }

        v.add(new dertaggedobject(2, supppubinfo));

        return new dersequence(v);
    }
}
