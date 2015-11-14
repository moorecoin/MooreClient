package org.ripple.bouncycastle.asn1.crmf;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

public class poposigningkeyinput
    extends asn1object
{
    private generalname sender;
    private pkmacvalue publickeymac;
    private subjectpublickeyinfo publickey;

    private poposigningkeyinput(asn1sequence seq)
    {
        asn1encodable authinfo = (asn1encodable)seq.getobjectat(0);

        if (authinfo instanceof asn1taggedobject)
        {
            asn1taggedobject tagobj = (asn1taggedobject)authinfo;
            if (tagobj.gettagno() != 0)
            {
                throw new illegalargumentexception(
                    "unknown authinfo tag: " + tagobj.gettagno());
            }
            sender = generalname.getinstance(tagobj.getobject());
        }
        else
        {
            publickeymac = pkmacvalue.getinstance(authinfo);
        }

        publickey = subjectpublickeyinfo.getinstance(seq.getobjectat(1));
    }

    public static poposigningkeyinput getinstance(object o)
    {
        if (o instanceof poposigningkeyinput)
        {
            return (poposigningkeyinput)o;
        }

        if (o != null)
        {
            return new poposigningkeyinput(asn1sequence.getinstance(o));
        }

        return null;
    }

    /**
     *  creates a new poposigningkeyinput with sender name as authinfo.
     */
    public poposigningkeyinput(
        generalname sender,
        subjectpublickeyinfo spki)
    {
        this.sender = sender;
        this.publickey = spki;
    }

    /**
     * creates a new poposigningkeyinput using password-based mac.
     */
    public poposigningkeyinput(
        pkmacvalue pkmac,
        subjectpublickeyinfo spki)
    {
        this.publickeymac = pkmac;
        this.publickey = spki;
    }

    /**
     * returns the sender field, or null if authinfo is publickeymac
     */
    public generalname getsender()
    {
        return sender;
    }

    /**
     * returns the publickeymac field, or null if authinfo is sender
     */
    public pkmacvalue getpublickeymac()
    {
        return publickeymac;
    }

    public subjectpublickeyinfo getpublickey()
    {
        return publickey;
    }

    /**
     * <pre>
     * poposigningkeyinput ::= sequence {
     *        authinfo             choice {
     *                                 sender              [0] generalname,
     *                                 -- used only if an authenticated identity has been
     *                                 -- established for the sender (e.g., a dn from a
     *                                 -- previously-issued and currently-valid certificate
     *                                 publickeymac        pkmacvalue },
     *                                 -- used if no authenticated generalname currently exists for
     *                                 -- the sender; publickeymac contains a password-based mac
     *                                 -- on the der-encoded value of publickey
     *        publickey           subjectpublickeyinfo }  -- from certtemplate
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        if (sender != null)
        {
            v.add(new dertaggedobject(false, 0, sender));
        }
        else
        {
            v.add(publickeymac);
        }

        v.add(publickey);

        return new dersequence(v);
    }
}
