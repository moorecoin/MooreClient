package org.ripple.bouncycastle.asn1.cmp;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.crmf.encryptedvalue;
import org.ripple.bouncycastle.asn1.crmf.pkipublicationinfo;

public class certifiedkeypair
    extends asn1object
{
    private certorenccert certorenccert;
    private encryptedvalue privatekey;
    private pkipublicationinfo  publicationinfo;

    private certifiedkeypair(asn1sequence seq)
    {
        certorenccert = certorenccert.getinstance(seq.getobjectat(0));

        if (seq.size() >= 2)
        {
            if (seq.size() == 2)
            {
                asn1taggedobject tagged = asn1taggedobject.getinstance(seq.getobjectat(1));
                if (tagged.gettagno() == 0)
                {
                    privatekey = encryptedvalue.getinstance(tagged.getobject());
                }
                else
                {
                    publicationinfo = pkipublicationinfo.getinstance(tagged.getobject());
                }
            }
            else
            {
                privatekey = encryptedvalue.getinstance(asn1taggedobject.getinstance(seq.getobjectat(1)));
                publicationinfo = pkipublicationinfo.getinstance(asn1taggedobject.getinstance(seq.getobjectat(2)));
            }
        }
    }

    public static certifiedkeypair getinstance(object o)
    {
        if (o instanceof certifiedkeypair)
        {
            return (certifiedkeypair)o;
        }

        if (o != null)
        {
            return new certifiedkeypair(asn1sequence.getinstance(o));
        }

        return null;
    }

    public certifiedkeypair(
        certorenccert certorenccert)
    {
        this(certorenccert, null, null);
    }

    public certifiedkeypair(
        certorenccert certorenccert,
        encryptedvalue privatekey,
        pkipublicationinfo  publicationinfo
        )
    {
        if (certorenccert == null)
        {
            throw new illegalargumentexception("'certorenccert' cannot be null");
        }

        this.certorenccert = certorenccert;
        this.privatekey = privatekey;
        this.publicationinfo = publicationinfo;
    }

    public certorenccert getcertorenccert()
    {
        return certorenccert;
    }

    public encryptedvalue getprivatekey()
    {
        return privatekey;
    }

    public pkipublicationinfo getpublicationinfo()
    {
        return publicationinfo;
    }

    /**
     * <pre>
     * certifiedkeypair ::= sequence {
     *                                  certorenccert       certorenccert,
     *                                  privatekey      [0] encryptedvalue      optional,
     *                                  -- see [crmf] for comment on encoding
     *                                  publicationinfo [1] pkipublicationinfo  optional
     *       }
     * </pre>
     * @return a basic asn.1 object representation.
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(certorenccert);

        if (privatekey != null)
        {
            v.add(new dertaggedobject(true, 0, privatekey));
        }

        if (publicationinfo != null)
        {
            v.add(new dertaggedobject(true, 1, publicationinfo));
        }

        return new dersequence(v);
    }
}
