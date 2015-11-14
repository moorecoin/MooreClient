package org.ripple.bouncycastle.asn1.cms;

import java.util.enumeration;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.dertaggedobject;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

public class signerinfo
    extends asn1object
{
    private asn1integer              version;
    private signeridentifier        sid;
    private algorithmidentifier     digalgorithm;
    private asn1set                 authenticatedattributes;
    private algorithmidentifier     digencryptionalgorithm;
    private asn1octetstring         encrypteddigest;
    private asn1set                 unauthenticatedattributes;

    public static signerinfo getinstance(
        object  o)
        throws illegalargumentexception
    {
        if (o == null || o instanceof signerinfo)
        {
            return (signerinfo)o;
        }
        else if (o instanceof asn1sequence)
        {
            return new signerinfo((asn1sequence)o);
        }

        throw new illegalargumentexception("unknown object in factory: " + o.getclass().getname());
    }

    public signerinfo(
        signeridentifier        sid,
        algorithmidentifier     digalgorithm,
        asn1set                 authenticatedattributes,
        algorithmidentifier     digencryptionalgorithm,
        asn1octetstring         encrypteddigest,
        asn1set                 unauthenticatedattributes)
    {
        if (sid.istagged())
        {
            this.version = new asn1integer(3);
        }
        else
        {
            this.version = new asn1integer(1);
        }

        this.sid = sid;
        this.digalgorithm = digalgorithm;
        this.authenticatedattributes = authenticatedattributes;
        this.digencryptionalgorithm = digencryptionalgorithm;
        this.encrypteddigest = encrypteddigest;
        this.unauthenticatedattributes = unauthenticatedattributes;
    }

    public signerinfo(
        signeridentifier        sid,
        algorithmidentifier     digalgorithm,
        attributes              authenticatedattributes,
        algorithmidentifier     digencryptionalgorithm,
        asn1octetstring         encrypteddigest,
        attributes              unauthenticatedattributes)
    {
        if (sid.istagged())
        {
            this.version = new asn1integer(3);
        }
        else
        {
            this.version = new asn1integer(1);
        }

        this.sid = sid;
        this.digalgorithm = digalgorithm;
        this.authenticatedattributes = asn1set.getinstance(authenticatedattributes);
        this.digencryptionalgorithm = digencryptionalgorithm;
        this.encrypteddigest = encrypteddigest;
        this.unauthenticatedattributes = asn1set.getinstance(unauthenticatedattributes);
    }

    /**
     * @deprecated use getinstance() method.
     */
    public signerinfo(
        asn1sequence seq)
    {
        enumeration     e = seq.getobjects();

        version = (asn1integer)e.nextelement();
        sid = signeridentifier.getinstance(e.nextelement());
        digalgorithm = algorithmidentifier.getinstance(e.nextelement());

        object obj = e.nextelement();

        if (obj instanceof asn1taggedobject)
        {
            authenticatedattributes = asn1set.getinstance((asn1taggedobject)obj, false);

            digencryptionalgorithm = algorithmidentifier.getinstance(e.nextelement());
        }
        else
        {
            authenticatedattributes = null;
            digencryptionalgorithm = algorithmidentifier.getinstance(obj);
        }

        encrypteddigest = deroctetstring.getinstance(e.nextelement());

        if (e.hasmoreelements())
        {
            unauthenticatedattributes = asn1set.getinstance((asn1taggedobject)e.nextelement(), false);
        }
        else
        {
            unauthenticatedattributes = null;
        }
    }

    public asn1integer getversion()
    {
        return version;
    }

    public signeridentifier getsid()
    {
        return sid;
    }

    public asn1set getauthenticatedattributes()
    {
        return authenticatedattributes;
    }

    public algorithmidentifier getdigestalgorithm()
    {
        return digalgorithm;
    }

    public asn1octetstring getencrypteddigest()
    {
        return encrypteddigest;
    }

    public algorithmidentifier getdigestencryptionalgorithm()
    {
        return digencryptionalgorithm;
    }

    public asn1set getunauthenticatedattributes()
    {
        return unauthenticatedattributes;
    }

    /**
     * produce an object suitable for an asn1outputstream.
     * <pre>
     *  signerinfo ::= sequence {
     *      version version,
     *      signeridentifier sid,
     *      digestalgorithm digestalgorithmidentifier,
     *      authenticatedattributes [0] implicit attributes optional,
     *      digestencryptionalgorithm digestencryptionalgorithmidentifier,
     *      encrypteddigest encrypteddigest,
     *      unauthenticatedattributes [1] implicit attributes optional
     *  }
     *
     *  encrypteddigest ::= octet string
     *
     *  digestalgorithmidentifier ::= algorithmidentifier
     *
     *  digestencryptionalgorithmidentifier ::= algorithmidentifier
     * </pre>
     */
    public asn1primitive toasn1primitive()
    {
        asn1encodablevector v = new asn1encodablevector();

        v.add(version);
        v.add(sid);
        v.add(digalgorithm);

        if (authenticatedattributes != null)
        {
            v.add(new dertaggedobject(false, 0, authenticatedattributes));
        }

        v.add(digencryptionalgorithm);
        v.add(encrypteddigest);

        if (unauthenticatedattributes != null)
        {
            v.add(new dertaggedobject(false, 1, unauthenticatedattributes));
        }

        return new dersequence(v);
    }
}
