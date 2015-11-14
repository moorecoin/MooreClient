package org.ripple.bouncycastle.asn1.pkcs;

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

/**
 * a pkcs#7 signer info object.
 */
public class signerinfo
    extends asn1object
{
    private asn1integer              version;
    private issuerandserialnumber   issuerandserialnumber;
    private algorithmidentifier     digalgorithm;
    private asn1set                 authenticatedattributes;
    private algorithmidentifier     digencryptionalgorithm;
    private asn1octetstring         encrypteddigest;
    private asn1set                 unauthenticatedattributes;

    public static signerinfo getinstance(
        object  o)
    {
        if (o instanceof signerinfo)
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
        asn1integer              version,
        issuerandserialnumber   issuerandserialnumber,
        algorithmidentifier     digalgorithm,
        asn1set                 authenticatedattributes,
        algorithmidentifier     digencryptionalgorithm,
        asn1octetstring         encrypteddigest,
        asn1set                 unauthenticatedattributes)
    {
        this.version = version;
        this.issuerandserialnumber = issuerandserialnumber;
        this.digalgorithm = digalgorithm;
        this.authenticatedattributes = authenticatedattributes;
        this.digencryptionalgorithm = digencryptionalgorithm;
        this.encrypteddigest = encrypteddigest;
        this.unauthenticatedattributes = unauthenticatedattributes;
    }

    public signerinfo(
        asn1sequence seq)
    {
        enumeration     e = seq.getobjects();

        version = (asn1integer)e.nextelement();
        issuerandserialnumber = issuerandserialnumber.getinstance(e.nextelement());
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

    public issuerandserialnumber getissuerandserialnumber()
    {
        return issuerandserialnumber;
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
     *      issuerandserialnumber issuerandserialnumber,
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
        v.add(issuerandserialnumber);
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
