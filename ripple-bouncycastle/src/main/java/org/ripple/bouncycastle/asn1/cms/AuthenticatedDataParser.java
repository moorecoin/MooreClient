package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.asn1setparser;
import org.ripple.bouncycastle.asn1.asn1taggedobject;
import org.ripple.bouncycastle.asn1.asn1taggedobjectparser;
import org.ripple.bouncycastle.asn1.bertags;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * produce an object suitable for an asn1outputstream.
 * <pre>
 * authenticateddata ::= sequence {
 *       version cmsversion,
 *       originatorinfo [0] implicit originatorinfo optional,
 *       recipientinfos recipientinfos,
 *       macalgorithm messageauthenticationcodealgorithm,
 *       digestalgorithm [1] digestalgorithmidentifier optional,
 *       encapcontentinfo encapsulatedcontentinfo,
 *       authattrs [2] implicit authattributes optional,
 *       mac messageauthenticationcode,
 *       unauthattrs [3] implicit unauthattributes optional }
 *
 * authattributes ::= set size (1..max) of attribute
 *
 * unauthattributes ::= set size (1..max) of attribute
 *
 * messageauthenticationcode ::= octet string
 * </pre>
 */
public class authenticateddataparser
{
    private asn1sequenceparser seq;
    private asn1integer version;
    private asn1encodable nextobject;
    private boolean originatorinfocalled;

    public authenticateddataparser(
        asn1sequenceparser seq)
        throws ioexception
    {
        this.seq = seq;
        this.version = asn1integer.getinstance(seq.readobject());
    }

    public asn1integer getversion()
    {
        return version;
    }

    public originatorinfo getoriginatorinfo()
        throws ioexception
    {
        originatorinfocalled = true;

        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        if (nextobject instanceof asn1taggedobjectparser && ((asn1taggedobjectparser)nextobject).gettagno() == 0)
        {
            asn1sequenceparser originatorinfo = (asn1sequenceparser) ((asn1taggedobjectparser)nextobject).getobjectparser(bertags.sequence, false);
            nextobject = null;
            return originatorinfo.getinstance(originatorinfo.toasn1primitive());
        }

        return null;
    }

    public asn1setparser getrecipientinfos()
        throws ioexception
    {
        if (!originatorinfocalled)
        {
            getoriginatorinfo();
        }

        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        asn1setparser recipientinfos = (asn1setparser)nextobject;
        nextobject = null;
        return recipientinfos;
    }

    public algorithmidentifier getmacalgorithm()
        throws ioexception
    {
        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        if (nextobject != null)
        {
            asn1sequenceparser o = (asn1sequenceparser)nextobject;
            nextobject = null;
            return algorithmidentifier.getinstance(o.toasn1primitive());
        }

        return null;
    }

    public algorithmidentifier getdigestalgorithm()
        throws ioexception
    {
        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        if (nextobject instanceof asn1taggedobjectparser)
        {
            algorithmidentifier obj = algorithmidentifier.getinstance((asn1taggedobject)nextobject.toasn1primitive(), false);
            nextobject = null;
            return obj;
        }

        return null;
    }

    public contentinfoparser getenapsulatedcontentinfo()
        throws ioexception
    {
        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        if (nextobject != null)
        {
            asn1sequenceparser o = (asn1sequenceparser)nextobject;
            nextobject = null;
            return new contentinfoparser(o);
        }

        return null;
    }

    public asn1setparser getauthattrs()
        throws ioexception
    {
        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        if (nextobject instanceof asn1taggedobjectparser)
        {
            asn1encodable o = nextobject;
            nextobject = null;
            return (asn1setparser)((asn1taggedobjectparser)o).getobjectparser(bertags.set, false);
        }

        return null;
    }

    public asn1octetstring getmac()
        throws ioexception
    {
        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        asn1encodable o = nextobject;
        nextobject = null;

        return asn1octetstring.getinstance(o.toasn1primitive());
    }

    public asn1setparser getunauthattrs()
        throws ioexception
    {
        if (nextobject == null)
        {
            nextobject = seq.readobject();
        }

        if (nextobject != null)
        {
            asn1encodable o = nextobject;
            nextobject = null;
            return (asn1setparser)((asn1taggedobjectparser)o).getobjectparser(bertags.set, false);
        }

        return null;
    }
}
