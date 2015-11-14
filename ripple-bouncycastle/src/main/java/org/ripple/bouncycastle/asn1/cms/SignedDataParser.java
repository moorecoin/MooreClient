package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.asn1set;
import org.ripple.bouncycastle.asn1.asn1setparser;
import org.ripple.bouncycastle.asn1.asn1taggedobjectparser;
import org.ripple.bouncycastle.asn1.bertags;

/**
 * <pre>
 * signeddata ::= sequence {
 *     version cmsversion,
 *     digestalgorithms digestalgorithmidentifiers,
 *     encapcontentinfo encapsulatedcontentinfo,
 *     certificates [0] implicit certificateset optional,
 *     crls [1] implicit certificaterevocationlists optional,
 *     signerinfos signerinfos
 *   }
 * </pre>
 */
public class signeddataparser
{
    private asn1sequenceparser _seq;
    private asn1integer         _version;
    private object             _nextobject;
    private boolean            _certscalled;
    private boolean            _crlscalled;

    public static signeddataparser getinstance(
        object o)
        throws ioexception
    {
        if (o instanceof asn1sequence)
        {
            return new signeddataparser(((asn1sequence)o).parser());
        }
        if (o instanceof asn1sequenceparser)
        {
            return new signeddataparser((asn1sequenceparser)o);
        }

        throw new ioexception("unknown object encountered: " + o.getclass().getname());
    }

    private signeddataparser(
        asn1sequenceparser seq)
        throws ioexception
    {
        this._seq = seq;
        this._version = (asn1integer)seq.readobject();
    }

    public asn1integer getversion()
    {
        return _version;
    }

    public asn1setparser getdigestalgorithms()
        throws ioexception
    {
        object o = _seq.readobject();

        if (o instanceof asn1set)
        {
            return ((asn1set)o).parser();
        }

        return (asn1setparser)o;
    }

    public contentinfoparser getencapcontentinfo()
        throws ioexception
    {
        return new contentinfoparser((asn1sequenceparser)_seq.readobject());
    }

    public asn1setparser getcertificates()
        throws ioexception
    {
        _certscalled = true;
        _nextobject = _seq.readobject();

        if (_nextobject instanceof asn1taggedobjectparser && ((asn1taggedobjectparser)_nextobject).gettagno() == 0)
        {
            asn1setparser certs = (asn1setparser)((asn1taggedobjectparser)_nextobject).getobjectparser(bertags.set, false);
            _nextobject = null;

            return certs;
        }

        return null;
    }

    public asn1setparser getcrls()
        throws ioexception
    {
        if (!_certscalled)
        {
            throw new ioexception("getcerts() has not been called.");
        }

        _crlscalled = true;

        if (_nextobject == null)
        {
            _nextobject = _seq.readobject();
        }

        if (_nextobject instanceof asn1taggedobjectparser && ((asn1taggedobjectparser)_nextobject).gettagno() == 1)
        {
            asn1setparser crls = (asn1setparser)((asn1taggedobjectparser)_nextobject).getobjectparser(bertags.set, false);
            _nextobject = null;

            return crls;
        }

        return null;
    }

    public asn1setparser getsignerinfos()
        throws ioexception
    {
        if (!_certscalled || !_crlscalled)
        {
            throw new ioexception("getcerts() and/or getcrls() has not been called.");
        }

        if (_nextobject == null)
        {
            _nextobject = _seq.readobject();
        }

        return (asn1setparser)_nextobject;
    }
}
