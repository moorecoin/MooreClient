package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.asn1setparser;
import org.ripple.bouncycastle.asn1.asn1taggedobjectparser;
import org.ripple.bouncycastle.asn1.bertags;

/** 
 * <pre>
 * envelopeddata ::= sequence {
 *     version cmsversion,
 *     originatorinfo [0] implicit originatorinfo optional,
 *     recipientinfos recipientinfos,
 *     encryptedcontentinfo encryptedcontentinfo,
 *     unprotectedattrs [1] implicit unprotectedattributes optional 
 * }
 * </pre>
 */
public class envelopeddataparser
{
    private asn1sequenceparser _seq;
    private asn1integer        _version;
    private asn1encodable      _nextobject;
    private boolean            _originatorinfocalled;
    
    public envelopeddataparser(
        asn1sequenceparser seq)
        throws ioexception
    {
        this._seq = seq;
        this._version = asn1integer.getinstance(seq.readobject());
    }

    public asn1integer getversion()
    {
        return _version;
    }

    public originatorinfo getoriginatorinfo() 
        throws ioexception
    {
        _originatorinfocalled = true; 
        
        if (_nextobject == null)
        {
            _nextobject = _seq.readobject();
        }
        
        if (_nextobject instanceof asn1taggedobjectparser && ((asn1taggedobjectparser)_nextobject).gettagno() == 0)
        {
            asn1sequenceparser originatorinfo = (asn1sequenceparser) ((asn1taggedobjectparser)_nextobject).getobjectparser(bertags.sequence, false);
            _nextobject = null;
            return originatorinfo.getinstance(originatorinfo.toasn1primitive());
        }
        
        return null;
    }
    
    public asn1setparser getrecipientinfos()
        throws ioexception
    {
        if (!_originatorinfocalled)
        {
            getoriginatorinfo();
        }
        
        if (_nextobject == null)
        {
            _nextobject = _seq.readobject();
        }
        
        asn1setparser recipientinfos = (asn1setparser)_nextobject;
        _nextobject = null;
        return recipientinfos;
    }

    public encryptedcontentinfoparser getencryptedcontentinfo() 
        throws ioexception
    {
        if (_nextobject == null)
        {
            _nextobject = _seq.readobject();
        }
        
        
        if (_nextobject != null)
        {
            asn1sequenceparser o = (asn1sequenceparser) _nextobject;
            _nextobject = null;
            return new encryptedcontentinfoparser(o);
        }
        
        return null;
    }

    public asn1setparser getunprotectedattrs()
        throws ioexception
    {
        if (_nextobject == null)
        {
            _nextobject = _seq.readobject();
        }
        
        
        if (_nextobject != null)
        {
            asn1encodable o = _nextobject;
            _nextobject = null;
            return (asn1setparser)((asn1taggedobjectparser)o).getobjectparser(bertags.set, false);
        }
        
        return null;
    }
}
