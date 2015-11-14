package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.asn1taggedobjectparser;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * <pre>
 * encryptedcontentinfo ::= sequence {
 *     contenttype contenttype,
 *     contentencryptionalgorithm contentencryptionalgorithmidentifier,
 *     encryptedcontent [0] implicit encryptedcontent optional 
 * }
 * </pre>
 */
public class encryptedcontentinfoparser
{
    private asn1objectidentifier    _contenttype;
    private algorithmidentifier     _contentencryptionalgorithm;
    private asn1taggedobjectparser _encryptedcontent;

    public encryptedcontentinfoparser(
        asn1sequenceparser  seq) 
        throws ioexception
    {
        _contenttype = (asn1objectidentifier)seq.readobject();
        _contentencryptionalgorithm = algorithmidentifier.getinstance(seq.readobject().toasn1primitive());
        _encryptedcontent = (asn1taggedobjectparser)seq.readobject();
    }
    
    public asn1objectidentifier getcontenttype()
    {
        return _contenttype;
    }
    
    public algorithmidentifier getcontentencryptionalgorithm()
    {
        return _contentencryptionalgorithm;
    }

    public asn1encodable getencryptedcontent(
        int  tag) 
        throws ioexception
    {
        return _encryptedcontent.getobjectparser(tag, false);
    }
}
