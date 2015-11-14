package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.asn1taggedobjectparser;

/**
 * produce an object suitable for an asn1outputstream.
 * <pre>
 * contentinfo ::= sequence {
 *          contenttype contenttype,
 *          content
 *          [0] explicit any defined by contenttype optional }
 * </pre>
 */
public class contentinfoparser
{
    private asn1objectidentifier contenttype;
    private asn1taggedobjectparser content;

    public contentinfoparser(
        asn1sequenceparser seq)
        throws ioexception
    {
        contenttype = (asn1objectidentifier)seq.readobject();
        content = (asn1taggedobjectparser)seq.readobject();
    }

    public asn1objectidentifier getcontenttype()
    {
        return contenttype;
    }

    public asn1encodable getcontent(
        int  tag)
        throws ioexception
    {
        if (content != null)
        {
            return content.getobjectparser(tag, true);
        }

        return null;
    }
}
