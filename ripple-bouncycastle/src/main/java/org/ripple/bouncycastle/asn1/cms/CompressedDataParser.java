package org.ripple.bouncycastle.asn1.cms;

import java.io.ioexception;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1sequenceparser;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;

/**
 * rfc 3274 - cms compressed data.
 * <pre>
 * compresseddata ::= sequence {
 *  version cmsversion,
 *  compressionalgorithm compressionalgorithmidentifier,
 *  encapcontentinfo encapsulatedcontentinfo
 * }
 * </pre>
 */
public class compresseddataparser
{
    private asn1integer _version;
    private algorithmidentifier _compressionalgorithm;
    private contentinfoparser _encapcontentinfo;

    public compresseddataparser(
        asn1sequenceparser seq)
        throws ioexception
    {
        this._version = (asn1integer)seq.readobject();
        this._compressionalgorithm = algorithmidentifier.getinstance(seq.readobject().toasn1primitive());
        this._encapcontentinfo = new contentinfoparser((asn1sequenceparser)seq.readobject());
    }

    public asn1integer getversion()
    {
        return _version;
    }

    public algorithmidentifier getcompressionalgorithmidentifier()
    {
        return _compressionalgorithm;
    }

    public contentinfoparser getencapcontentinfo()
    {
        return _encapcontentinfo;
    }
}
