package org.ripple.bouncycastle.jcajce.provider.util;

import java.io.ioexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;

public interface asymmetrickeyinfoconverter
{
    privatekey generateprivate(privatekeyinfo keyinfo)
        throws ioexception;

    publickey generatepublic(subjectpublickeyinfo keyinfo)
        throws ioexception;
}
