package org.ripple.bouncycastle.crypto.engines;

/**
 * an implementation of the aes key wrapper from the nist key wrap
 * specification.
 * <p>
 * for further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
 */
public class aeswrapengine
    extends rfc3394wrapengine
{
    public aeswrapengine()
    {
        super(new aesengine());
    }
}
