package org.ripple.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.ioexception;
import java.math.biginteger;
import java.security.invalidkeyexception;
import java.security.privatekey;
import java.security.publickey;

import org.ripple.bouncycastle.asn1.asn1encodablevector;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.dsa;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.nulldigest;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.signers.ecdsasigner;
import org.ripple.bouncycastle.crypto.signers.ecnrsigner;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.dsabase;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.dsaencoder;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.ecutil;

public class signaturespi
    extends dsabase
{
    signaturespi(digest digest, dsa signer, dsaencoder encoder)
    {
        super(digest, signer, encoder);
    }

    protected void engineinitverify(publickey publickey)
        throws invalidkeyexception
    {
        cipherparameters param = ecutil.generatepublickeyparameter(publickey);

        digest.reset();
        signer.init(false, param);
    }

    protected void engineinitsign(
        privatekey privatekey)
        throws invalidkeyexception
    {
        cipherparameters param = ecutil.generateprivatekeyparameter(privatekey);

        digest.reset();

        if (apprandom != null)
        {
            signer.init(true, new parameterswithrandom(param, apprandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    static public class ecdsa
        extends signaturespi
    {
        public ecdsa()
        {
            super(new sha1digest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecdsanone
        extends signaturespi
    {
        public ecdsanone()
        {
            super(new nulldigest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecdsa224
        extends signaturespi
    {
        public ecdsa224()
        {
            super(new sha224digest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecdsa256
        extends signaturespi
    {
        public ecdsa256()
        {
            super(new sha256digest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecdsa384
        extends signaturespi
    {
        public ecdsa384()
        {
            super(new sha384digest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecdsa512
        extends signaturespi
    {
        public ecdsa512()
        {
            super(new sha512digest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecdsaripemd160
        extends signaturespi
    {
        public ecdsaripemd160()
        {
            super(new ripemd160digest(), new ecdsasigner(), new stddsaencoder());
        }
    }

    static public class ecnr
        extends signaturespi
    {
        public ecnr()
        {
            super(new sha1digest(), new ecnrsigner(), new stddsaencoder());
        }
    }

    static public class ecnr224
        extends signaturespi
    {
        public ecnr224()
        {
            super(new sha224digest(), new ecnrsigner(), new stddsaencoder());
        }
    }

    static public class ecnr256
        extends signaturespi
    {
        public ecnr256()
        {
            super(new sha256digest(), new ecnrsigner(), new stddsaencoder());
        }
    }

    static public class ecnr384
        extends signaturespi
    {
        public ecnr384()
        {
            super(new sha384digest(), new ecnrsigner(), new stddsaencoder());
        }
    }

    static public class ecnr512
        extends signaturespi
    {
        public ecnr512()
        {
            super(new sha512digest(), new ecnrsigner(), new stddsaencoder());
        }
    }

    static public class eccvcdsa
        extends signaturespi
    {
        public eccvcdsa()
        {
            super(new sha1digest(), new ecdsasigner(), new cvcdsaencoder());
        }
    }

    static public class eccvcdsa224
        extends signaturespi
    {
        public eccvcdsa224()
        {
            super(new sha224digest(), new ecdsasigner(), new cvcdsaencoder());
        }
    }

    static public class eccvcdsa256
        extends signaturespi
    {
        public eccvcdsa256()
        {
            super(new sha256digest(), new ecdsasigner(), new cvcdsaencoder());
        }
    }

    static public class eccvcdsa384
        extends signaturespi
    {
        public eccvcdsa384()
        {
            super(new sha384digest(), new ecdsasigner(), new cvcdsaencoder());
        }
    }

    static public class eccvcdsa512
        extends signaturespi
    {
        public eccvcdsa512()
        {
            super(new sha512digest(), new ecdsasigner(), new cvcdsaencoder());
        }
    }

    private static class stddsaencoder
        implements dsaencoder
    {
        public byte[] encode(
            biginteger r,
            biginteger s)
            throws ioexception
        {
            asn1encodablevector v = new asn1encodablevector();

            v.add(new asn1integer(r));
            v.add(new asn1integer(s));

            return new dersequence(v).getencoded(asn1encoding.der);
        }

        public biginteger[] decode(
            byte[] encoding)
            throws ioexception
        {
            asn1sequence s = (asn1sequence)asn1primitive.frombytearray(encoding);
            biginteger[] sig = new biginteger[2];

            sig[0] = asn1integer.getinstance(s.getobjectat(0)).getvalue();
            sig[1] = asn1integer.getinstance(s.getobjectat(1)).getvalue();

            return sig;
        }
    }

    private static class cvcdsaencoder
        implements dsaencoder
    {
        public byte[] encode(
            biginteger r,
            biginteger s)
            throws ioexception
        {
            byte[] first = makeunsigned(r);
            byte[] second = makeunsigned(s);
            byte[] res;

            if (first.length > second.length)
            {
                res = new byte[first.length * 2];
            }
            else
            {
                res = new byte[second.length * 2];
            }

            system.arraycopy(first, 0, res, res.length / 2 - first.length, first.length);
            system.arraycopy(second, 0, res, res.length - second.length, second.length);

            return res;
        }


        private byte[] makeunsigned(biginteger val)
        {
            byte[] res = val.tobytearray();

            if (res[0] == 0)
            {
                byte[] tmp = new byte[res.length - 1];

                system.arraycopy(res, 1, tmp, 0, tmp.length);

                return tmp;
            }

            return res;
        }

        public biginteger[] decode(
            byte[] encoding)
            throws ioexception
        {
            biginteger[] sig = new biginteger[2];

            byte[] first = new byte[encoding.length / 2];
            byte[] second = new byte[encoding.length / 2];

            system.arraycopy(encoding, 0, first, 0, first.length);
            system.arraycopy(encoding, first.length, second, 0, second.length);

            sig[0] = new biginteger(1, first);
            sig[1] = new biginteger(1, second);

            return sig;
        }
    }
}