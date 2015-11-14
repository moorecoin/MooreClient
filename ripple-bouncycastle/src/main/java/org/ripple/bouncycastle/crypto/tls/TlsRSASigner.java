package org.ripple.bouncycastle.crypto.tls;

import org.ripple.bouncycastle.crypto.asymmetricblockcipher;
import org.ripple.bouncycastle.crypto.cipherparameters;
import org.ripple.bouncycastle.crypto.cryptoexception;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.encodings.pkcs1encoding;
import org.ripple.bouncycastle.crypto.engines.rsablindedengine;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithrandom;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.signers.genericsigner;
import org.ripple.bouncycastle.crypto.signers.rsadigestsigner;
import org.ripple.bouncycastle.util.arrays;

public class tlsrsasigner
    extends abstracttlssigner
{

    public byte[] generaterawsignature(asymmetrickeyparameter privatekey, byte[] md5andsha1)
        throws cryptoexception
    {

        asymmetricblockcipher engine = creatersaimpl();
        engine.init(true, new parameterswithrandom(privatekey, this.context.getsecurerandom()));
        return engine.processblock(md5andsha1, 0, md5andsha1.length);
    }

    public boolean verifyrawsignature(byte[] sigbytes, asymmetrickeyparameter publickey, byte[] md5andsha1)
        throws cryptoexception
    {

        asymmetricblockcipher engine = creatersaimpl();
        engine.init(false, publickey);
        byte[] signed = engine.processblock(sigbytes, 0, sigbytes.length);
        return arrays.constanttimeareequal(signed, md5andsha1);
    }

    public signer createsigner(asymmetrickeyparameter privatekey)
    {
        return makesigner(new combinedhash(), true,
            new parameterswithrandom(privatekey, this.context.getsecurerandom()));
    }

    public signer createverifyer(asymmetrickeyparameter publickey)
    {
        return makesigner(new combinedhash(), false, publickey);
    }

    public boolean isvalidpublickey(asymmetrickeyparameter publickey)
    {
        return publickey instanceof rsakeyparameters && !publickey.isprivate();
    }

    protected signer makesigner(digest d, boolean forsigning, cipherparameters cp)
    {
        signer s;
        if (protocolversion.tlsv12.isequalorearlierversionof(context.getserverversion().getequivalenttlsversion()))
        {
            /*
             * rfc 5246 4.7. in rsa signing, the opaque vector contains the signature generated
             * using the rsassa-pkcs1-v1_5 signature scheme defined in [pkcs1].
             */
            s = new rsadigestsigner(d);
        }
        else
        {
            /*
             * rfc 5246 4.7. note that earlier versions of tls used a different rsa signature scheme
             * that did not include a digestinfo encoding.
             */
            s = new genericsigner(creatersaimpl(), d);
        }
        s.init(forsigning, cp);
        return s;
    }

    protected asymmetricblockcipher creatersaimpl()
    {
        /*
         * rfc 5264 7.4.7.1. implementation note: it is now known that remote timing-based attacks
         * on tls are possible, at least when the client and server are on the same lan.
         * accordingly, implementations that use static rsa keys must use rsa blinding or some other
         * anti-timing technique, as described in [timing].
         */
        return new pkcs1encoding(new rsablindedengine());
    }
}
