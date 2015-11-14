package org.ripple.bouncycastle.openpgp.operator.bc;

import java.io.inputstream;

import org.ripple.bouncycastle.crypto.blockcipher;
import org.ripple.bouncycastle.crypto.bufferedblockcipher;
import org.ripple.bouncycastle.crypto.io.cipherinputstream;
import org.ripple.bouncycastle.crypto.modes.cfbblockcipher;
import org.ripple.bouncycastle.crypto.modes.openpgpcfbblockcipher;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.parameterswithiv;
import org.ripple.bouncycastle.openpgp.operator.pgpdatadecryptor;
import org.ripple.bouncycastle.openpgp.operator.pgpdigestcalculator;

class bcutil
{
    static bufferedblockcipher createstreamcipher(boolean forencryption, blockcipher engine, boolean withintegritypacket, byte[] key)
    {
        bufferedblockcipher c;

        if (withintegritypacket)
        {
            c = new bufferedblockcipher(new cfbblockcipher(engine, engine.getblocksize() * 8));
        }
        else
        {
            c = new bufferedblockcipher(new openpgpcfbblockcipher(engine));
        }

        keyparameter keyparameter = new keyparameter(key);

        if (withintegritypacket)
        {
            c.init(forencryption, new parameterswithiv(keyparameter, new byte[engine.getblocksize()]));
        }
        else
        {
            c.init(forencryption, keyparameter);
        }

        return c;
    }

    public static pgpdatadecryptor createdatadecryptor(boolean withintegritypacket, blockcipher engine, byte[] key)
    {
        final bufferedblockcipher c = createstreamcipher(false, engine, withintegritypacket, key);

        return new pgpdatadecryptor()
        {
            public inputstream getinputstream(inputstream in)
            {
                return new cipherinputstream(in, c);
            }

            public int getblocksize()
            {
                return c.getblocksize();
            }

            public pgpdigestcalculator getintegritycalculator()
            {
                return new sha1pgpdigestcalculator();
            }
        };
    }

    public static bufferedblockcipher createsymmetrickeywrapper(boolean forencryption, blockcipher engine, byte[] key, byte[] iv)
    {
        bufferedblockcipher c = new bufferedblockcipher(new cfbblockcipher(engine, engine.getblocksize() * 8));

        c.init(forencryption, new parameterswithiv(new keyparameter(key), iv));

        return c;
    }
}
