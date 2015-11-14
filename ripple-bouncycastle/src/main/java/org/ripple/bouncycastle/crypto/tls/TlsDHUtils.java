package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.math.biginteger;
import java.security.securerandom;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.agreement.dhbasicagreement;
import org.ripple.bouncycastle.crypto.generators.dhbasickeypairgenerator;
import org.ripple.bouncycastle.crypto.params.dhkeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dhpublickeyparameters;
import org.ripple.bouncycastle.util.bigintegers;

public class tlsdhutils
{

    static final biginteger one = biginteger.valueof(1);
    static final biginteger two = biginteger.valueof(2);

    public static byte[] calculatedhbasicagreement(dhpublickeyparameters publickey,
                                                   dhprivatekeyparameters privatekey)
    {

        dhbasicagreement basicagreement = new dhbasicagreement();
        basicagreement.init(privatekey);
        biginteger agreementvalue = basicagreement.calculateagreement(publickey);

        /*
         * rfc 5246 8.1.2. leading bytes of z that contain all zero bits are stripped before it is
         * used as the pre_master_secret.
         */
        return bigintegers.asunsignedbytearray(agreementvalue);
    }

    public static asymmetriccipherkeypair generatedhkeypair(securerandom random,
                                                            dhparameters dhparams)
    {
        dhbasickeypairgenerator dhgen = new dhbasickeypairgenerator();
        dhgen.init(new dhkeygenerationparameters(random, dhparams));
        return dhgen.generatekeypair();
    }

    public static dhprivatekeyparameters generateephemeralclientkeyexchange(securerandom random,
                                                                            dhparameters dhparams, outputstream output)
        throws ioexception
    {

        asymmetriccipherkeypair dhagreeclientkeypair = generatedhkeypair(random, dhparams);
        dhprivatekeyparameters dhagreeclientprivatekey = (dhprivatekeyparameters)dhagreeclientkeypair
            .getprivate();

        biginteger yc = ((dhpublickeyparameters)dhagreeclientkeypair.getpublic()).gety();
        byte[] kedata = bigintegers.asunsignedbytearray(yc);
        tlsutils.writeopaque16(kedata, output);

        return dhagreeclientprivatekey;
    }

    public static dhpublickeyparameters validatedhpublickey(dhpublickeyparameters key)
        throws ioexception
    {
        biginteger y = key.gety();
        dhparameters params = key.getparameters();
        biginteger p = params.getp();
        biginteger g = params.getg();

        if (!p.isprobableprime(2))
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
        if (g.compareto(two) < 0 || g.compareto(p.subtract(two)) > 0)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
        if (y.compareto(two) < 0 || y.compareto(p.subtract(one)) > 0)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        // todo see rfc 2631 for more discussion of diffie-hellman validation

        return key;
    }

    public static biginteger readdhparameter(inputstream input)
        throws ioexception
    {
        return new biginteger(1, tlsutils.readopaque16(input));
    }

    public static void writedhparameter(biginteger x, outputstream output)
        throws ioexception
    {
        tlsutils.writeopaque16(bigintegers.asunsignedbytearray(x), output);
    }
}
