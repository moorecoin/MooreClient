package org.ripple.bouncycastle.crypto.util;

import java.io.ioexception;
import java.io.inputstream;
import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.nist.nistnamedcurves;
import org.ripple.bouncycastle.asn1.oiw.elgamalparameter;
import org.ripple.bouncycastle.asn1.oiw.oiwobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.dhparameter;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.privatekeyinfo;
import org.ripple.bouncycastle.asn1.pkcs.rsaprivatekey;
import org.ripple.bouncycastle.asn1.sec.ecprivatekey;
import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.teletrust.teletrustnamedcurves;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.dsaparameter;
import org.ripple.bouncycastle.asn1.x9.x962namedcurves;
import org.ripple.bouncycastle.asn1.x9.x962parameters;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.asn1.x9.x9objectidentifiers;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dhparameters;
import org.ripple.bouncycastle.crypto.params.dhprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.dsaparameters;
import org.ripple.bouncycastle.crypto.params.dsaprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.elgamalparameters;
import org.ripple.bouncycastle.crypto.params.elgamalprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.rsaprivatecrtkeyparameters;

/**
 * factory for creating private key objects from pkcs8 privatekeyinfo objects.
 */
public class privatekeyfactory
{
    /**
     * create a private key parameter from a pkcs8 privatekeyinfo encoding.
     * 
     * @param privatekeyinfodata the privatekeyinfo encoding
     * @return a suitable private key parameter
     * @throws ioexception on an error decoding the key
     */
    public static asymmetrickeyparameter createkey(byte[] privatekeyinfodata) throws ioexception
    {
        return createkey(privatekeyinfo.getinstance(asn1primitive.frombytearray(privatekeyinfodata)));
    }

    /**
     * create a private key parameter from a pkcs8 privatekeyinfo encoding read from a
     * stream.
     * 
     * @param instr the stream to read the privatekeyinfo encoding from
     * @return a suitable private key parameter
     * @throws ioexception on an error decoding the key
     */
    public static asymmetrickeyparameter createkey(inputstream instr) throws ioexception
    {
        return createkey(privatekeyinfo.getinstance(new asn1inputstream(instr).readobject()));
    }

    /**
     * create a private key parameter from the passed in pkcs8 privatekeyinfo object.
     * 
     * @param keyinfo the privatekeyinfo object containing the key material
     * @return a suitable private key parameter
     * @throws ioexception on an error decoding the key
     */
    public static asymmetrickeyparameter createkey(privatekeyinfo keyinfo) throws ioexception
    {
        algorithmidentifier algid = keyinfo.getprivatekeyalgorithm();

        if (algid.getalgorithm().equals(pkcsobjectidentifiers.rsaencryption))
        {
            rsaprivatekey keystructure = rsaprivatekey.getinstance(keyinfo.parseprivatekey());

            return new rsaprivatecrtkeyparameters(keystructure.getmodulus(),
                keystructure.getpublicexponent(), keystructure.getprivateexponent(),
                keystructure.getprime1(), keystructure.getprime2(), keystructure.getexponent1(),
                keystructure.getexponent2(), keystructure.getcoefficient());
        }
        // todo?
//      else if (algid.getobjectid().equals(x9objectidentifiers.dhpublicnumber))
        else if (algid.getalgorithm().equals(pkcsobjectidentifiers.dhkeyagreement))
        {
            dhparameter params = dhparameter.getinstance(algid.getparameters());
            asn1integer derx = (asn1integer)keyinfo.parseprivatekey();

            biginteger lval = params.getl();
            int l = lval == null ? 0 : lval.intvalue();
            dhparameters dhparams = new dhparameters(params.getp(), params.getg(), null, l);

            return new dhprivatekeyparameters(derx.getvalue(), dhparams);
        }
        else if (algid.getalgorithm().equals(oiwobjectidentifiers.elgamalalgorithm))
        {
            elgamalparameter params = new elgamalparameter((asn1sequence)algid.getparameters());
            asn1integer derx = (asn1integer)keyinfo.parseprivatekey();

            return new elgamalprivatekeyparameters(derx.getvalue(), new elgamalparameters(
                params.getp(), params.getg()));
        }
        else if (algid.getalgorithm().equals(x9objectidentifiers.id_dsa))
        {
            asn1integer derx = (asn1integer)keyinfo.parseprivatekey();
            asn1encodable de = algid.getparameters();

            dsaparameters parameters = null;
            if (de != null)
            {
                dsaparameter params = dsaparameter.getinstance(de.toasn1primitive());
                parameters = new dsaparameters(params.getp(), params.getq(), params.getg());
            }

            return new dsaprivatekeyparameters(derx.getvalue(), parameters);
        }
        else if (algid.getalgorithm().equals(x9objectidentifiers.id_ecpublickey))
        {
            x962parameters params = new x962parameters((asn1primitive)algid.getparameters());

            x9ecparameters x9;
            if (params.isnamedcurve())
            {
                asn1objectidentifier oid = asn1objectidentifier.getinstance(params.getparameters());
                x9 = x962namedcurves.getbyoid(oid);

                if (x9 == null)
                {
                    x9 = secnamedcurves.getbyoid(oid);

                    if (x9 == null)
                    {
                        x9 = nistnamedcurves.getbyoid(oid);

                        if (x9 == null)
                        {
                            x9 = teletrustnamedcurves.getbyoid(oid);
                        }
                    }
                }
            }
            else
            {
                x9 = x9ecparameters.getinstance(params.getparameters());
            }

            ecprivatekey ec = ecprivatekey.getinstance(keyinfo.parseprivatekey());
            biginteger d = ec.getkey();

            // todo we lose any named parameters here

            ecdomainparameters dparams = new ecdomainparameters(
                    x9.getcurve(), x9.getg(), x9.getn(), x9.geth(), x9.getseed());

            return new ecprivatekeyparameters(d, dparams);
        }
        else
        {
            throw new runtimeexception("algorithm identifier in key not recognised");
        }
    }
}
