package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.math.biginteger;
import java.security.securerandom;
import java.util.hashtable;

import org.ripple.bouncycastle.asn1.sec.secnamedcurves;
import org.ripple.bouncycastle.asn1.x9.x9ecparameters;
import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.agreement.ecdhbasicagreement;
import org.ripple.bouncycastle.crypto.generators.eckeypairgenerator;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.eckeygenerationparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.math.ec.eccurve;
import org.ripple.bouncycastle.math.ec.ecpoint;
import org.ripple.bouncycastle.util.bigintegers;
import org.ripple.bouncycastle.util.integers;

public class tlseccutils
{

    public static final integer ext_elliptic_curves = integers.valueof(extensiontype.elliptic_curves);
    public static final integer ext_ec_point_formats = integers.valueof(extensiontype.ec_point_formats);

    private static final string[] curvenames = new string[]{"sect163k1", "sect163r1", "sect163r2", "sect193r1",
        "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
        "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1",
        "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1",};

    public static void addsupportedellipticcurvesextension(hashtable extensions, int[] namedcurves)
        throws ioexception
    {

        extensions.put(ext_elliptic_curves, createsupportedellipticcurvesextension(namedcurves));
    }

    public static void addsupportedpointformatsextension(hashtable extensions, short[] ecpointformats)
        throws ioexception
    {

        extensions.put(ext_ec_point_formats, createsupportedpointformatsextension(ecpointformats));
    }

    public static int[] getsupportedellipticcurvesextension(hashtable extensions)
        throws ioexception
    {

        if (extensions == null)
        {
            return null;
        }
        byte[] extensionvalue = (byte[])extensions.get(ext_elliptic_curves);
        if (extensionvalue == null)
        {
            return null;
        }
        return readsupportedellipticcurvesextension(extensionvalue);
    }

    public static short[] getsupportedpointformatsextension(hashtable extensions)
        throws ioexception
    {

        if (extensions == null)
        {
            return null;
        }
        byte[] extensionvalue = (byte[])extensions.get(ext_ec_point_formats);
        if (extensionvalue == null)
        {
            return null;
        }
        return readsupportedpointformatsextension(extensionvalue);
    }

    public static byte[] createsupportedellipticcurvesextension(int[] namedcurves)
        throws ioexception
    {

        if (namedcurves == null || namedcurves.length < 1)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint16(2 * namedcurves.length, buf);
        tlsutils.writeuint16array(namedcurves, buf);
        return buf.tobytearray();
    }

    public static byte[] createsupportedpointformatsextension(short[] ecpointformats)
        throws ioexception
    {

        if (ecpointformats == null)
        {
            ecpointformats = new short[]{ecpointformat.uncompressed};
        }
        else if (!tlsprotocol.arraycontains(ecpointformats, ecpointformat.uncompressed))
        {
            /*
             * rfc 4492 5.1. if the supported point formats extension is indeed sent, it must
             * contain the value 0 (uncompressed) as one of the items in the list of point formats.
             */

            // note: we add it at the end (lowest preference)
            short[] tmp = new short[ecpointformats.length + 1];
            system.arraycopy(ecpointformats, 0, tmp, 0, ecpointformats.length);
            tmp[ecpointformats.length] = ecpointformat.uncompressed;

            ecpointformats = tmp;
        }

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8((short)ecpointformats.length, buf);
        tlsutils.writeuint8array(ecpointformats, buf);
        return buf.tobytearray();
    }

    public static int[] readsupportedellipticcurvesextension(byte[] extensionvalue)
        throws ioexception
    {

        if (extensionvalue == null)
        {
            throw new illegalargumentexception("'extensionvalue' cannot be null");
        }

        bytearrayinputstream buf = new bytearrayinputstream(extensionvalue);

        int length = tlsutils.readuint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        int[] namedcurves = tlsutils.readuint16array(length / 2, buf);

        tlsprotocol.assertempty(buf);

        return namedcurves;
    }

    public static short[] readsupportedpointformatsextension(byte[] extensionvalue)
        throws ioexception
    {

        if (extensionvalue == null)
        {
            throw new illegalargumentexception("'extensionvalue' cannot be null");
        }

        bytearrayinputstream buf = new bytearrayinputstream(extensionvalue);

        short length = tlsutils.readuint8(buf);
        if (length < 1)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        short[] ecpointformats = tlsutils.readuint8array(length, buf);

        tlsprotocol.assertempty(buf);

        if (!tlsprotocol.arraycontains(ecpointformats, ecpointformat.uncompressed))
        {
            /*
             * rfc 4492 5.1. if the supported point formats extension is indeed sent, it must
             * contain the value 0 (uncompressed) as one of the items in the list of point formats.
             */
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        return ecpointformats;
    }

    public static string getnameofnamedcurve(int namedcurve)
    {
        return issupportednamedcurve(namedcurve) ? curvenames[namedcurve - 1] : null;
    }

    public static ecdomainparameters getparametersfornamedcurve(int namedcurve)
    {
        string curvename = getnameofnamedcurve(namedcurve);
        if (curvename == null)
        {
            return null;
        }

        // lazily created the first time a particular curve is accessed
        x9ecparameters ecp = secnamedcurves.getbyname(curvename);

        if (ecp == null)
        {
            return null;
        }

        // it's a bit inefficient to do this conversion every time
        return new ecdomainparameters(ecp.getcurve(), ecp.getg(), ecp.getn(), ecp.geth(), ecp.getseed());
    }

    public static boolean hasanysupportednamedcurves()
    {
        return curvenames.length > 0;
    }

    public static boolean containseccciphersuites(int[] ciphersuites)
    {
        for (int i = 0; i < ciphersuites.length; ++i)
        {
            if (iseccciphersuite(ciphersuites[i]))
            {
                return true;
            }
        }
        return false;
    }

    public static boolean iseccciphersuite(int ciphersuite)
    {
        switch (ciphersuite)
        {
        case ciphersuite.tls_ecdh_ecdsa_with_null_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_null_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_null_sha:
        case ciphersuite.tls_ecdh_rsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_null_sha:
        case ciphersuite.tls_ecdhe_rsa_with_rc4_128_sha:
        case ciphersuite.tls_ecdhe_rsa_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdh_anon_with_null_sha:
        case ciphersuite.tls_ecdh_anon_with_rc4_128_sha:
        case ciphersuite.tls_ecdh_anon_with_3des_ede_cbc_sha:
        case ciphersuite.tls_ecdh_anon_with_aes_128_cbc_sha:
        case ciphersuite.tls_ecdh_anon_with_aes_256_cbc_sha:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_gcm_sha384:
            return true;
        default:
            return false;
        }
    }

    public static boolean areonsamecurve(ecdomainparameters a, ecdomainparameters b)
    {
        // todo move to ecdomainparameters.equals() or other utility method?
        return a.getcurve().equals(b.getcurve()) && a.getg().equals(b.getg()) && a.getn().equals(b.getn())
            && a.geth().equals(b.geth());
    }

    public static boolean issupportednamedcurve(int namedcurve)
    {
        return (namedcurve > 0 && namedcurve <= curvenames.length);
    }

    public static boolean iscompressionpreferred(short[] ecpointformats, short compressionformat)
    {
        if (ecpointformats == null)
        {
            return false;
        }
        for (int i = 0; i < ecpointformats.length; ++i)
        {
            short ecpointformat = ecpointformats[i];
            if (ecpointformat == ecpointformat.uncompressed)
            {
                return false;
            }
            if (ecpointformat == compressionformat)
            {
                return true;
            }
        }
        return false;
    }

    public static byte[] serializeecfieldelement(int fieldsize, biginteger x)
        throws ioexception
    {
        int requiredlength = (fieldsize + 7) / 8;
        return bigintegers.asunsignedbytearray(requiredlength, x);
    }

    public static byte[] serializeecpoint(short[] ecpointformats, ecpoint point)
        throws ioexception
    {

        eccurve curve = point.getcurve();

        /*
         * rfc 4492 5.7. ...an elliptic curve point in uncompressed or compressed format. here, the
         * format must conform to what the server has requested through a supported point formats
         * extension if this extension was used, and must be uncompressed if this extension was not
         * used.
         */
        boolean compressed = false;
        if (curve instanceof eccurve.f2m)
        {
            compressed = iscompressionpreferred(ecpointformats, ecpointformat.ansix962_compressed_char2);
        }
        else if (curve instanceof eccurve.fp)
        {
            compressed = iscompressionpreferred(ecpointformats, ecpointformat.ansix962_compressed_prime);
        }
        return point.getencoded(compressed);
    }

    public static byte[] serializeecpublickey(short[] ecpointformats, ecpublickeyparameters keyparameters)
        throws ioexception
    {

        return serializeecpoint(ecpointformats, keyparameters.getq());
    }

    public static biginteger deserializeecfieldelement(int fieldsize, byte[] encoding)
        throws ioexception
    {
        int requiredlength = (fieldsize + 7) / 8;
        if (encoding.length != requiredlength)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }
        return new biginteger(1, encoding);
    }

    public static ecpoint deserializeecpoint(short[] ecpointformats, eccurve curve, byte[] encoding)
        throws ioexception
    {
        /*
         * note: here we implicitly decode compressed or uncompressed encodings. defaulttlsclient by
         * default is set up to advertise that we can parse any encoding so this works fine, but
         * extra checks might be needed here if that were changed.
         */
        return curve.decodepoint(encoding);
    }

    public static ecpublickeyparameters deserializeecpublickey(short[] ecpointformats, ecdomainparameters curve_params,
                                                               byte[] encoding)
        throws ioexception
    {

        try
        {
            ecpoint y = deserializeecpoint(ecpointformats, curve_params.getcurve(), encoding);
            return new ecpublickeyparameters(y, curve_params);
        }
        catch (runtimeexception e)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
    }

    public static byte[] calculateecdhbasicagreement(ecpublickeyparameters publickey, ecprivatekeyparameters privatekey)
    {

        ecdhbasicagreement basicagreement = new ecdhbasicagreement();
        basicagreement.init(privatekey);
        biginteger agreementvalue = basicagreement.calculateagreement(publickey);

        /*
         * rfc 4492 5.10. note that this octet string (z in ieee 1363 terminology) as output by
         * fe2osp, the field element to octet string conversion primitive, has constant length for
         * any given field; leading zeros found in this octet string must not be truncated.
         */
        return bigintegers.asunsignedbytearray(basicagreement.getfieldsize(), agreementvalue);
    }

    public static asymmetriccipherkeypair generateeckeypair(securerandom random, ecdomainparameters ecparams)
    {

        eckeypairgenerator keypairgenerator = new eckeypairgenerator();
        eckeygenerationparameters keygenerationparameters = new eckeygenerationparameters(ecparams, random);
        keypairgenerator.init(keygenerationparameters);
        return keypairgenerator.generatekeypair();
    }

    public static ecpublickeyparameters validateecpublickey(ecpublickeyparameters key)
        throws ioexception
    {
        // todo check rfc 4492 for validation
        return key;
    }

    public static int readecexponent(int fieldsize, inputstream input)
        throws ioexception
    {
        biginteger k = readecparameter(input);
        if (k.bitlength() < 32)
        {
            int k = k.intvalue();
            if (k > 0 && k < fieldsize)
            {
                return k;
            }
        }
        throw new tlsfatalalert(alertdescription.illegal_parameter);
    }

    public static biginteger readecfieldelement(int fieldsize, inputstream input)
        throws ioexception
    {
        return deserializeecfieldelement(fieldsize, tlsutils.readopaque8(input));
    }

    public static biginteger readecparameter(inputstream input)
        throws ioexception
    {
        // todo are leading zeroes okay here?
        return new biginteger(1, tlsutils.readopaque8(input));
    }

    public static ecdomainparameters readecparameters(int[] namedcurves, short[] ecpointformats, inputstream input)
        throws ioexception
    {

        try
        {
            short curvetype = tlsutils.readuint8(input);

            switch (curvetype)
            {
            case eccurvetype.explicit_prime:
            {
                biginteger prime_p = readecparameter(input);
                biginteger a = readecfieldelement(prime_p.bitlength(), input);
                biginteger b = readecfieldelement(prime_p.bitlength(), input);
                eccurve curve = new eccurve.fp(prime_p, a, b);
                ecpoint base = deserializeecpoint(ecpointformats, curve, tlsutils.readopaque8(input));
                biginteger order = readecparameter(input);
                biginteger cofactor = readecparameter(input);
                return new ecdomainparameters(curve, base, order, cofactor);
            }
            case eccurvetype.explicit_char2:
            {
                int m = tlsutils.readuint16(input);
                short basis = tlsutils.readuint8(input);
                eccurve curve;
                switch (basis)
                {
                case ecbasistype.ec_basis_trinomial:
                {
                    int k = readecexponent(m, input);
                    biginteger a = readecfieldelement(m, input);
                    biginteger b = readecfieldelement(m, input);
                    curve = new eccurve.f2m(m, k, a, b);
                    break;
                }
                case ecbasistype.ec_basis_pentanomial:
                {
                    int k1 = readecexponent(m, input);
                    int k2 = readecexponent(m, input);
                    int k3 = readecexponent(m, input);
                    biginteger a = readecfieldelement(m, input);
                    biginteger b = readecfieldelement(m, input);
                    curve = new eccurve.f2m(m, k1, k2, k3, a, b);
                    break;
                }
                default:
                    throw new tlsfatalalert(alertdescription.illegal_parameter);
                }
                ecpoint base = deserializeecpoint(ecpointformats, curve, tlsutils.readopaque8(input));
                biginteger order = readecparameter(input);
                biginteger cofactor = readecparameter(input);
                return new ecdomainparameters(curve, base, order, cofactor);
            }
            case eccurvetype.named_curve:
            {
                int namedcurve = tlsutils.readuint16(input);
                if (!namedcurve.referstoaspecificnamedcurve(namedcurve))
                {
                    /*
                     * rfc 4492 5.4. all those values of namedcurve are allowed that refer to a
                     * specific curve. values of namedcurve that indicate support for a class of
                     * explicitly defined curves are not allowed here [...].
                     */
                    throw new tlsfatalalert(alertdescription.illegal_parameter);
                }

                if (!tlsprotocol.arraycontains(namedcurves, namedcurve))
                {
                    /*
                     * rfc 4492 4. [...] servers must not negotiate the use of an ecc cipher suite
                     * unless they can complete the handshake while respecting the choice of curves
                     * and compression techniques specified by the client.
                     */
                    throw new tlsfatalalert(alertdescription.illegal_parameter);
                }

                return tlseccutils.getparametersfornamedcurve(namedcurve);
            }
            default:
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
        catch (runtimeexception e)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
    }

    public static void writeecexponent(int k, outputstream output)
        throws ioexception
    {
        biginteger k = biginteger.valueof(k);
        writeecparameter(k, output);
    }

    public static void writeecfieldelement(int fieldsize, biginteger x, outputstream output)
        throws ioexception
    {
        tlsutils.writeopaque8(serializeecfieldelement(fieldsize, x), output);
    }

    public static void writeecparameter(biginteger x, outputstream output)
        throws ioexception
    {
        tlsutils.writeopaque8(bigintegers.asunsignedbytearray(x), output);
    }

    public static void writeexplicitecparameters(short[] ecpointformats, ecdomainparameters ecparameters,
                                                 outputstream output)
        throws ioexception
    {

        eccurve curve = ecparameters.getcurve();
        if (curve instanceof eccurve.fp)
        {

            tlsutils.writeuint8(eccurvetype.explicit_prime, output);

            eccurve.fp fp = (eccurve.fp)curve;
            writeecparameter(fp.getq(), output);

        }
        else if (curve instanceof eccurve.f2m)
        {

            tlsutils.writeuint8(eccurvetype.explicit_char2, output);

            eccurve.f2m f2m = (eccurve.f2m)curve;
            tlsutils.writeuint16(f2m.getm(), output);

            if (f2m.istrinomial())
            {
                tlsutils.writeuint8(ecbasistype.ec_basis_trinomial, output);
                writeecexponent(f2m.getk1(), output);
            }
            else
            {
                tlsutils.writeuint8(ecbasistype.ec_basis_pentanomial, output);
                writeecexponent(f2m.getk1(), output);
                writeecexponent(f2m.getk2(), output);
                writeecexponent(f2m.getk3(), output);
            }

        }
        else
        {
            throw new illegalargumentexception("'ecparameters' not a known curve type");
        }

        writeecfieldelement(curve.getfieldsize(), curve.geta().tobiginteger(), output);
        writeecfieldelement(curve.getfieldsize(), curve.getb().tobiginteger(), output);
        tlsutils.writeopaque8(serializeecpoint(ecpointformats, ecparameters.getg()), output);
        writeecparameter(ecparameters.getn(), output);
        writeecparameter(ecparameters.geth(), output);
    }

    public static void writenamedecparameters(int namedcurve, outputstream output)
        throws ioexception
    {

        if (!namedcurve.referstoaspecificnamedcurve(namedcurve))
        {
            /*
             * rfc 4492 5.4. all those values of namedcurve are allowed that refer to a specific
             * curve. values of namedcurve that indicate support for a class of explicitly defined
             * curves are not allowed here [...].
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        tlsutils.writeuint8(eccurvetype.named_curve, output);
        tlsutils.writeuint16(namedcurve, output);
    }
}
