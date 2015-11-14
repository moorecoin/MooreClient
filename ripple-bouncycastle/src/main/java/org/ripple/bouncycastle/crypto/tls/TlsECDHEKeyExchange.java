package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.util.vector;

import org.ripple.bouncycastle.crypto.asymmetriccipherkeypair;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.signer;
import org.ripple.bouncycastle.crypto.io.signerinputstream;
import org.ripple.bouncycastle.crypto.params.ecdomainparameters;
import org.ripple.bouncycastle.crypto.params.ecprivatekeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;

/**
 * ecdhe key exchange (see rfc 4492)
 */
public class tlsecdhekeyexchange
    extends tlsecdhkeyexchange
{

    protected tlssignercredentials servercredentials = null;

    public tlsecdhekeyexchange(int keyexchange, vector supportedsignaturealgorithms, int[] namedcurves,
                               short[] clientecpointformats, short[] serverecpointformats)
    {
        super(keyexchange, supportedsignaturealgorithms, namedcurves, clientecpointformats, serverecpointformats);
    }

    public void processservercredentials(tlscredentials servercredentials)
        throws ioexception
    {

        if (!(servercredentials instanceof tlssignercredentials))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        processservercertificate(servercredentials.getcertificate());

        this.servercredentials = (tlssignercredentials)servercredentials;
    }

    public byte[] generateserverkeyexchange()
        throws ioexception
    {

        /*
         * first we try to find a supported named curve from the client's list.
         */
        int namedcurve = -1;
        if (namedcurves == null)
        {
            namedcurve = namedcurve.secp256r1;
        }
        else
        {
            for (int i = 0; i < namedcurves.length; ++i)
            {
                int entry = namedcurves[i];
                if (tlseccutils.issupportednamedcurve(entry))
                {
                    namedcurve = entry;
                    break;
                }
            }
        }

        ecdomainparameters curve_params = null;
        if (namedcurve >= 0)
        {
            curve_params = tlseccutils.getparametersfornamedcurve(namedcurve);
        }
        else
        {
            /*
             * if no named curves are suitable, check if the client supports explicit curves.
             */
            if (tlsprotocol.arraycontains(namedcurves, namedcurve.arbitrary_explicit_prime_curves))
            {
                curve_params = tlseccutils.getparametersfornamedcurve(namedcurve.secp256r1);
            }
            else if (tlsprotocol.arraycontains(namedcurves, namedcurve.arbitrary_explicit_char2_curves))
            {
                curve_params = tlseccutils.getparametersfornamedcurve(namedcurve.sect233r1);
            }
        }

        if (curve_params == null)
        {
            /*
             * note: we shouldn't have negotiated ecdhe key exchange since we apparently can't find
             * a suitable curve.
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        asymmetriccipherkeypair kp = tlseccutils.generateeckeypair(context.getsecurerandom(), curve_params);
        this.ecagreeserverprivatekey = (ecprivatekeyparameters)kp.getprivate();

        byte[] publicbytes = tlseccutils.serializeecpublickey(clientecpointformats,
            (ecpublickeyparameters)kp.getpublic());

        bytearrayoutputstream buf = new bytearrayoutputstream();

        if (namedcurve < 0)
        {
            tlseccutils.writeexplicitecparameters(clientecpointformats, curve_params, buf);
        }
        else
        {
            tlseccutils.writenamedecparameters(namedcurve, buf);
        }

        tlsutils.writeopaque8(publicbytes, buf);

        byte[] digestinput = buf.tobytearray();

        digest d = new combinedhash();
        securityparameters securityparameters = context.getsecurityparameters();
        d.update(securityparameters.clientrandom, 0, securityparameters.clientrandom.length);
        d.update(securityparameters.serverrandom, 0, securityparameters.serverrandom.length);
        d.update(digestinput, 0, digestinput.length);

        byte[] hash = new byte[d.getdigestsize()];
        d.dofinal(hash, 0);

        byte[] sigbytes = servercredentials.generatecertificatesignature(hash);
        /*
         * todo rfc 5246 4.7. digitally-signed element needs signatureandhashalgorithm prepended
         * from tls 1.2
         */
        tlsutils.writeopaque16(sigbytes, buf);

        return buf.tobytearray();
    }

    public void processserverkeyexchange(inputstream input)
        throws ioexception
    {

        securityparameters securityparameters = context.getsecurityparameters();

        signer signer = initverifyer(tlssigner, securityparameters);
        inputstream sigin = new signerinputstream(input, signer);

        ecdomainparameters curve_params = tlseccutils.readecparameters(namedcurves, clientecpointformats, sigin);

        byte[] point = tlsutils.readopaque8(sigin);

        byte[] sigbyte = tlsutils.readopaque16(input);
        if (!signer.verifysignature(sigbyte))
        {
            throw new tlsfatalalert(alertdescription.decrypt_error);
        }

        this.ecagreeserverpublickey = tlseccutils.validateecpublickey(tlseccutils.deserializeecpublickey(
            clientecpointformats, curve_params, point));
    }

    public void validatecertificaterequest(certificaterequest certificaterequest)
        throws ioexception
    {
        /*
         * rfc 4492 3. [...] the ecdsa_fixed_ecdh and rsa_fixed_ecdh mechanisms are usable with
         * ecdh_ecdsa and ecdh_rsa. their use with ecdhe_ecdsa and ecdhe_rsa is prohibited because
         * the use of a long-term ecdh client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        short[] types = certificaterequest.getcertificatetypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case clientcertificatetype.rsa_sign:
            case clientcertificatetype.dss_sign:
            case clientcertificatetype.ecdsa_sign:
                break;
            default:
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
    }

    public void processclientcredentials(tlscredentials clientcredentials)
        throws ioexception
    {
        if (clientcredentials instanceof tlssignercredentials)
        {
            // ok
        }
        else
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    protected signer initverifyer(tlssigner tlssigner, securityparameters securityparameters)
    {
        signer signer = tlssigner.createverifyer(this.serverpublickey);
        signer.update(securityparameters.clientrandom, 0, securityparameters.clientrandom.length);
        signer.update(securityparameters.serverrandom, 0, securityparameters.serverrandom.length);
        return signer;
    }
}
