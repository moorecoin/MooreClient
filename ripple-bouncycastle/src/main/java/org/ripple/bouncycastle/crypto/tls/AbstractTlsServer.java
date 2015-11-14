package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.util.hashtable;
import java.util.vector;

public abstract class abstracttlsserver
    extends abstracttlspeer
    implements tlsserver
{

    protected tlscipherfactory cipherfactory;

    protected tlsservercontext context;

    protected protocolversion clientversion;
    protected int[] offeredciphersuites;
    protected short[] offeredcompressionmethods;
    protected hashtable clientextensions;

    protected vector supportedsignaturealgorithms;
    protected boolean eccciphersuitesoffered;
    protected int[] namedcurves;
    protected short[] clientecpointformats, serverecpointformats;

    protected protocolversion serverversion;
    protected int selectedciphersuite;
    protected short selectedcompressionmethod;
    protected hashtable serverextensions;

    public abstracttlsserver()
    {
        this(new defaulttlscipherfactory());
    }

    public abstracttlsserver(tlscipherfactory cipherfactory)
    {
        this.cipherfactory = cipherfactory;
    }

    protected abstract int[] getciphersuites();

    protected short[] getcompressionmethods()
    {
        return new short[]{compressionmethod._null};
    }

    protected protocolversion getmaximumversion()
    {
        return protocolversion.tlsv11;
    }

    protected protocolversion getminimumversion()
    {
        return protocolversion.tlsv10;
    }

    protected boolean supportsclientecccapabilities(int[] namedcurves, short[] ecpointformats)
    {

        // note: bc supports all the current set of point formats so we don't check them here

        if (namedcurves == null)
        {
            /*
             * rfc 4492 4. a client that proposes ecc cipher suites may choose not to include these
             * extensions. in this case, the server is free to choose any one of the elliptic curves
             * or point formats [...].
             */
            return tlseccutils.hasanysupportednamedcurves();
        }

        for (int i = 0; i < namedcurves.length; ++i)
        {
            int namedcurve = namedcurves[i];
            if (!namedcurve.referstoaspecificnamedcurve(namedcurve) || tlseccutils.issupportednamedcurve(namedcurve))
            {
                return true;
            }
        }

        return false;
    }

    public void init(tlsservercontext context)
    {
        this.context = context;
    }

    public void notifyclientversion(protocolversion clientversion)
        throws ioexception
    {
        this.clientversion = clientversion;
    }

    public void notifyofferedciphersuites(int[] offeredciphersuites)
        throws ioexception
    {
        this.offeredciphersuites = offeredciphersuites;
        this.eccciphersuitesoffered = tlseccutils.containseccciphersuites(this.offeredciphersuites);
    }

    public void notifyofferedcompressionmethods(short[] offeredcompressionmethods)
        throws ioexception
    {
        this.offeredcompressionmethods = offeredcompressionmethods;
    }

    public void notifysecurerenegotiation(boolean securerenegotiation)
        throws ioexception
    {
        if (!securerenegotiation)
        {
            /*
             * rfc 5746 3.6. in this case, some servers may want to terminate the handshake instead
             * of continuing; see section 4.3 for discussion.
             */
            throw new tlsfatalalert(alertdescription.handshake_failure);
        }
    }

    public void processclientextensions(hashtable clientextensions)
        throws ioexception
    {

        this.clientextensions = clientextensions;

        if (clientextensions != null)
        {

            this.supportedsignaturealgorithms = tlsutils.getsignaturealgorithmsextension(clientextensions);
            if (this.supportedsignaturealgorithms != null)
            {
                /*
                 * rfc 5246 7.4.1.4.1. note: this extension is not meaningful for tls versions prior
                 * to 1.2. clients must not offer it if they are offering prior versions.
                 */
                if (!tlsutils.issignaturealgorithmsextensionallowed(clientversion))
                {
                    throw new tlsfatalalert(alertdescription.illegal_parameter);
                }
            }

            this.namedcurves = tlseccutils.getsupportedellipticcurvesextension(clientextensions);
            this.clientecpointformats = tlseccutils.getsupportedpointformatsextension(clientextensions);
        }

        /*
         * rfc 4429 4. the client must not include these extensions in the clienthello message if it
         * does not propose any ecc cipher suites.
         */
        if (!this.eccciphersuitesoffered && (this.namedcurves != null || this.clientecpointformats != null))
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
    }

    public protocolversion getserverversion()
        throws ioexception
    {
        if (getminimumversion().isequalorearlierversionof(clientversion))
        {
            protocolversion maximumversion = getmaximumversion();
            if (clientversion.isequalorearlierversionof(maximumversion))
            {
                return serverversion = clientversion;
            }
            if (clientversion.islaterversionof(maximumversion))
            {
                return serverversion = maximumversion;
            }
        }
        throw new tlsfatalalert(alertdescription.protocol_version);
    }

    public int getselectedciphersuite()
        throws ioexception
    {

        /*
         * todo rfc 5246 7.4.3. in order to negotiate correctly, the server must check any candidate
         * cipher suites against the "signature_algorithms" extension before selecting them. this is
         * somewhat inelegant but is a compromise designed to minimize changes to the original
         * cipher suite design.
         */

        /*
         * rfc 4429 5.1. a server that receives a clienthello containing one or both of these
         * extensions must use the client's enumerated capabilities to guide its selection of an
         * appropriate cipher suite. one of the proposed ecc cipher suites must be negotiated only
         * if the server can successfully complete the handshake while using the curves and point
         * formats supported by the client [...].
         */
        boolean eccciphersuitesenabled = supportsclientecccapabilities(this.namedcurves, this.clientecpointformats);

        int[] ciphersuites = getciphersuites();
        for (int i = 0; i < ciphersuites.length; ++i)
        {
            int ciphersuite = ciphersuites[i];
            if (tlsprotocol.arraycontains(this.offeredciphersuites, ciphersuite)
                && (eccciphersuitesenabled || !tlseccutils.iseccciphersuite(ciphersuite)))
            {
                return this.selectedciphersuite = ciphersuite;
            }
        }
        throw new tlsfatalalert(alertdescription.handshake_failure);
    }

    public short getselectedcompressionmethod()
        throws ioexception
    {
        short[] compressionmethods = getcompressionmethods();
        for (int i = 0; i < compressionmethods.length; ++i)
        {
            if (tlsprotocol.arraycontains(offeredcompressionmethods, compressionmethods[i]))
            {
                return this.selectedcompressionmethod = compressionmethods[i];
            }
        }
        throw new tlsfatalalert(alertdescription.handshake_failure);
    }

    // hashtable is (integer -> byte[])
    public hashtable getserverextensions()
        throws ioexception
    {

        if (this.clientecpointformats != null && tlseccutils.iseccciphersuite(this.selectedciphersuite))
        {
            /*
             * rfc 4492 5.2. a server that selects an ecc cipher suite in response to a clienthello
             * message including a supported point formats extension appends this extension (along
             * with others) to its serverhello message, enumerating the point formats it can parse.
             */
            this.serverecpointformats = new short[]{ecpointformat.ansix962_compressed_char2,
                ecpointformat.ansix962_compressed_prime, ecpointformat.uncompressed};

            this.serverextensions = new hashtable();
            tlseccutils.addsupportedpointformatsextension(serverextensions, serverecpointformats);
            return serverextensions;
        }

        return null;
    }

    public vector getserversupplementaldata()
        throws ioexception
    {
        return null;
    }

    public certificaterequest getcertificaterequest()
    {
        return null;
    }

    public void processclientsupplementaldata(vector clientsupplementaldata)
        throws ioexception
    {
        if (clientsupplementaldata != null)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
    }

    public void notifyclientcertificate(certificate clientcertificate)
        throws ioexception
    {
        throw new tlsfatalalert(alertdescription.internal_error);
    }

    public tlscompression getcompression()
        throws ioexception
    {
        switch (selectedcompressionmethod)
        {
        case compressionmethod._null:
            return new tlsnullcompression();

        default:
            /*
             * note: internal error here; we selected the compression method, so if we now can't
             * produce an implementation, we shouldn't have chosen it!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public newsessionticket getnewsessionticket()
        throws ioexception
    {
        /*
         * rfc 5077 3.3. if the server determines that it does not want to include a ticket after it
         * has included the sessionticket extension in the serverhello, then it sends a zero-length
         * ticket in the newsessionticket handshake message.
         */
        return new newsessionticket(0l, tlsutils.empty_bytes);
    }

    public void notifyhandshakecomplete()
        throws ioexception
    {
    }
}
