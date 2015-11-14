package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.util.hashtable;
import java.util.vector;

public abstract class abstracttlsclient
    extends abstracttlspeer
    implements tlsclient
{

    protected tlscipherfactory cipherfactory;

    protected tlsclientcontext context;

    protected vector supportedsignaturealgorithms;

    protected int selectedciphersuite;
    protected short selectedcompressionmethod;

    public abstracttlsclient()
    {
        this(new defaulttlscipherfactory());
    }

    public abstracttlsclient(tlscipherfactory cipherfactory)
    {
        this.cipherfactory = cipherfactory;
    }

    public void init(tlsclientcontext context)
    {
        this.context = context;
    }

    /**
     * rfc 5246 e.1. "tls clients that wish to negotiate with older servers may send any value
     * {03,xx} as the record layer version number. typical values would be {03,00}, the lowest
     * version number supported by the client, and the value of clienthello.client_version. no
     * single value will guarantee interoperability with all old servers, but this is a complex
     * topic beyond the scope of this document."
     */
    public protocolversion getclienthellorecordlayerversion()
    {
        // "{03,00}"
        // return protocolversion.sslv3;

        // "the lowest version number supported by the client"
        // return getminimumserverversion();

        // "the value of clienthello.client_version"
        return getclientversion();
    }

    public protocolversion getclientversion()
    {
        return protocolversion.tlsv11;
    }

    public hashtable getclientextensions()
        throws ioexception
    {

        hashtable clientextensions = null;

        protocolversion clientversion = context.getclientversion();

        /*
         * rfc 5246 7.4.1.4.1. note: this extension is not meaningful for tls versions prior to 1.2.
         * clients must not offer it if they are offering prior versions.
         */
        if (tlsutils.issignaturealgorithmsextensionallowed(clientversion))
        {

            // todo provide a way for the user to specify the acceptable hash/signature algorithms.

            short[] hashalgorithms = new short[]{hashalgorithm.sha512, hashalgorithm.sha384, hashalgorithm.sha256,
                hashalgorithm.sha224, hashalgorithm.sha1};

            // todo sort out ecdsa signatures and add them as the preferred option here
            short[] signaturealgorithms = new short[]{signaturealgorithm.rsa};

            this.supportedsignaturealgorithms = new vector();
            for (int i = 0; i < hashalgorithms.length; ++i)
            {
                for (int j = 0; j < signaturealgorithms.length; ++j)
                {
                    this.supportedsignaturealgorithms.addelement(new signatureandhashalgorithm(hashalgorithms[i],
                        signaturealgorithms[j]));
                }
            }

            /*
             * rfc 5264 7.4.3. currently, dsa [dss] may only be used with sha-1.
             */
            this.supportedsignaturealgorithms.addelement(new signatureandhashalgorithm(hashalgorithm.sha1,
                signaturealgorithm.dsa));

            if (clientextensions == null)
            {
                clientextensions = new hashtable();
            }

            tlsutils.addsignaturealgorithmsextension(clientextensions, supportedsignaturealgorithms);
        }

        return clientextensions;
    }

    public protocolversion getminimumversion()
    {
        return protocolversion.tlsv10;
    }

    public void notifyserverversion(protocolversion serverversion)
        throws ioexception
    {
        if (!getminimumversion().isequalorearlierversionof(serverversion))
        {
            throw new tlsfatalalert(alertdescription.protocol_version);
        }
    }

    public short[] getcompressionmethods()
    {
        return new short[]{compressionmethod._null};
    }

    public void notifysessionid(byte[] sessionid)
    {
        // currently ignored
    }

    public void notifyselectedciphersuite(int selectedciphersuite)
    {
        this.selectedciphersuite = selectedciphersuite;
    }

    public void notifyselectedcompressionmethod(short selectedcompressionmethod)
    {
        this.selectedcompressionmethod = selectedcompressionmethod;
    }

    public void notifysecurerenegotiation(boolean securerenegotiation)
        throws ioexception
    {
        if (!securerenegotiation)
        {
            /*
             * rfc 5746 3.4. in this case, some clients may want to terminate the handshake instead
             * of continuing; see section 4.1 for discussion.
             */
            // throw new tlsfatalalert(alertdescription.handshake_failure);
        }
    }

    public void processserverextensions(hashtable serverextensions)
        throws ioexception
    {
        /*
         * tlsprotocol implementation validates that any server extensions received correspond to
         * client extensions sent. by default, we don't send any, and this method is not called.
         */
        if (serverextensions != null)
        {
            /*
             * rfc 5246 7.4.1.4.1. servers must not send this extension.
             */
            if (serverextensions.containskey(tlsutils.ext_signature_algorithms))
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }
    }

    public void processserversupplementaldata(vector serversupplementaldata)
        throws ioexception
    {
        if (serversupplementaldata != null)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }
    }

    public vector getclientsupplementaldata()
        throws ioexception
    {
        return null;
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
             * note: internal error here; the tlsprotocol implementation verifies that the
             * server-selected compression method was in the list of client-offered compression
             * methods, so if we now can't produce an implementation, we shouldn't have offered it!
             */
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public void notifynewsessionticket(newsessionticket newsessionticket)
        throws ioexception
    {
    }

    public void notifyhandshakecomplete()
        throws ioexception
    {
    }
}
