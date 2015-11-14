package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.securerandom;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;
import org.ripple.bouncycastle.util.arrays;

public class tlsserverprotocol
    extends tlsprotocol
{

    protected tlsserver tlsserver = null;
    protected tlsservercontextimpl tlsservercontext = null;

    protected int[] offeredciphersuites;
    protected short[] offeredcompressionmethods;
    protected hashtable clientextensions;

    protected int selectedciphersuite;
    protected short selectedcompressionmethod;
    protected hashtable serverextensions;

    protected tlskeyexchange keyexchange = null;
    protected tlscredentials servercredentials = null;
    protected certificaterequest certificaterequest = null;

    protected short clientcertificatetype = -1;
    protected certificate clientcertificate = null;
    protected byte[] certificateverifyhash = null;

    public tlsserverprotocol(inputstream input, outputstream output, securerandom securerandom)
    {
        super(input, output, securerandom);
    }

    /**
     * receives a tls handshake in the role of server
     *
     * @param tlsserver
     * @throws ioexception if handshake was not successful.
     */
    public void accept(tlsserver tlsserver)
        throws ioexception
    {

        if (tlsserver == null)
        {
            throw new illegalargumentexception("'tlsserver' cannot be null");
        }
        if (this.tlsserver != null)
        {
            throw new illegalstateexception("accept can only be called once");
        }

        this.tlsserver = tlsserver;

        this.securityparameters = new securityparameters();
        this.securityparameters.entity = connectionend.server;
        this.securityparameters.serverrandom = createrandomblock(securerandom);

        this.tlsservercontext = new tlsservercontextimpl(securerandom, securityparameters);
        this.tlsserver.init(tlsservercontext);
        this.recordstream.init(tlsservercontext);

        this.recordstream.setrestrictreadversion(false);

        completehandshake();

        this.tlsserver.notifyhandshakecomplete();
    }

    protected abstracttlscontext getcontext()
    {
        return tlsservercontext;
    }

    protected tlspeer getpeer()
    {
        return tlsserver;
    }

    protected void handlechangecipherspecmessage()
        throws ioexception
    {

        switch (this.connection_state)
        {
        case cs_client_key_exchange:
        {
            if (this.certificateverifyhash != null)
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            // nb: fall through to next case label
        }
        case cs_certificate_verify:
        {
            this.connection_state = cs_client_change_cipher_spec;
            break;
        }
        default:
        {
            this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
        }
        }
    }

    protected void handlehandshakemessage(short type, byte[] data)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(data);

        switch (type)
        {
        case handshaketype.client_hello:
        {
            switch (this.connection_state)
            {
            case cs_start:
            {
                receiveclienthellomessage(buf);
                this.connection_state = cs_client_hello;

                sendserverhellomessage();
                this.connection_state = cs_server_hello;

                // todo this block could really be done before actually sending the hello
                {
                    securityparameters.prfalgorithm = getprfalgorithm(selectedciphersuite);
                    securityparameters.compressionalgorithm = this.selectedcompressionmethod;

                    /*
                     * rfc 5264 7.4.9. any cipher suite which does not explicitly specify
                     * verify_data_length has a verify_data_length equal to 12. this includes all
                     * existing cipher suites.
                     */
                    securityparameters.verifydatalength = 12;

                    recordstream.notifyhellocomplete();
                }

                vector serversupplementaldata = tlsserver.getserversupplementaldata();
                if (serversupplementaldata != null)
                {
                    sendsupplementaldatamessage(serversupplementaldata);
                }
                this.connection_state = cs_server_supplemental_data;

                this.keyexchange = tlsserver.getkeyexchange();
                this.keyexchange.init(getcontext());

                this.servercredentials = tlsserver.getcredentials();
                if (this.servercredentials == null)
                {
                    this.keyexchange.skipservercredentials();
                }
                else
                {
                    this.keyexchange.processservercredentials(this.servercredentials);
                    sendcertificatemessage(this.servercredentials.getcertificate());
                }
                this.connection_state = cs_server_certificate;

                byte[] serverkeyexchange = this.keyexchange.generateserverkeyexchange();
                if (serverkeyexchange != null)
                {
                    sendserverkeyexchangemessage(serverkeyexchange);
                }
                this.connection_state = cs_server_key_exchange;

                if (this.servercredentials != null)
                {
                    this.certificaterequest = tlsserver.getcertificaterequest();
                    if (this.certificaterequest != null)
                    {
                        this.keyexchange.validatecertificaterequest(certificaterequest);
                        sendcertificaterequestmessage(certificaterequest);
                    }
                }
                this.connection_state = cs_certificate_request;

                sendserverhellodonemessage();
                this.connection_state = cs_server_hello_done;

                break;
            }
            default:
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            }
            break;
        }
        case handshaketype.supplemental_data:
        {
            switch (this.connection_state)
            {
            case cs_server_hello_done:
            {
                tlsserver.processclientsupplementaldata(readsupplementaldatamessage(buf));
                this.connection_state = cs_client_supplemental_data;
                break;
            }
            default:
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            }
            break;
        }
        case handshaketype.certificate:
        {
            switch (this.connection_state)
            {
            case cs_server_hello_done:
            {
                tlsserver.processclientsupplementaldata(null);
                // nb: fall through to next case label
            }
            case cs_client_supplemental_data:
            {
                if (this.certificaterequest == null)
                {
                    this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
                }
                receivecertificatemessage(buf);
                this.connection_state = cs_client_certificate;
                break;
            }
            default:
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            }
            break;
        }
        case handshaketype.client_key_exchange:
        {
            switch (this.connection_state)
            {
            case cs_server_hello_done:
            {
                tlsserver.processclientsupplementaldata(null);
                // nb: fall through to next case label
            }
            case cs_client_supplemental_data:
            {
                if (this.certificaterequest == null)
                {
                    this.keyexchange.skipclientcredentials();
                }
                else
                {

                    protocolversion equivalenttlsversion = getcontext().getserverversion().getequivalenttlsversion();

                    if (protocolversion.tlsv12.isequalorearlierversionof(equivalenttlsversion))
                    {
                        /*
                         * rfc 5246 if no suitable certificate is available, the client must send a
                         * certificate message containing no certificates.
                         * 
                         * note: in previous rfcs, this was should instead of must.
                         */
                        this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
                    }
                    else if (equivalenttlsversion.isssl())
                    {
                        if (clientcertificate == null)
                        {
                            this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
                        }
                    }
                    else
                    {
                        notifyclientcertificate(certificate.empty_chain);
                    }
                }
                // nb: fall through to next case label
            }
            case cs_client_certificate:
            {
                receiveclientkeyexchangemessage(buf);
                this.connection_state = cs_client_key_exchange;
                break;
            }
            default:
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            }
            break;
        }
        case handshaketype.certificate_verify:
        {
            switch (this.connection_state)
            {
            case cs_client_key_exchange:
            {
                /*
                 * rfc 5246 7.4.8 this message is only sent following a client certificate that has
                 * signing capability (i.e., all certificates except those containing fixed
                 * diffie-hellman parameters).
                 */
                if (this.certificateverifyhash == null)
                {
                    this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
                }
                receivecertificateverifymessage(buf);
                this.connection_state = cs_certificate_verify;
                break;
            }
            default:
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            }
            break;
        }
        case handshaketype.finished:
        {
            switch (this.connection_state)
            {
            case cs_client_change_cipher_spec:
                processfinishedmessage(buf);
                this.connection_state = cs_client_finished;

                if (expectsessionticket)
                {
                    sendnewsessionticketmessage(tlsserver.getnewsessionticket());
                }
                this.connection_state = cs_server_session_ticket;

                sendchangecipherspecmessage();
                this.connection_state = cs_server_change_cipher_spec;

                sendfinishedmessage();
                this.connection_state = cs_server_finished;
                break;
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            break;
        }
        case handshaketype.hello_request:
        case handshaketype.hello_verify_request:
        case handshaketype.server_hello:
        case handshaketype.server_key_exchange:
        case handshaketype.certificate_request:
        case handshaketype.server_hello_done:
        case handshaketype.session_ticket:
        default:
            // we do not support this!
            this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            break;
        }
    }

    protected void handlewarningmessage(short description)
        throws ioexception
    {
        switch (description)
        {
        case alertdescription.no_certificate:
        {
            /*
             * ssl 3.0 if the server has sent a certificate request message, the client must send
             * either the certificate message or a no_certificate alert.
             */
            if (getcontext().getserverversion().isssl() && certificaterequest != null)
            {
                notifyclientcertificate(certificate.empty_chain);
            }
            break;
        }
        default:
        {
            super.handlewarningmessage(description);
        }
        }
    }

    protected void notifyclientcertificate(certificate clientcertificate)
        throws ioexception
    {

        if (certificaterequest == null)
        {
            throw new illegalstateexception();
        }

        if (this.clientcertificate != null)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        this.clientcertificate = clientcertificate;

        if (clientcertificate.isempty())
        {
            this.keyexchange.skipclientcredentials();
        }
        else
        {

            /*
             * todo rfc 5246 7.4.6. if the certificate_authorities list in the certificate request
             * message was non-empty, one of the certificates in the certificate chain should be
             * issued by one of the listed cas.
             */

            this.clientcertificatetype = tlsutils.getclientcertificatetype(clientcertificate,
                this.servercredentials.getcertificate());

            this.keyexchange.processclientcertificate(clientcertificate);
        }

        /*
         * rfc 5246 7.4.6. if the client does not send any certificates, the server may at its
         * discretion either continue the handshake without client authentication, or respond with a
         * fatal handshake_failure alert. also, if some aspect of the certificate chain was
         * unacceptable (e.g., it was not signed by a known, trusted ca), the server may at its
         * discretion either continue the handshake (considering the client unauthenticated) or send
         * a fatal alert.
         */
        this.tlsserver.notifyclientcertificate(clientcertificate);
    }

    protected void receivecertificatemessage(bytearrayinputstream buf)
        throws ioexception
    {

        certificate clientcertificate = certificate.parse(buf);

        assertempty(buf);

        notifyclientcertificate(clientcertificate);
    }

    protected void receivecertificateverifymessage(bytearrayinputstream buf)
        throws ioexception
    {

        byte[] clientcertificatesignature = tlsutils.readopaque16(buf);

        assertempty(buf);

        // verify the certificateverify message contains a correct signature.
        try
        {
            tlssigner tlssigner = tlsutils.createtlssigner(this.clientcertificatetype);
            tlssigner.init(getcontext());

            org.ripple.bouncycastle.asn1.x509.certificate x509cert = this.clientcertificate.getcertificateat(0);
            subjectpublickeyinfo keyinfo = x509cert.getsubjectpublickeyinfo();
            asymmetrickeyparameter publickey = publickeyfactory.createkey(keyinfo);

            tlssigner.verifyrawsignature(clientcertificatesignature, publickey, this.certificateverifyhash);
        }
        catch (exception e)
        {
            throw new tlsfatalalert(alertdescription.decrypt_error);
        }
    }

    protected void receiveclienthellomessage(bytearrayinputstream buf)
        throws ioexception
    {

        protocolversion client_version = tlsutils.readversion(buf);
        if (client_version.isdtls())
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        /*
         * read the client random
         */
        byte[] client_random = tlsutils.readfully(32, buf);

        byte[] sessionid = tlsutils.readopaque8(buf);
        if (sessionid.length > 32)
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        int cipher_suites_length = tlsutils.readuint16(buf);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
        {
            this.failwitherror(alertlevel.fatal, alertdescription.decode_error);
        }

        /*
         * note: "if the session_id field is not empty (implying a session resumption request) this
         * vector must include at least the cipher_suite from that session."
         */
        this.offeredciphersuites = tlsutils.readuint16array(cipher_suites_length / 2, buf);

        int compression_methods_length = tlsutils.readuint8(buf);
        if (compression_methods_length < 1)
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        this.offeredcompressionmethods = tlsutils.readuint8array(compression_methods_length, buf);

        /*
         * todo rfc 3546 2.3 if [...] the older session is resumed, then the server must ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        this.clientextensions = readextensions(buf);

        getcontext().setclientversion(client_version);

        tlsserver.notifyclientversion(client_version);

        securityparameters.clientrandom = client_random;

        tlsserver.notifyofferedciphersuites(offeredciphersuites);
        tlsserver.notifyofferedcompressionmethods(offeredcompressionmethods);

        /*
         * rfc 5746 3.6. server behavior: initial handshake
         */
        {
            /*
             * rfc 5746 3.4. the client must include either an empty "renegotiation_info" extension,
             * or the tls_empty_renegotiation_info_scsv signaling cipher suite value in the
             * clienthello. including both is not recommended.
             */

            /*
             * when a clienthello is received, the server must check if it includes the
             * tls_empty_renegotiation_info_scsv scsv. if it does, set the secure_renegotiation flag
             * to true.
             */
            if (arraycontains(offeredciphersuites, ciphersuite.tls_empty_renegotiation_info_scsv))
            {
                this.secure_renegotiation = true;
            }

            /*
             * the server must check if the "renegotiation_info" extension is included in the
             * clienthello.
             */
            if (clientextensions != null)
            {
                byte[] renegextvalue = (byte[])clientextensions.get(ext_renegotiationinfo);
                if (renegextvalue != null)
                {
                    /*
                     * if the extension is present, set secure_renegotiation flag to true. the
                     * server must then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, must abort the handshake.
                     */
                    this.secure_renegotiation = true;

                    if (!arrays.constanttimeareequal(renegextvalue, createrenegotiationinfo(tlsutils.empty_bytes)))
                    {
                        this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
                    }
                }
            }
        }

        tlsserver.notifysecurerenegotiation(this.secure_renegotiation);

        if (clientextensions != null)
        {
            tlsserver.processclientextensions(clientextensions);
        }
    }

    protected void receiveclientkeyexchangemessage(bytearrayinputstream buf)
        throws ioexception
    {

        this.keyexchange.processclientkeyexchange(buf);

        assertempty(buf);

        establishmastersecret(getcontext(), keyexchange);

        /*
         * initialize our cipher suite
         */
        recordstream.setpendingconnectionstate(tlsserver.getcompression(), tlsserver.getcipher());

        if (expectcertificateverifymessage())
        {
            this.certificateverifyhash = recordstream.getcurrenthash(null);
        }
    }

    protected void sendcertificaterequestmessage(certificaterequest certificaterequest)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.certificate_request, buf);

        // reserve space for length
        tlsutils.writeuint24(0, buf);

        certificaterequest.encode(buf);
        byte[] message = buf.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendnewsessionticketmessage(newsessionticket newsessionticket)
        throws ioexception
    {

        if (newsessionticket == null)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.session_ticket, buf);

        // reserve space for length
        tlsutils.writeuint24(0, buf);

        newsessionticket.encode(buf);
        byte[] message = buf.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendserverhellomessage()
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.server_hello, buf);

        // reserve space for length
        tlsutils.writeuint24(0, buf);

        protocolversion server_version = tlsserver.getserverversion();
        if (!server_version.isequalorearlierversionof(getcontext().getclientversion()))
        {
            this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
        }

        recordstream.setreadversion(server_version);
        recordstream.setwriteversion(server_version);
        recordstream.setrestrictreadversion(true);
        getcontext().setserverversion(server_version);

        tlsutils.writeversion(server_version, buf);

        buf.write(this.securityparameters.serverrandom);

        /*
         * the server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        tlsutils.writeopaque8(tlsutils.empty_bytes, buf);

        this.selectedciphersuite = tlsserver.getselectedciphersuite();
        if (!arraycontains(this.offeredciphersuites, this.selectedciphersuite)
            || this.selectedciphersuite == ciphersuite.tls_null_with_null_null
            || this.selectedciphersuite == ciphersuite.tls_empty_renegotiation_info_scsv)
        {
            this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
        }

        this.selectedcompressionmethod = tlsserver.getselectedcompressionmethod();
        if (!arraycontains(this.offeredcompressionmethods, this.selectedcompressionmethod))
        {
            this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
        }

        tlsutils.writeuint16(this.selectedciphersuite, buf);
        tlsutils.writeuint8(this.selectedcompressionmethod, buf);

        this.serverextensions = tlsserver.getserverextensions();

        /*
         * rfc 5746 3.6. server behavior: initial handshake
         */
        if (this.secure_renegotiation)
        {

            boolean norenegext = this.serverextensions == null
                || !this.serverextensions.containskey(ext_renegotiationinfo);

            if (norenegext)
            {
                /*
                 * note that sending a "renegotiation_info" extension in response to a clienthello
                 * containing only the scsv is an explicit exception to the prohibition in rfc 5246,
                 * section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                 * because the client is signaling its willingness to receive the extension via the
                 * tls_empty_renegotiation_info_scsv scsv.
                 */
                if (this.serverextensions == null)
                {
                    this.serverextensions = new hashtable();
                }

                /*
                 * if the secure_renegotiation flag is set to true, the server must include an empty
                 * "renegotiation_info" extension in the serverhello message.
                 */
                this.serverextensions.put(ext_renegotiationinfo, createrenegotiationinfo(tlsutils.empty_bytes));
            }
        }

        if (this.serverextensions != null)
        {
            this.expectsessionticket = serverextensions.containskey(ext_sessionticket);
            writeextensions(buf, this.serverextensions);
        }

        byte[] message = buf.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendserverhellodonemessage()
        throws ioexception
    {

        byte[] message = new byte[4];
        tlsutils.writeuint8(handshaketype.server_hello_done, message, 0);
        tlsutils.writeuint24(0, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendserverkeyexchangemessage(byte[] serverkeyexchange)
        throws ioexception
    {
        bytearrayoutputstream bos = new bytearrayoutputstream();

        tlsutils.writeuint8(handshaketype.server_key_exchange, bos);
        tlsutils.writeuint24(serverkeyexchange.length, bos);
        bos.write(serverkeyexchange);
        byte[] message = bos.tobytearray();

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected boolean expectcertificateverifymessage()
    {
        return this.clientcertificatetype >= 0 && tlsutils.hassigningcapability(this.clientcertificatetype);
    }
}
