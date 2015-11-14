package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.security.securerandom;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.crypto.prng.threadedseedgenerator;
import org.ripple.bouncycastle.util.arrays;

public class tlsclientprotocol
    extends tlsprotocol
{

    protected tlsclient tlsclient = null;
    protected tlsclientcontextimpl tlsclientcontext = null;

    protected int[] offeredciphersuites = null;
    protected short[] offeredcompressionmethods = null;
    protected hashtable clientextensions = null;

    protected int selectedciphersuite;
    protected short selectedcompressionmethod;

    protected tlskeyexchange keyexchange = null;
    protected tlsauthentication authentication = null;
    protected certificaterequest certificaterequest = null;

    private static securerandom createsecurerandom()
    {
        /*
         * we use our threaded seed generator to generate a good random seed. if the user has a
         * better random seed, he should use the constructor with a securerandom.
         */
        threadedseedgenerator tsg = new threadedseedgenerator();
        securerandom random = new securerandom();

        /*
         * hopefully, 20 bytes in fast mode are good enough.
         */
        random.setseed(tsg.generateseed(20, true));

        return random;
    }

    public tlsclientprotocol(inputstream input, outputstream output)
    {
        this(input, output, createsecurerandom());
    }

    public tlsclientprotocol(inputstream input, outputstream output, securerandom securerandom)
    {
        super(input, output, securerandom);
    }

    /**
     * initiates a tls handshake in the role of client
     *
     * @param tlsclient
     * @throws ioexception if handshake was not successful.
     */
    public void connect(tlsclient tlsclient)
        throws ioexception
    {
        if (tlsclient == null)
        {
            throw new illegalargumentexception("'tlsclient' cannot be null");
        }
        if (this.tlsclient != null)
        {
            throw new illegalstateexception("connect can only be called once");
        }

        this.tlsclient = tlsclient;

        this.securityparameters = new securityparameters();
        this.securityparameters.entity = connectionend.client;
        this.securityparameters.clientrandom = createrandomblock(securerandom);

        this.tlsclientcontext = new tlsclientcontextimpl(securerandom, securityparameters);
        this.tlsclient.init(tlsclientcontext);
        this.recordstream.init(tlsclientcontext);

        sendclienthellomessage();
        this.connection_state = cs_client_hello;

        completehandshake();

        this.tlsclient.notifyhandshakecomplete();
    }

    protected abstracttlscontext getcontext()
    {
        return tlsclientcontext;
    }

    protected tlspeer getpeer()
    {
        return tlsclient;
    }

    protected void handlechangecipherspecmessage()
        throws ioexception
    {

        switch (this.connection_state)
        {
        case cs_client_finished:
        {
            if (this.expectsessionticket)
            {
                /*
                 * rfc 5077 3.3. this message must be sent if the server included a sessionticket
                 * extension in the serverhello.
                 */
                this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
            }
            // nb: fall through to next case label
        }
        case cs_server_session_ticket:
            this.connection_state = cs_server_change_cipher_spec;
            break;
        default:
            this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
        }
    }

    protected void handlehandshakemessage(short type, byte[] data)
        throws ioexception
    {
        bytearrayinputstream buf = new bytearrayinputstream(data);

        switch (type)
        {
        case handshaketype.certificate:
        {
            switch (this.connection_state)
            {
            case cs_server_hello:
            {
                handlesupplementaldata(null);
                // nb: fall through to next case label
            }
            case cs_server_supplemental_data:
            {
                // parse the certificate message and send to cipher suite

                certificate servercertificate = certificate.parse(buf);

                assertempty(buf);

                this.keyexchange.processservercertificate(servercertificate);

                this.authentication = tlsclient.getauthentication();
                this.authentication.notifyservercertificate(servercertificate);

                break;
            }
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }

            this.connection_state = cs_server_certificate;
            break;
        }
        case handshaketype.finished:
            switch (this.connection_state)
            {
            case cs_server_change_cipher_spec:
                processfinishedmessage(buf);
                this.connection_state = cs_server_finished;
                break;
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            break;
        case handshaketype.server_hello:
            switch (this.connection_state)
            {
            case cs_client_hello:
                receiveserverhellomessage(buf);
                this.connection_state = cs_server_hello;

                securityparameters.prfalgorithm = getprfalgorithm(selectedciphersuite);
                securityparameters.compressionalgorithm = this.selectedcompressionmethod;

                /*
                 * rfc 5264 7.4.9. any cipher suite which does not explicitly specify
                 * verify_data_length has a verify_data_length equal to 12. this includes all
                 * existing cipher suites.
                 */
                securityparameters.verifydatalength = 12;

                recordstream.notifyhellocomplete();

                break;
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            break;
        case handshaketype.supplemental_data:
        {
            switch (this.connection_state)
            {
            case cs_server_hello:
                handlesupplementaldata(readsupplementaldatamessage(buf));
                break;
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            break;
        }
        case handshaketype.server_hello_done:
            switch (this.connection_state)
            {
            case cs_server_hello:
            {
                handlesupplementaldata(null);
                // nb: fall through to next case label
            }
            case cs_server_supplemental_data:
            {

                // there was no server certificate message; check it's ok
                this.keyexchange.skipservercredentials();
                this.authentication = null;

                // nb: fall through to next case label
            }
            case cs_server_certificate:

                // there was no server key exchange message; check it's ok
                this.keyexchange.skipserverkeyexchange();

                // nb: fall through to next case label

            case cs_server_key_exchange:
            case cs_certificate_request:

                assertempty(buf);

                this.connection_state = cs_server_hello_done;

                vector clientsupplementaldata = tlsclient.getclientsupplementaldata();
                if (clientsupplementaldata != null)
                {
                    sendsupplementaldatamessage(clientsupplementaldata);
                }
                this.connection_state = cs_client_supplemental_data;

                tlscredentials clientcreds = null;
                if (certificaterequest == null)
                {
                    this.keyexchange.skipclientcredentials();
                }
                else
                {
                    clientcreds = this.authentication.getclientcredentials(certificaterequest);

                    if (clientcreds == null)
                    {
                        this.keyexchange.skipclientcredentials();

                        /*
                         * rfc 5246 if no suitable certificate is available, the client must send a
                         * certificate message containing no certificates.
                         * 
                         * note: in previous rfcs, this was should instead of must.
                         */
                        sendcertificatemessage(certificate.empty_chain);
                    }
                    else
                    {
                        this.keyexchange.processclientcredentials(clientcreds);

                        sendcertificatemessage(clientcreds.getcertificate());
                    }
                }

                this.connection_state = cs_client_certificate;

                /*
                 * send the client key exchange message, depending on the key exchange we are using
                 * in our ciphersuite.
                 */
                sendclientkeyexchangemessage();

                establishmastersecret(getcontext(), keyexchange);

                /*
                 * initialize our cipher suite
                 */
                recordstream.setpendingconnectionstate(tlsclient.getcompression(), tlsclient.getcipher());

                this.connection_state = cs_client_key_exchange;

                if (clientcreds != null && clientcreds instanceof tlssignercredentials)
                {
                    /*
                     * todo rfc 5246 4.7. digitally-signed element needs signatureandhashalgorithm
                     * prepended from tls 1.2
                     */
                    tlssignercredentials signercreds = (tlssignercredentials)clientcreds;
                    byte[] md5andsha1 = recordstream.getcurrenthash(null);
                    byte[] clientcertificatesignature = signercreds.generatecertificatesignature(md5andsha1);
                    sendcertificateverifymessage(clientcertificatesignature);

                    this.connection_state = cs_certificate_verify;
                }

                sendchangecipherspecmessage();
                this.connection_state = cs_client_change_cipher_spec;

                sendfinishedmessage();
                this.connection_state = cs_client_finished;
                break;
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
            }
            break;
        case handshaketype.server_key_exchange:
        {
            switch (this.connection_state)
            {
            case cs_server_hello:
            {
                handlesupplementaldata(null);
                // nb: fall through to next case label
            }
            case cs_server_supplemental_data:
            {

                // there was no server certificate message; check it's ok
                this.keyexchange.skipservercredentials();
                this.authentication = null;

                // nb: fall through to next case label
            }
            case cs_server_certificate:

                this.keyexchange.processserverkeyexchange(buf);

                assertempty(buf);
                break;

            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }

            this.connection_state = cs_server_key_exchange;
            break;
        }
        case handshaketype.certificate_request:
        {
            switch (this.connection_state)
            {
            case cs_server_certificate:

                // there was no server key exchange message; check it's ok
                this.keyexchange.skipserverkeyexchange();

                // nb: fall through to next case label

            case cs_server_key_exchange:
            {
                if (this.authentication == null)
                {
                    /*
                     * rfc 2246 7.4.4. it is a fatal handshake_failure alert for an anonymous server
                     * to request client identification.
                     */
                    this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
                }

                this.certificaterequest = certificaterequest.parse(buf);

                assertempty(buf);

                this.keyexchange.validatecertificaterequest(this.certificaterequest);

                break;
            }
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }

            this.connection_state = cs_certificate_request;
            break;
        }
        case handshaketype.session_ticket:
        {
            switch (this.connection_state)
            {
            case cs_client_finished:
                if (!this.expectsessionticket)
                {
                    /*
                     * rfc 5077 3.3. this message must not be sent if the server did not include a
                     * sessionticket extension in the serverhello.
                     */
                    this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
                }
                receivenewsessionticketmessage(buf);
                this.connection_state = cs_server_session_ticket;
                break;
            default:
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
        }
        case handshaketype.hello_request:

            assertempty(buf);

            /*
             * rfc 2246 7.4.1.1 hello request this message will be ignored by the client if the
             * client is currently negotiating a session. this message may be ignored by the client
             * if it does not wish to renegotiate a session, or the client may, if it wishes,
             * respond with a no_renegotiation alert.
             */
            if (this.connection_state == cs_server_finished)
            {
                string message = "renegotiation not supported";
                raisewarning(alertdescription.no_renegotiation, message);
            }
            break;
        case handshaketype.client_key_exchange:
        case handshaketype.certificate_verify:
        case handshaketype.client_hello:
        case handshaketype.hello_verify_request:
        default:
            // we do not support this!
            this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            break;
        }
    }

    protected void handlesupplementaldata(vector serversupplementaldata)
        throws ioexception
    {

        this.tlsclient.processserversupplementaldata(serversupplementaldata);
        this.connection_state = cs_server_supplemental_data;

        this.keyexchange = tlsclient.getkeyexchange();
        this.keyexchange.init(getcontext());
    }

    protected void receivenewsessionticketmessage(bytearrayinputstream buf)
        throws ioexception
    {

        newsessionticket newsessionticket = newsessionticket.parse(buf);

        tlsprotocol.assertempty(buf);

        tlsclient.notifynewsessionticket(newsessionticket);
    }

    protected void receiveserverhellomessage(bytearrayinputstream buf)
        throws ioexception
    {

        protocolversion server_version = tlsutils.readversion(buf);
        if (server_version.isdtls())
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        // check that this matches what the server is sending in the record layer
        if (!server_version.equals(recordstream.getreadversion()))
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        protocolversion client_version = getcontext().getclientversion();
        if (!server_version.isequalorearlierversionof(client_version))
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        this.recordstream.setwriteversion(server_version);
        getcontext().setserverversion(server_version);
        this.tlsclient.notifyserverversion(server_version);

        /*
         * read the server random
         */
        securityparameters.serverrandom = tlsutils.readfully(32, buf);

        byte[] sessionid = tlsutils.readopaque8(buf);
        if (sessionid.length > 32)
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        this.tlsclient.notifysessionid(sessionid);

        /*
         * find out which ciphersuite the server has chosen and check that it was one of the offered
         * ones.
         */
        this.selectedciphersuite = tlsutils.readuint16(buf);
        if (!arraycontains(offeredciphersuites, this.selectedciphersuite)
            || this.selectedciphersuite == ciphersuite.tls_null_with_null_null
            || this.selectedciphersuite == ciphersuite.tls_empty_renegotiation_info_scsv)
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        this.tlsclient.notifyselectedciphersuite(this.selectedciphersuite);

        /*
         * find out which compressionmethod the server has chosen and check that it was one of the
         * offered ones.
         */
        short selectedcompressionmethod = tlsutils.readuint8(buf);
        if (!arraycontains(offeredcompressionmethods, selectedcompressionmethod))
        {
            this.failwitherror(alertlevel.fatal, alertdescription.illegal_parameter);
        }

        this.tlsclient.notifyselectedcompressionmethod(selectedcompressionmethod);

        /*
         * rfc3546 2.2 the extended server hello message format may be sent in place of the server
         * hello message when the client has requested extended functionality via the extended
         * client hello message specified in section 2.1. ... note that the extended server hello
         * message is only sent in response to an extended client hello message. this prevents the
         * possibility that the extended server hello message could "break" existing tls 1.0
         * clients.
         */

        /*
         * todo rfc 3546 2.3 if [...] the older session is resumed, then the server must ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        // integer -> byte[]
        hashtable serverextensions = readextensions(buf);

        /*
         * rfc 3546 2.2 note that the extended server hello message is only sent in response to an
         * extended client hello message.
         * 
         * however, see rfc 5746 exception below. we always include the scsv, so an extended server
         * hello is always allowed.
         */
        if (serverextensions != null)
        {
            enumeration e = serverextensions.keys();
            while (e.hasmoreelements())
            {
                integer exttype = (integer)e.nextelement();

                /*
                 * rfc 5746 3.6. note that sending a "renegotiation_info" extension in response to a
                 * clienthello containing only the scsv is an explicit exception to the prohibition
                 * in rfc 5246, section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the tls_empty_renegotiation_info_scsv scsv.
                 */
                if (!exttype.equals(ext_renegotiationinfo)
                    && (clientextensions == null || clientextensions.get(exttype) == null))
                {
                    /*
                     * rfc 5246 7.4.1.4 an extension type must not appear in the serverhello unless
                     * the same extension type appeared in the corresponding clienthello. if a
                     * client receives an extension type in serverhello that it did not request in
                     * the associated clienthello, it must abort the handshake with an
                     * unsupported_extension fatal alert.
                     */
                    this.failwitherror(alertlevel.fatal, alertdescription.unsupported_extension);
                }
            }

            /*
             * rfc 5746 3.4. client behavior: initial handshake
             */
            {
                /*
                 * when a serverhello is received, the client must check if it includes the
                 * "renegotiation_info" extension:
                 */
                byte[] renegextvalue = (byte[])serverextensions.get(ext_renegotiationinfo);
                if (renegextvalue != null)
                {
                    /*
                     * if the extension is present, set the secure_renegotiation flag to true. the
                     * client must then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, must abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    this.secure_renegotiation = true;

                    if (!arrays.constanttimeareequal(renegextvalue, createrenegotiationinfo(tlsutils.empty_bytes)))
                    {
                        this.failwitherror(alertlevel.fatal, alertdescription.handshake_failure);
                    }
                }
            }

            this.expectsessionticket = serverextensions.containskey(ext_sessionticket);
        }

        tlsclient.notifysecurerenegotiation(this.secure_renegotiation);

        if (clientextensions != null)
        {
            tlsclient.processserverextensions(serverextensions);
        }
    }

    protected void sendcertificateverifymessage(byte[] data)
        throws ioexception
    {
        /*
         * send signature of handshake messages so far to prove we are the owner of the cert see rfc
         * 2246 sections 4.7, 7.4.3 and 7.4.8
         */
        bytearrayoutputstream bos = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.certificate_verify, bos);
        tlsutils.writeuint24(data.length + 2, bos);
        tlsutils.writeopaque16(data, bos);
        byte[] message = bos.tobytearray();

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendclienthellomessage()
        throws ioexception
    {

        recordstream.setwriteversion(this.tlsclient.getclienthellorecordlayerversion());

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.client_hello, buf);

        // reserve space for length
        tlsutils.writeuint24(0, buf);

        protocolversion client_version = this.tlsclient.getclientversion();
        if (client_version.isdtls())
        {
            this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
        }

        getcontext().setclientversion(client_version);
        tlsutils.writeversion(client_version, buf);

        buf.write(securityparameters.clientrandom);

        // session id
        tlsutils.writeopaque8(tlsutils.empty_bytes, buf);

        /*
         * cipher suites
         */
        this.offeredciphersuites = this.tlsclient.getciphersuites();

        // integer -> byte[]
        this.clientextensions = this.tlsclient.getclientextensions();

        // cipher suites (and scsv)
        {
            /*
             * rfc 5746 3.4. the client must include either an empty "renegotiation_info" extension,
             * or the tls_empty_renegotiation_info_scsv signaling cipher suite value in the
             * clienthello. including both is not recommended.
             */
            boolean norenegext = clientextensions == null || clientextensions.get(ext_renegotiationinfo) == null;

            int count = offeredciphersuites.length;
            if (norenegext)
            {
                // note: 1 extra slot for tls_empty_renegotiation_info_scsv
                ++count;
            }

            tlsutils.writeuint16(2 * count, buf);
            tlsutils.writeuint16array(offeredciphersuites, buf);

            if (norenegext)
            {
                tlsutils.writeuint16(ciphersuite.tls_empty_renegotiation_info_scsv, buf);
            }
        }

        // compression methods
        this.offeredcompressionmethods = this.tlsclient.getcompressionmethods();

        tlsutils.writeuint8((short)offeredcompressionmethods.length, buf);
        tlsutils.writeuint8array(offeredcompressionmethods, buf);

        // extensions
        if (clientextensions != null)
        {
            writeextensions(buf, clientextensions);
        }

        byte[] message = buf.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendclientkeyexchangemessage()
        throws ioexception
    {
        bytearrayoutputstream bos = new bytearrayoutputstream();

        tlsutils.writeuint8(handshaketype.client_key_exchange, bos);

        // reserve space for length
        tlsutils.writeuint24(0, bos);

        this.keyexchange.generateclientkeyexchange(bos);
        byte[] message = bos.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }
}
