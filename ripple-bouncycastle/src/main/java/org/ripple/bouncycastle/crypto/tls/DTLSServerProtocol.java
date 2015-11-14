package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.security.securerandom;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;
import org.ripple.bouncycastle.util.arrays;

public class dtlsserverprotocol
    extends dtlsprotocol
{

    protected boolean verifyrequests = true;

    public dtlsserverprotocol(securerandom securerandom)
    {
        super(securerandom);
    }

    public boolean getverifyrequests()
    {
        return verifyrequests;
    }

    public void setverifyrequests(boolean verifyrequests)
    {
        this.verifyrequests = verifyrequests;
    }

    public dtlstransport accept(tlsserver server, datagramtransport transport)
        throws ioexception
    {

        if (server == null)
        {
            throw new illegalargumentexception("'server' cannot be null");
        }
        if (transport == null)
        {
            throw new illegalargumentexception("'transport' cannot be null");
        }

        securityparameters securityparameters = new securityparameters();
        securityparameters.entity = connectionend.server;
        securityparameters.serverrandom = tlsprotocol.createrandomblock(securerandom);

        serverhandshakestate state = new serverhandshakestate();
        state.server = server;
        state.servercontext = new tlsservercontextimpl(securerandom, securityparameters);
        server.init(state.servercontext);

        dtlsrecordlayer recordlayer = new dtlsrecordlayer(transport, state.servercontext, server, contenttype.handshake);

        // todo need to handle sending of helloverifyrequest without entering a full connection

        try
        {
            return serverhandshake(state, recordlayer);
        }
        catch (tlsfatalalert fatalalert)
        {
            recordlayer.fail(fatalalert.getalertdescription());
            throw fatalalert;
        }
        catch (ioexception e)
        {
            recordlayer.fail(alertdescription.internal_error);
            throw e;
        }
        catch (runtimeexception e)
        {
            recordlayer.fail(alertdescription.internal_error);
            throw new tlsfatalalert(alertdescription.internal_error);
        }
    }

    public dtlstransport serverhandshake(serverhandshakestate state, dtlsrecordlayer recordlayer)
        throws ioexception
    {

        securityparameters securityparameters = state.servercontext.getsecurityparameters();
        dtlsreliablehandshake handshake = new dtlsreliablehandshake(state.servercontext, recordlayer);

        dtlsreliablehandshake.message clientmessage = handshake.receivemessage();

        {
            // note: after receiving a record from the client, we discover the record layer version
            protocolversion client_version = recordlayer.getdiscoveredpeerversion();
            // todo read rfcs for guidance on the expected record layer version number
            state.servercontext.setclientversion(client_version);
        }

        if (clientmessage.gettype() == handshaketype.client_hello)
        {
            processclienthello(state, clientmessage.getbody());
        }
        else
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        byte[] serverhellobody = generateserverhello(state);
        handshake.sendmessage(handshaketype.server_hello, serverhellobody);

        // todo this block could really be done before actually sending the hello
        {
            securityparameters.prfalgorithm = tlsprotocol.getprfalgorithm(state.selectedciphersuite);
            securityparameters.compressionalgorithm = state.selectedcompressionmethod;

            /*
             * rfc 5264 7.4.9. any cipher suite which does not explicitly specify verify_data_length
             * has a verify_data_length equal to 12. this includes all existing cipher suites.
             */
            securityparameters.verifydatalength = 12;

            handshake.notifyhellocomplete();
        }

        vector serversupplementaldata = state.server.getserversupplementaldata();
        if (serversupplementaldata != null)
        {
            byte[] supplementaldatabody = generatesupplementaldata(serversupplementaldata);
            handshake.sendmessage(handshaketype.supplemental_data, supplementaldatabody);
        }

        state.keyexchange = state.server.getkeyexchange();
        state.keyexchange.init(state.servercontext);

        state.servercredentials = state.server.getcredentials();
        if (state.servercredentials == null)
        {
            state.keyexchange.skipservercredentials();
        }
        else
        {
            state.keyexchange.processservercredentials(state.servercredentials);

            byte[] certificatebody = generatecertificate(state.servercredentials.getcertificate());
            handshake.sendmessage(handshaketype.certificate, certificatebody);
        }

        byte[] serverkeyexchange = state.keyexchange.generateserverkeyexchange();
        if (serverkeyexchange != null)
        {
            handshake.sendmessage(handshaketype.server_key_exchange, serverkeyexchange);
        }

        if (state.servercredentials != null)
        {
            state.certificaterequest = state.server.getcertificaterequest();
            if (state.certificaterequest != null)
            {
                state.keyexchange.validatecertificaterequest(state.certificaterequest);

                byte[] certificaterequestbody = generatecertificaterequest(state, state.certificaterequest);
                handshake.sendmessage(handshaketype.certificate_request, certificaterequestbody);
            }
        }

        handshake.sendmessage(handshaketype.server_hello_done, tlsutils.empty_bytes);

        clientmessage = handshake.receivemessage();

        if (clientmessage.gettype() == handshaketype.supplemental_data)
        {
            processclientsupplementaldata(state, clientmessage.getbody());
            clientmessage = handshake.receivemessage();
        }
        else
        {
            state.server.processclientsupplementaldata(null);
        }

        if (state.certificaterequest == null)
        {
            state.keyexchange.skipclientcredentials();
        }
        else
        {
            if (clientmessage.gettype() == handshaketype.certificate)
            {
                processclientcertificate(state, clientmessage.getbody());
                clientmessage = handshake.receivemessage();
            }
            else
            {
                protocolversion equivalenttlsversion = state.servercontext.getserverversion().getequivalenttlsversion();

                if (protocolversion.tlsv12.isequalorearlierversionof(equivalenttlsversion))
                {
                    /*
                     * rfc 5246 if no suitable certificate is available, the client must send a
                     * certificate message containing no certificates.
                     * 
                     * note: in previous rfcs, this was should instead of must.
                     */
                    throw new tlsfatalalert(alertdescription.unexpected_message);
                }

                notifyclientcertificate(state, certificate.empty_chain);
            }
        }

        if (clientmessage.gettype() == handshaketype.client_key_exchange)
        {
            processclientkeyexchange(state, clientmessage.getbody());
        }
        else
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        recordlayer.initpendingepoch(state.server.getcipher());

        /*
         * rfc 5246 7.4.8 this message is only sent following a client certificate that has signing
         * capability (i.e., all certificates except those containing fixed diffie-hellman
         * parameters).
         */
        if (expectcertificateverifymessage(state))
        {
            byte[] certificateverifyhash = handshake.getcurrenthash();
            clientmessage = handshake.receivemessage();

            if (clientmessage.gettype() == handshaketype.certificate_verify)
            {
                processcertificateverify(state, clientmessage.getbody(), certificateverifyhash);
            }
            else
            {
                throw new tlsfatalalert(alertdescription.unexpected_message);
            }
        }

        // note: calculated exclusive of the actual finished message from the client
        byte[] clientfinishedhash = handshake.getcurrenthash();
        clientmessage = handshake.receivemessage();

        if (clientmessage.gettype() == handshaketype.finished)
        {
            byte[] expectedclientverifydata = tlsutils.calculateverifydata(state.servercontext, "client finished",
                clientfinishedhash);
            processfinished(clientmessage.getbody(), expectedclientverifydata);
        }
        else
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        if (state.expectsessionticket)
        {
            newsessionticket newsessionticket = state.server.getnewsessionticket();
            byte[] newsessionticketbody = generatenewsessionticket(state, newsessionticket);
            handshake.sendmessage(handshaketype.session_ticket, newsessionticketbody);
        }

        // note: calculated exclusive of the finished message itself
        byte[] serververifydata = tlsutils.calculateverifydata(state.servercontext, "server finished",
            handshake.getcurrenthash());
        handshake.sendmessage(handshaketype.finished, serververifydata);

        handshake.finish();

        state.server.notifyhandshakecomplete();

        return new dtlstransport(recordlayer);
    }

    protected byte[] generatecertificaterequest(serverhandshakestate state, certificaterequest certificaterequest)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        certificaterequest.encode(buf);
        return buf.tobytearray();
    }

    protected byte[] generatenewsessionticket(serverhandshakestate state, newsessionticket newsessionticket)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        newsessionticket.encode(buf);
        return buf.tobytearray();
    }

    protected byte[] generateserverhello(serverhandshakestate state)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();

        protocolversion server_version = state.server.getserverversion();
        if (!server_version.isequalorearlierversionof(state.servercontext.getclientversion()))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        // todo read rfcs for guidance on the expected record layer version number
        // recordstream.setreadversion(server_version);
        // recordstream.setwriteversion(server_version);
        // recordstream.setrestrictreadversion(true);
        state.servercontext.setserverversion(server_version);

        tlsutils.writeversion(state.servercontext.getserverversion(), buf);

        buf.write(state.servercontext.getsecurityparameters().serverrandom);

        /*
         * the server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        tlsutils.writeopaque8(tlsutils.empty_bytes, buf);

        state.selectedciphersuite = state.server.getselectedciphersuite();
        if (!tlsprotocol.arraycontains(state.offeredciphersuites, state.selectedciphersuite)
            || state.selectedciphersuite == ciphersuite.tls_null_with_null_null
            || state.selectedciphersuite == ciphersuite.tls_empty_renegotiation_info_scsv)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        validateselectedciphersuite(state.selectedciphersuite, alertdescription.internal_error);

        state.selectedcompressionmethod = state.server.getselectedcompressionmethod();
        if (!tlsprotocol.arraycontains(state.offeredcompressionmethods, state.selectedcompressionmethod))
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        tlsutils.writeuint16(state.selectedciphersuite, buf);
        tlsutils.writeuint8(state.selectedcompressionmethod, buf);

        state.serverextensions = state.server.getserverextensions();

        /*
         * rfc 5746 3.6. server behavior: initial handshake
         */
        if (state.secure_renegotiation)
        {

            boolean norenegext = state.serverextensions == null
                || !state.serverextensions.containskey(tlsprotocol.ext_renegotiationinfo);

            if (norenegext)
            {
                /*
                 * note that sending a "renegotiation_info" extension in response to a clienthello
                 * containing only the scsv is an explicit exception to the prohibition in rfc 5246,
                 * section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                 * because the client is signaling its willingness to receive the extension via the
                 * tls_empty_renegotiation_info_scsv scsv.
                 */
                if (state.serverextensions == null)
                {
                    state.serverextensions = new hashtable();
                }

                /*
                 * if the secure_renegotiation flag is set to true, the server must include an empty
                 * "renegotiation_info" extension in the serverhello message.
                 */
                state.serverextensions.put(tlsprotocol.ext_renegotiationinfo,
                    tlsprotocol.createrenegotiationinfo(tlsutils.empty_bytes));
            }
        }

        if (state.serverextensions != null)
        {
            state.expectsessionticket = state.serverextensions.containskey(tlsprotocol.ext_sessionticket);
            tlsprotocol.writeextensions(buf, state.serverextensions);
        }

        return buf.tobytearray();
    }

    protected void notifyclientcertificate(serverhandshakestate state, certificate clientcertificate)
        throws ioexception
    {

        if (state.certificaterequest == null)
        {
            throw new illegalstateexception();
        }

        if (state.clientcertificate != null)
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        state.clientcertificate = clientcertificate;

        if (clientcertificate.isempty())
        {
            state.keyexchange.skipclientcredentials();
        }
        else
        {

            /*
             * todo rfc 5246 7.4.6. if the certificate_authorities list in the certificate request
             * message was non-empty, one of the certificates in the certificate chain should be
             * issued by one of the listed cas.
             */

            state.clientcertificatetype = tlsutils.getclientcertificatetype(clientcertificate,
                state.servercredentials.getcertificate());

            state.keyexchange.processclientcertificate(clientcertificate);
        }

        /*
         * rfc 5246 7.4.6. if the client does not send any certificates, the server may at its
         * discretion either continue the handshake without client authentication, or respond with a
         * fatal handshake_failure alert. also, if some aspect of the certificate chain was
         * unacceptable (e.g., it was not signed by a known, trusted ca), the server may at its
         * discretion either continue the handshake (considering the client unauthenticated) or send
         * a fatal alert.
         */
        state.server.notifyclientcertificate(clientcertificate);
    }

    protected void processclientcertificate(serverhandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        certificate clientcertificate = certificate.parse(buf);

        tlsprotocol.assertempty(buf);

        notifyclientcertificate(state, clientcertificate);
    }

    protected void processcertificateverify(serverhandshakestate state, byte[] body, byte[] certificateverifyhash)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        byte[] clientcertificatesignature = tlsutils.readopaque16(buf);

        tlsprotocol.assertempty(buf);

        // verify the certificateverify message contains a correct signature.
        try
        {
            tlssigner tlssigner = tlsutils.createtlssigner(state.clientcertificatetype);
            tlssigner.init(state.servercontext);

            org.ripple.bouncycastle.asn1.x509.certificate x509cert = state.clientcertificate.getcertificateat(0);
            subjectpublickeyinfo keyinfo = x509cert.getsubjectpublickeyinfo();
            asymmetrickeyparameter publickey = publickeyfactory.createkey(keyinfo);

            tlssigner.verifyrawsignature(clientcertificatesignature, publickey, certificateverifyhash);
        }
        catch (exception e)
        {
            throw new tlsfatalalert(alertdescription.decrypt_error);
        }
    }

    protected void processclienthello(serverhandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        // todo read rfcs for guidance on the expected record layer version number
        protocolversion client_version = tlsutils.readversion(buf);
        if (!client_version.isdtls())
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        /*
         * read the client random
         */
        byte[] client_random = tlsutils.readfully(32, buf);

        byte[] sessionid = tlsutils.readopaque8(buf);
        if (sessionid.length > 32)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        // todo rfc 4347 has the cookie length restricted to 32, but not in rfc 6347
        byte[] cookie = tlsutils.readopaque8(buf);

        int cipher_suites_length = tlsutils.readuint16(buf);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }

        /*
         * note: "if the session_id field is not empty (implying a session resumption request) this
         * vector must include at least the cipher_suite from that session."
         */
        state.offeredciphersuites = tlsutils.readuint16array(cipher_suites_length / 2, buf);

        int compression_methods_length = tlsutils.readuint8(buf);
        if (compression_methods_length < 1)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        state.offeredcompressionmethods = tlsutils.readuint8array(compression_methods_length, buf);

        /*
         * todo rfc 3546 2.3 if [...] the older session is resumed, then the server must ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        state.clientextensions = tlsprotocol.readextensions(buf);

        state.servercontext.setclientversion(client_version);

        state.server.notifyclientversion(client_version);

        state.servercontext.getsecurityparameters().clientrandom = client_random;

        state.server.notifyofferedciphersuites(state.offeredciphersuites);
        state.server.notifyofferedcompressionmethods(state.offeredcompressionmethods);

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
            if (tlsprotocol.arraycontains(state.offeredciphersuites, ciphersuite.tls_empty_renegotiation_info_scsv))
            {
                state.secure_renegotiation = true;
            }

            /*
             * the server must check if the "renegotiation_info" extension is included in the
             * clienthello.
             */
            if (state.clientextensions != null)
            {
                byte[] renegextvalue = (byte[])state.clientextensions.get(tlsprotocol.ext_renegotiationinfo);
                if (renegextvalue != null)
                {
                    /*
                     * if the extension is present, set secure_renegotiation flag to true. the
                     * server must then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, must abort the handshake.
                     */
                    state.secure_renegotiation = true;

                    if (!arrays.constanttimeareequal(renegextvalue,
                        tlsprotocol.createrenegotiationinfo(tlsutils.empty_bytes)))
                    {
                        throw new tlsfatalalert(alertdescription.handshake_failure);
                    }
                }
            }
        }

        state.server.notifysecurerenegotiation(state.secure_renegotiation);

        if (state.clientextensions != null)
        {
            state.server.processclientextensions(state.clientextensions);
        }
    }

    protected void processclientkeyexchange(serverhandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        state.keyexchange.processclientkeyexchange(buf);

        tlsprotocol.assertempty(buf);

        tlsprotocol.establishmastersecret(state.servercontext, state.keyexchange);
    }

    protected void processclientsupplementaldata(serverhandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);
        vector clientsupplementaldata = tlsprotocol.readsupplementaldatamessage(buf);
        state.server.processclientsupplementaldata(clientsupplementaldata);
    }

    protected boolean expectcertificateverifymessage(serverhandshakestate state)
    {
        return state.clientcertificatetype >= 0 && tlsutils.hassigningcapability(state.clientcertificatetype);
    }

    protected static class serverhandshakestate
    {
        tlsserver server = null;
        tlsservercontextimpl servercontext = null;
        int[] offeredciphersuites;
        short[] offeredcompressionmethods;
        hashtable clientextensions;
        int selectedciphersuite = -1;
        short selectedcompressionmethod = -1;
        boolean secure_renegotiation = false;
        boolean expectsessionticket = false;
        hashtable serverextensions = null;
        tlskeyexchange keyexchange = null;
        tlscredentials servercredentials = null;
        certificaterequest certificaterequest = null;
        short clientcertificatetype = -1;
        certificate clientcertificate = null;
    }
}
