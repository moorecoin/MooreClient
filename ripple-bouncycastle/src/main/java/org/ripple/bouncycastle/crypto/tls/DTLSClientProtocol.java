package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.security.securerandom;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.util.arrays;

public class dtlsclientprotocol
    extends dtlsprotocol
{

    public dtlsclientprotocol(securerandom securerandom)
    {
        super(securerandom);
    }

    public dtlstransport connect(tlsclient client, datagramtransport transport)
        throws ioexception
    {

        if (client == null)
        {
            throw new illegalargumentexception("'client' cannot be null");
        }
        if (transport == null)
        {
            throw new illegalargumentexception("'transport' cannot be null");
        }

        securityparameters securityparameters = new securityparameters();
        securityparameters.entity = connectionend.client;
        securityparameters.clientrandom = tlsprotocol.createrandomblock(securerandom);

        clienthandshakestate state = new clienthandshakestate();
        state.client = client;
        state.clientcontext = new tlsclientcontextimpl(securerandom, securityparameters);
        client.init(state.clientcontext);

        dtlsrecordlayer recordlayer = new dtlsrecordlayer(transport, state.clientcontext, client, contenttype.handshake);

        try
        {
            return clienthandshake(state, recordlayer);
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

    protected dtlstransport clienthandshake(clienthandshakestate state, dtlsrecordlayer recordlayer)
        throws ioexception
    {

        securityparameters securityparameters = state.clientcontext.getsecurityparameters();
        dtlsreliablehandshake handshake = new dtlsreliablehandshake(state.clientcontext, recordlayer);

        byte[] clienthellobody = generateclienthello(state, state.client);
        handshake.sendmessage(handshaketype.client_hello, clienthellobody);

        dtlsreliablehandshake.message servermessage = handshake.receivemessage();

        {
            // note: after receiving a record from the server, we discover the record layer version
            protocolversion server_version = recordlayer.getdiscoveredpeerversion();
            protocolversion client_version = state.clientcontext.getclientversion();

            if (!server_version.isequalorearlierversionof(client_version))
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }

            state.clientcontext.setserverversion(server_version);
            state.client.notifyserverversion(server_version);
        }

        while (servermessage.gettype() == handshaketype.hello_verify_request)
        {
            byte[] cookie = parsehelloverifyrequest(state.clientcontext, servermessage.getbody());
            byte[] patched = patchclienthellowithcookie(clienthellobody, cookie);

            handshake.resethandshakemessagesdigest();
            handshake.sendmessage(handshaketype.client_hello, patched);

            servermessage = handshake.receivemessage();
        }

        if (servermessage.gettype() == handshaketype.server_hello)
        {
            processserverhello(state, servermessage.getbody());
            servermessage = handshake.receivemessage();
        }
        else
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        securityparameters.prfalgorithm = tlsprotocol.getprfalgorithm(state.selectedciphersuite);
        securityparameters.compressionalgorithm = state.selectedcompressionmethod;

        /*
         * rfc 5264 7.4.9. any cipher suite which does not explicitly specify verify_data_length has
         * a verify_data_length equal to 12. this includes all existing cipher suites.
         */
        securityparameters.verifydatalength = 12;

        handshake.notifyhellocomplete();

        if (servermessage.gettype() == handshaketype.supplemental_data)
        {
            processserversupplementaldata(state, servermessage.getbody());
            servermessage = handshake.receivemessage();
        }
        else
        {
            state.client.processserversupplementaldata(null);
        }

        state.keyexchange = state.client.getkeyexchange();
        state.keyexchange.init(state.clientcontext);

        if (servermessage.gettype() == handshaketype.certificate)
        {
            processservercertificate(state, servermessage.getbody());
            servermessage = handshake.receivemessage();
        }
        else
        {
            // okay, certificate is optional
            state.keyexchange.skipservercredentials();
        }

        if (servermessage.gettype() == handshaketype.server_key_exchange)
        {
            processserverkeyexchange(state, servermessage.getbody());
            servermessage = handshake.receivemessage();
        }
        else
        {
            // okay, serverkeyexchange is optional
            state.keyexchange.skipserverkeyexchange();
        }

        if (servermessage.gettype() == handshaketype.certificate_request)
        {
            processcertificaterequest(state, servermessage.getbody());
            servermessage = handshake.receivemessage();
        }
        else
        {
            // okay, certificaterequest is optional
        }

        if (servermessage.gettype() == handshaketype.server_hello_done)
        {
            if (servermessage.getbody().length != 0)
            {
                throw new tlsfatalalert(alertdescription.decode_error);
            }
        }
        else
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        vector clientsupplementaldata = state.client.getclientsupplementaldata();
        if (clientsupplementaldata != null)
        {
            byte[] supplementaldatabody = generatesupplementaldata(clientsupplementaldata);
            handshake.sendmessage(handshaketype.supplemental_data, supplementaldatabody);
        }

        if (state.certificaterequest != null)
        {
            state.clientcredentials = state.authentication.getclientcredentials(state.certificaterequest);

            /*
             * rfc 5246 if no suitable certificate is available, the client must send a certificate
             * message containing no certificates.
             * 
             * note: in previous rfcs, this was should instead of must.
             */
            certificate clientcertificate = null;
            if (state.clientcredentials != null)
            {
                clientcertificate = state.clientcredentials.getcertificate();
            }
            if (clientcertificate == null)
            {
                clientcertificate = certificate.empty_chain;
            }

            byte[] certificatebody = generatecertificate(clientcertificate);
            handshake.sendmessage(handshaketype.certificate, certificatebody);
        }

        if (state.clientcredentials != null)
        {
            state.keyexchange.processclientcredentials(state.clientcredentials);
        }
        else
        {
            state.keyexchange.skipclientcredentials();
        }

        byte[] clientkeyexchangebody = generateclientkeyexchange(state);
        handshake.sendmessage(handshaketype.client_key_exchange, clientkeyexchangebody);

        tlsprotocol.establishmastersecret(state.clientcontext, state.keyexchange);

        if (state.clientcredentials instanceof tlssignercredentials)
        {
            /*
             * todo rfc 5246 4.7. digitally-signed element needs signatureandhashalgorithm prepended
             * from tls 1.2
             */
            tlssignercredentials signercredentials = (tlssignercredentials)state.clientcredentials;
            byte[] md5andsha1 = handshake.getcurrenthash();
            byte[] signature = signercredentials.generatecertificatesignature(md5andsha1);
            byte[] certificateverifybody = generatecertificateverify(state, signature);
            handshake.sendmessage(handshaketype.certificate_verify, certificateverifybody);
        }

        recordlayer.initpendingepoch(state.client.getcipher());

        // note: calculated exclusive of the finished message itself
        byte[] clientverifydata = tlsutils.calculateverifydata(state.clientcontext, "client finished",
            handshake.getcurrenthash());
        handshake.sendmessage(handshaketype.finished, clientverifydata);

        if (state.expectsessionticket)
        {
            servermessage = handshake.receivemessage();
            if (servermessage.gettype() == handshaketype.session_ticket)
            {
                processnewsessionticket(state, servermessage.getbody());
            }
            else
            {
                throw new tlsfatalalert(alertdescription.unexpected_message);
            }
        }

        // note: calculated exclusive of the actual finished message from the server
        byte[] expectedserververifydata = tlsutils.calculateverifydata(state.clientcontext, "server finished",
            handshake.getcurrenthash());
        servermessage = handshake.receivemessage();

        if (servermessage.gettype() == handshaketype.finished)
        {
            processfinished(servermessage.getbody(), expectedserververifydata);
        }
        else
        {
            throw new tlsfatalalert(alertdescription.unexpected_message);
        }

        handshake.finish();

        state.client.notifyhandshakecomplete();

        return new dtlstransport(recordlayer);
    }

    protected byte[] generatecertificateverify(clienthandshakestate state, byte[] signature)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeopaque16(signature, buf);
        return buf.tobytearray();
    }

    protected byte[] generateclienthello(clienthandshakestate state, tlsclient client)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();

        protocolversion client_version = client.getclientversion();
        if (!client_version.isdtls())
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        state.clientcontext.setclientversion(client_version);
        tlsutils.writeversion(client_version, buf);

        buf.write(state.clientcontext.getsecurityparameters().getclientrandom());

        // session id
        tlsutils.writeopaque8(tlsutils.empty_bytes, buf);

        // cookie
        tlsutils.writeopaque8(tlsutils.empty_bytes, buf);

        /*
         * cipher suites
         */
        state.offeredciphersuites = client.getciphersuites();

        // integer -> byte[]
        state.clientextensions = client.getclientextensions();

        // cipher suites (and scsv)
        {
            /*
             * rfc 5746 3.4. the client must include either an empty "renegotiation_info" extension,
             * or the tls_empty_renegotiation_info_scsv signaling cipher suite value in the
             * clienthello. including both is not recommended.
             */
            boolean norenegext = state.clientextensions == null
                || state.clientextensions.get(tlsprotocol.ext_renegotiationinfo) == null;

            int count = state.offeredciphersuites.length;
            if (norenegext)
            {
                // note: 1 extra slot for tls_empty_renegotiation_info_scsv
                ++count;
            }

            tlsutils.writeuint16(2 * count, buf);
            tlsutils.writeuint16array(state.offeredciphersuites, buf);

            if (norenegext)
            {
                tlsutils.writeuint16(ciphersuite.tls_empty_renegotiation_info_scsv, buf);
            }
        }

        // todo add support for compression
        // compression methods
        // state.offeredcompressionmethods = client.getcompressionmethods();
        state.offeredcompressionmethods = new short[]{compressionmethod._null};

        tlsutils.writeuint8((short)state.offeredcompressionmethods.length, buf);
        tlsutils.writeuint8array(state.offeredcompressionmethods, buf);

        // extensions
        if (state.clientextensions != null)
        {
            tlsprotocol.writeextensions(buf, state.clientextensions);
        }

        return buf.tobytearray();
    }

    protected byte[] generateclientkeyexchange(clienthandshakestate state)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        state.keyexchange.generateclientkeyexchange(buf);
        return buf.tobytearray();
    }

    protected void processcertificaterequest(clienthandshakestate state, byte[] body)
        throws ioexception
    {

        if (state.authentication == null)
        {
            /*
             * rfc 2246 7.4.4. it is a fatal handshake_failure alert for an anonymous server to
             * request client identification.
             */
            throw new tlsfatalalert(alertdescription.handshake_failure);
        }

        bytearrayinputstream buf = new bytearrayinputstream(body);

        state.certificaterequest = certificaterequest.parse(buf);

        tlsprotocol.assertempty(buf);

        state.keyexchange.validatecertificaterequest(state.certificaterequest);
    }

    protected void processnewsessionticket(clienthandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        newsessionticket newsessionticket = newsessionticket.parse(buf);

        tlsprotocol.assertempty(buf);

        state.client.notifynewsessionticket(newsessionticket);
    }

    protected void processservercertificate(clienthandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        certificate servercertificate = certificate.parse(buf);

        tlsprotocol.assertempty(buf);

        state.keyexchange.processservercertificate(servercertificate);
        state.authentication = state.client.getauthentication();
        state.authentication.notifyservercertificate(servercertificate);
    }

    protected void processserverhello(clienthandshakestate state, byte[] body)
        throws ioexception
    {

        securityparameters securityparameters = state.clientcontext.getsecurityparameters();

        bytearrayinputstream buf = new bytearrayinputstream(body);

        // todo read rfcs for guidance on the expected record layer version number
        protocolversion server_version = tlsutils.readversion(buf);
        if (!server_version.equals(state.clientcontext.getserverversion()))
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        securityparameters.serverrandom = tlsutils.readfully(32, buf);

        byte[] sessionid = tlsutils.readopaque8(buf);
        if (sessionid.length > 32)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
        state.client.notifysessionid(sessionid);

        state.selectedciphersuite = tlsutils.readuint16(buf);
        if (!tlsprotocol.arraycontains(state.offeredciphersuites, state.selectedciphersuite)
            || state.selectedciphersuite == ciphersuite.tls_null_with_null_null
            || state.selectedciphersuite == ciphersuite.tls_empty_renegotiation_info_scsv)
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        validateselectedciphersuite(state.selectedciphersuite, alertdescription.illegal_parameter);

        state.client.notifyselectedciphersuite(state.selectedciphersuite);

        state.selectedcompressionmethod = tlsutils.readuint8(buf);
        if (!tlsprotocol.arraycontains(state.offeredcompressionmethods, state.selectedcompressionmethod))
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }
        state.client.notifyselectedcompressionmethod(state.selectedcompressionmethod);

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
        hashtable serverextensions = tlsprotocol.readextensions(buf);

        /*
         * rfc 3546 2.2 note that the extended server hello message is only sent in response to an
         * extended client hello message. however, see rfc 5746 exception below. we always include
         * the scsv, so an extended server hello is always allowed.
         */
        if (serverextensions != null)
        {
            enumeration e = serverextensions.keys();
            while (e.hasmoreelements())
            {
                integer exttype = (integer)e.nextelement();

                /*
                 * rfc 5746 note that sending a "renegotiation_info" extension in response to a
                 * clienthello containing only the scsv is an explicit exception to the prohibition
                 * in rfc 5246, section 7.4.1.4, on the server sending unsolicited extensions and is
                 * only allowed because the client is signaling its willingness to receive the
                 * extension via the tls_empty_renegotiation_info_scsv scsv. tls implementations
                 * must continue to comply with section 7.4.1.4 for all other extensions.
                 */
                if (!exttype.equals(tlsprotocol.ext_renegotiationinfo)
                    && (state.clientextensions == null || state.clientextensions.get(exttype) == null))
                {
                    /*
                     * rfc 3546 2.3 note that for all extension types (including those defined in
                     * future), the extension type must not appear in the extended server hello
                     * unless the same extension type appeared in the corresponding client hello.
                     * thus clients must abort the handshake if they receive an extension type in
                     * the extended server hello that they did not request in the associated
                     * (extended) client hello.
                     */
                    throw new tlsfatalalert(alertdescription.unsupported_extension);
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
                byte[] renegextvalue = (byte[])serverextensions.get(tlsprotocol.ext_renegotiationinfo);
                if (renegextvalue != null)
                {
                    /*
                     * if the extension is present, set the secure_renegotiation flag to true. the
                     * client must then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, must abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    state.secure_renegotiation = true;

                    if (!arrays.constanttimeareequal(renegextvalue,
                        tlsprotocol.createrenegotiationinfo(tlsutils.empty_bytes)))
                    {
                        throw new tlsfatalalert(alertdescription.handshake_failure);
                    }
                }
            }

            state.expectsessionticket = serverextensions.containskey(tlsprotocol.ext_sessionticket);
        }

        state.client.notifysecurerenegotiation(state.secure_renegotiation);

        if (state.clientextensions != null)
        {
            state.client.processserverextensions(serverextensions);
        }
    }

    protected void processserverkeyexchange(clienthandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        state.keyexchange.processserverkeyexchange(buf);

        tlsprotocol.assertempty(buf);
    }

    protected void processserversupplementaldata(clienthandshakestate state, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);
        vector serversupplementaldata = tlsprotocol.readsupplementaldatamessage(buf);
        state.client.processserversupplementaldata(serversupplementaldata);
    }

    protected static byte[] parsehelloverifyrequest(tlscontext context, byte[] body)
        throws ioexception
    {

        bytearrayinputstream buf = new bytearrayinputstream(body);

        protocolversion server_version = tlsutils.readversion(buf);
        if (!server_version.equals(context.getserverversion()))
        {
            throw new tlsfatalalert(alertdescription.illegal_parameter);
        }

        byte[] cookie = tlsutils.readopaque8(buf);

        // todo rfc 4347 has the cookie length restricted to 32, but not in rfc 6347

        tlsprotocol.assertempty(buf);

        return cookie;
    }

    protected static byte[] patchclienthellowithcookie(byte[] clienthellobody, byte[] cookie)
        throws ioexception
    {

        int sessionidpos = 34;
        int sessionidlength = tlsutils.readuint8(clienthellobody, sessionidpos);

        int cookielengthpos = sessionidpos + 1 + sessionidlength;
        int cookiepos = cookielengthpos + 1;

        byte[] patched = new byte[clienthellobody.length + cookie.length];
        system.arraycopy(clienthellobody, 0, patched, 0, cookielengthpos);
        tlsutils.writeuint8((short)cookie.length, patched, cookielengthpos);
        system.arraycopy(cookie, 0, patched, cookiepos, cookie.length);
        system.arraycopy(clienthellobody, cookiepos, patched, cookiepos + cookie.length, clienthellobody.length
            - cookiepos);

        return patched;
    }

    protected static class clienthandshakestate
    {
        tlsclient client = null;
        tlsclientcontextimpl clientcontext = null;
        int[] offeredciphersuites = null;
        short[] offeredcompressionmethods = null;
        hashtable clientextensions = null;
        int selectedciphersuite = -1;
        short selectedcompressionmethod = -1;
        boolean secure_renegotiation = false;
        boolean expectsessionticket = false;
        tlskeyexchange keyexchange = null;
        tlsauthentication authentication = null;
        certificaterequest certificaterequest = null;
        tlscredentials clientcredentials = null;
    }
}
