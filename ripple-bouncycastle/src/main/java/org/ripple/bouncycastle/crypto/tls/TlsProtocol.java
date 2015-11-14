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

import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;

/**
 * an implementation of all high level protocols in tls 1.0/1.1.
 */
public abstract class tlsprotocol
{

    protected static final integer ext_renegotiationinfo = integers.valueof(extensiontype.renegotiation_info);
    protected static final integer ext_sessionticket = integers.valueof(extensiontype.session_ticket);

    private static final string tls_error_message = "internal tls error, this could be an attack";

    /*
     * our connection states
     */
    protected static final short cs_start = 0;
    protected static final short cs_client_hello = 1;
    protected static final short cs_server_hello = 2;
    protected static final short cs_server_supplemental_data = 3;
    protected static final short cs_server_certificate = 4;
    protected static final short cs_server_key_exchange = 5;
    protected static final short cs_certificate_request = 6;
    protected static final short cs_server_hello_done = 7;
    protected static final short cs_client_supplemental_data = 8;
    protected static final short cs_client_certificate = 9;
    protected static final short cs_client_key_exchange = 10;
    protected static final short cs_certificate_verify = 11;
    protected static final short cs_client_change_cipher_spec = 12;
    protected static final short cs_client_finished = 13;
    protected static final short cs_server_session_ticket = 14;
    protected static final short cs_server_change_cipher_spec = 15;
    protected static final short cs_server_finished = 16;

    /*
     * queues for data from some protocols.
     */
    private bytequeue applicationdataqueue = new bytequeue();
    private bytequeue changecipherspecqueue = new bytequeue();
    private bytequeue alertqueue = new bytequeue();
    private bytequeue handshakequeue = new bytequeue();

    /*
     * the record stream we use
     */
    protected recordstream recordstream;
    protected securerandom securerandom;

    private tlsinputstream tlsinputstream = null;
    private tlsoutputstream tlsoutputstream = null;

    private volatile boolean closed = false;
    private volatile boolean failedwitherror = false;
    private volatile boolean appdataready = false;
    private volatile boolean writeextraemptyrecords = true;
    private byte[] expected_verify_data = null;

    protected securityparameters securityparameters = null;

    protected short connection_state = cs_start;
    protected boolean secure_renegotiation = false;
    protected boolean expectsessionticket = false;

    public tlsprotocol(inputstream input, outputstream output, securerandom securerandom)
    {
        this.recordstream = new recordstream(this, input, output);
        this.securerandom = securerandom;
    }

    protected abstract abstracttlscontext getcontext();

    protected abstract tlspeer getpeer();

    protected abstract void handlechangecipherspecmessage()
        throws ioexception;

    protected abstract void handlehandshakemessage(short type, byte[] buf)
        throws ioexception;

    protected void handlewarningmessage(short description)
        throws ioexception
    {

    }

    protected void completehandshake()
        throws ioexception
    {

        this.expected_verify_data = null;

        /*
         * we will now read data, until we have completed the handshake.
         */
        while (this.connection_state != cs_server_finished)
        {
            safereadrecord();
        }

        this.recordstream.finalisehandshake();

        protocolversion version = getcontext().getserverversion();
        this.writeextraemptyrecords = version.isequalorearlierversionof(protocolversion.tlsv10);

        /*
         * if this was an initial handshake, we are now ready to send and receive application data.
         */
        if (!appdataready)
        {
            this.appdataready = true;

            this.tlsinputstream = new tlsinputstream(this);
            this.tlsoutputstream = new tlsoutputstream(this);
        }
    }

    protected void processrecord(short protocol, byte[] buf, int offset, int len)
        throws ioexception
    {
        /*
         * have a look at the protocol type, and add it to the correct queue.
         */
        switch (protocol)
        {
        case contenttype.change_cipher_spec:
            changecipherspecqueue.adddata(buf, offset, len);
            processchangecipherspec();
            break;
        case contenttype.alert:
            alertqueue.adddata(buf, offset, len);
            processalert();
            break;
        case contenttype.handshake:
            handshakequeue.adddata(buf, offset, len);
            processhandshake();
            break;
        case contenttype.application_data:
            if (!appdataready)
            {
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }
            applicationdataqueue.adddata(buf, offset, len);
            processapplicationdata();
            break;
        default:
            /*
             * uh, we don't know this protocol.
             * 
             * rfc2246 defines on page 13, that we should ignore this.
             */
        }
    }

    private void processhandshake()
        throws ioexception
    {
        boolean read;
        do
        {
            read = false;
            /*
             * we need the first 4 bytes, they contain type and length of the message.
             */
            if (handshakequeue.size() >= 4)
            {
                byte[] beginning = new byte[4];
                handshakequeue.read(beginning, 0, 4, 0);
                bytearrayinputstream bis = new bytearrayinputstream(beginning);
                short type = tlsutils.readuint8(bis);
                int len = tlsutils.readuint24(bis);

                /*
                 * check if we have enough bytes in the buffer to read the full message.
                 */
                if (handshakequeue.size() >= (len + 4))
                {
                    /*
                     * read the message.
                     */
                    byte[] buf = new byte[len];
                    handshakequeue.read(buf, 0, len, 4);
                    handshakequeue.removedata(len + 4);

                    /*
                     * rfc 2246 7.4.9. the value handshake_messages includes all handshake messages
                     * starting at client hello up to, but not including, this finished message.
                     * [..] note: [also,] hello request messages are omitted from handshake hashes.
                     */
                    switch (type)
                    {
                    case handshaketype.hello_request:
                        break;
                    case handshaketype.finished:
                    {

                        if (this.expected_verify_data == null)
                        {
                            this.expected_verify_data = createverifydata(!getcontext().isserver());
                        }

                        // nb: fall through to next case label
                    }
                    default:
                        recordstream.updatehandshakedata(beginning, 0, 4);
                        recordstream.updatehandshakedata(buf, 0, len);
                        break;
                    }

                    /*
                     * now, parse the message.
                     */
                    handlehandshakemessage(type, buf);
                    read = true;
                }
            }
        }
        while (read);
    }

    private void processapplicationdata()
    {
        /*
         * there is nothing we need to do here.
         * 
         * this function could be used for callbacks when application data arrives in the future.
         */
    }

    private void processalert()
        throws ioexception
    {
        while (alertqueue.size() >= 2)
        {
            /*
             * an alert is always 2 bytes. read the alert.
             */
            byte[] tmp = new byte[2];
            alertqueue.read(tmp, 0, 2, 0);
            alertqueue.removedata(2);
            short level = tmp[0];
            short description = tmp[1];

            getpeer().notifyalertreceived(level, description);

            if (level == alertlevel.fatal)
            {

                this.failedwitherror = true;
                this.closed = true;
                /*
                 * now try to close the stream, ignore errors.
                 */
                try
                {
                    recordstream.close();
                }
                catch (exception e)
                {

                }
                throw new ioexception(tls_error_message);
            }
            else
            {

                /*
                 * rfc 5246 7.2.1. the other party must respond with a close_notify alert of its own
                 * and close down the connection immediately, discarding any pending writes.
                 */
                // todo can close_notify be a fatal alert?
                if (description == alertdescription.close_notify)
                {
                    handleclose(false);
                }

                /*
                 * if it is just a warning, we continue.
                 */
                handlewarningmessage(description);
            }
        }
    }

    /**
     * this method is called, when a change cipher spec message is received.
     *
     * @throws ioexception if the message has an invalid content or the handshake is not in the correct
     * state.
     */
    private void processchangecipherspec()
        throws ioexception
    {
        while (changecipherspecqueue.size() > 0)
        {
            /*
             * a change cipher spec message is only one byte with the value 1.
             */
            byte[] b = new byte[1];
            changecipherspecqueue.read(b, 0, 1, 0);
            changecipherspecqueue.removedata(1);
            if (b[0] != 1)
            {
                /*
                 * this should never happen.
                 */
                this.failwitherror(alertlevel.fatal, alertdescription.unexpected_message);
            }

            recordstream.receivedreadcipherspec();

            handlechangecipherspecmessage();
        }
    }

    /**
     * read data from the network. the method will return immediately, if there is still some data
     * left in the buffer, or block until some application data has been read from the network.
     *
     * @param buf    the buffer where the data will be copied to.
     * @param offset the position where the data will be placed in the buffer.
     * @param len    the maximum number of bytes to read.
     * @return the number of bytes read.
     * @throws ioexception if something goes wrong during reading data.
     */
    protected int readapplicationdata(byte[] buf, int offset, int len)
        throws ioexception
    {

        if (len < 1)
        {
            return 0;
        }

        while (applicationdataqueue.size() == 0)
        {
            /*
             * we need to read some data.
             */
            if (this.closed)
            {
                if (this.failedwitherror)
                {
                    /*
                     * something went terribly wrong, we should throw an ioexception
                     */
                    throw new ioexception(tls_error_message);
                }

                /*
                 * connection has been closed, there is no more data to read.
                 */
                return -1;
            }

            safereadrecord();
        }
        len = math.min(len, applicationdataqueue.size());
        applicationdataqueue.read(buf, offset, len, 0);
        applicationdataqueue.removedata(len);
        return len;
    }

    protected void safereadrecord()
        throws ioexception
    {
        try
        {
            recordstream.readrecord();
        }
        catch (tlsfatalalert e)
        {
            if (!this.closed)
            {
                this.failwitherror(alertlevel.fatal, e.getalertdescription());
            }
            throw e;
        }
        catch (ioexception e)
        {
            if (!this.closed)
            {
                this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
            }
            throw e;
        }
        catch (runtimeexception e)
        {
            if (!this.closed)
            {
                this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
            }
            throw e;
        }
    }

    protected void safewriterecord(short type, byte[] buf, int offset, int len)
        throws ioexception
    {
        try
        {
            recordstream.writerecord(type, buf, offset, len);
        }
        catch (tlsfatalalert e)
        {
            if (!this.closed)
            {
                this.failwitherror(alertlevel.fatal, e.getalertdescription());
            }
            throw e;
        }
        catch (ioexception e)
        {
            if (!closed)
            {
                this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
            }
            throw e;
        }
        catch (runtimeexception e)
        {
            if (!closed)
            {
                this.failwitherror(alertlevel.fatal, alertdescription.internal_error);
            }
            throw e;
        }
    }

    /**
     * send some application data to the remote system.
     * <p/>
     * the method will handle fragmentation internally.
     *
     * @param buf    the buffer with the data.
     * @param offset the position in the buffer where the data is placed.
     * @param len    the length of the data.
     * @throws ioexception if something goes wrong during sending.
     */
    protected void writedata(byte[] buf, int offset, int len)
        throws ioexception
    {
        if (this.closed)
        {
            if (this.failedwitherror)
            {
                throw new ioexception(tls_error_message);
            }

            throw new ioexception("sorry, connection has been closed, you cannot write more data");
        }

        while (len > 0)
        {
            /*
             * rfc 5246 6.2.1. zero-length fragments of application data may be sent as they are
             * potentially useful as a traffic analysis countermeasure.
             */
            if (this.writeextraemptyrecords)
            {
                /*
                 * protect against known iv attack!
                 * 
                 * do not remove this line, except you know exactly what you are doing here.
                 */
                safewriterecord(contenttype.application_data, tlsutils.empty_bytes, 0, 0);
            }

            /*
             * we are only allowed to write fragments up to 2^14 bytes.
             */
            int towrite = math.min(len, 1 << 14);

            safewriterecord(contenttype.application_data, buf, offset, towrite);

            offset += towrite;
            len -= towrite;
        }
    }

    /**
     * @return an outputstream which can be used to send data.
     */
    public outputstream getoutputstream()
    {
        return this.tlsoutputstream;
    }

    /**
     * @return an inputstream which can be used to read data.
     */
    public inputstream getinputstream()
    {
        return this.tlsinputstream;
    }

    /**
     * terminate this connection with an alert.
     * <p/>
     * can be used for normal closure too.
     *
     * @param alertlevel       the level of the alert, an be alertlevel.fatal or al_warning.
     * @param alertdescription the exact alert message.
     * @throws ioexception if alert was fatal.
     */
    protected void failwitherror(short alertlevel, short alertdescription)
        throws ioexception
    {
        /*
         * check if the connection is still open.
         */
        if (!closed)
        {
            /*
             * prepare the message
             */
            this.closed = true;

            if (alertlevel == alertlevel.fatal)
            {
                /*
                 * this is a fatal message.
                 */
                this.failedwitherror = true;
            }
            raisealert(alertlevel, alertdescription, null, null);
            recordstream.close();
            if (alertlevel == alertlevel.fatal)
            {
                throw new ioexception(tls_error_message);
            }
        }
        else
        {
            throw new ioexception(tls_error_message);
        }
    }

    protected void processfinishedmessage(bytearrayinputstream buf)
        throws ioexception
    {

        byte[] verify_data = tlsutils.readfully(expected_verify_data.length, buf);

        assertempty(buf);

        /*
         * compare both checksums.
         */
        if (!arrays.constanttimeareequal(expected_verify_data, verify_data))
        {
            /*
             * wrong checksum in the finished message.
             */
            this.failwitherror(alertlevel.fatal, alertdescription.decrypt_error);
        }
    }

    protected void raisealert(short alertlevel, short alertdescription, string message, exception cause)
        throws ioexception
    {

        getpeer().notifyalertraised(alertlevel, alertdescription, message, cause);

        byte[] error = new byte[2];
        error[0] = (byte)alertlevel;
        error[1] = (byte)alertdescription;

        safewriterecord(contenttype.alert, error, 0, 2);
    }

    protected void raisewarning(short alertdescription, string message)
        throws ioexception
    {
        raisealert(alertlevel.warning, alertdescription, message, null);
    }

    protected void sendcertificatemessage(certificate certificate)
        throws ioexception
    {

        if (certificate == null)
        {
            certificate = certificate.empty_chain;
        }

        if (certificate.getlength() == 0)
        {
            tlscontext context = getcontext();
            if (!context.isserver())
            {
                protocolversion serverversion = getcontext().getserverversion();
                if (serverversion.isssl())
                {
                    string message = serverversion.tostring() + " client didn't provide credentials";
                    raisewarning(alertdescription.no_certificate, message);
                    return;
                }
            }
        }

        bytearrayoutputstream bos = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.certificate, bos);

        // reserve space for length
        tlsutils.writeuint24(0, bos);

        certificate.encode(bos);
        byte[] message = bos.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendchangecipherspecmessage()
        throws ioexception
    {
        byte[] message = new byte[]{1};
        safewriterecord(contenttype.change_cipher_spec, message, 0, message.length);
        recordstream.sentwritecipherspec();
    }

    protected void sendfinishedmessage()
        throws ioexception
    {
        byte[] verify_data = createverifydata(getcontext().isserver());

        bytearrayoutputstream bos = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.finished, bos);
        tlsutils.writeuint24(verify_data.length, bos);
        bos.write(verify_data);
        byte[] message = bos.tobytearray();

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected void sendsupplementaldatamessage(vector supplementaldata)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8(handshaketype.supplemental_data, buf);

        // reserve space for length
        tlsutils.writeuint24(0, buf);

        writesupplementaldata(buf, supplementaldata);

        byte[] message = buf.tobytearray();

        // patch actual length back in
        tlsutils.writeuint24(message.length - 4, message, 1);

        safewriterecord(contenttype.handshake, message, 0, message.length);
    }

    protected byte[] createverifydata(boolean isserver)
    {
        tlscontext context = getcontext();

        if (isserver)
        {
            return tlsutils.calculateverifydata(context, "server finished",
                recordstream.getcurrenthash(tlsutils.ssl_server));
        }

        return tlsutils.calculateverifydata(context, "client finished",
            recordstream.getcurrenthash(tlsutils.ssl_client));
    }

    /**
     * closes this connection.
     *
     * @throws ioexception if something goes wrong during closing.
     */
    public void close()
        throws ioexception
    {
        handleclose(true);
    }

    protected void handleclose(boolean user_canceled)
        throws ioexception
    {
        if (!closed)
        {
            if (user_canceled && !appdataready)
            {
                raisewarning(alertdescription.user_canceled, "user canceled handshake");
            }
            this.failwitherror(alertlevel.warning, alertdescription.close_notify);
        }
    }

    protected void flush()
        throws ioexception
    {
        recordstream.flush();
    }

    protected static boolean arraycontains(short[] a, short n)
    {
        for (int i = 0; i < a.length; ++i)
        {
            if (a[i] == n)
            {
                return true;
            }
        }
        return false;
    }

    protected static boolean arraycontains(int[] a, int n)
    {
        for (int i = 0; i < a.length; ++i)
        {
            if (a[i] == n)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * make sure the inputstream 'buf' now empty. fail otherwise.
     *
     * @param buf the inputstream to check.
     * @throws ioexception if 'buf' is not empty.
     */
    protected static void assertempty(bytearrayinputstream buf)
        throws ioexception
    {
        if (buf.available() > 0)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }
    }

    protected static byte[] createrandomblock(securerandom random)
    {
        byte[] result = new byte[32];
        random.nextbytes(result);
        tlsutils.writegmtunixtime(result, 0);
        return result;
    }

    protected static byte[] createrenegotiationinfo(byte[] renegotiated_connection)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeopaque8(renegotiated_connection, buf);
        return buf.tobytearray();
    }

    protected static void establishmastersecret(tlscontext context, tlskeyexchange keyexchange)
        throws ioexception
    {

        byte[] pre_master_secret = keyexchange.generatepremastersecret();

        try
        {
            context.getsecurityparameters().mastersecret = tlsutils.calculatemastersecret(context, pre_master_secret);
        }
        finally
        {
            // todo is there a way to ensure the data is really overwritten?
            /*
             * rfc 2246 8.1. the pre_master_secret should be deleted from memory once the
             * master_secret has been computed.
             */
            if (pre_master_secret != null)
            {
                arrays.fill(pre_master_secret, (byte)0);
            }
        }
    }

    protected static hashtable readextensions(bytearrayinputstream input)
        throws ioexception
    {

        if (input.available() < 1)
        {
            return null;
        }

        byte[] extbytes = tlsutils.readopaque16(input);

        assertempty(input);

        bytearrayinputstream buf = new bytearrayinputstream(extbytes);

        // integer -> byte[]
        hashtable extensions = new hashtable();

        while (buf.available() > 0)
        {
            integer exttype = integers.valueof(tlsutils.readuint16(buf));
            byte[] extvalue = tlsutils.readopaque16(buf);

            /*
             * rfc 3546 2.3 there must not be more than one extension of the same type.
             */
            if (null != extensions.put(exttype, extvalue))
            {
                throw new tlsfatalalert(alertdescription.illegal_parameter);
            }
        }

        return extensions;
    }

    protected static vector readsupplementaldatamessage(bytearrayinputstream input)
        throws ioexception
    {

        byte[] supp_data = tlsutils.readopaque24(input);

        assertempty(input);

        bytearrayinputstream buf = new bytearrayinputstream(supp_data);

        vector supplementaldata = new vector();

        while (buf.available() > 0)
        {
            int supp_data_type = tlsutils.readuint16(buf);
            byte[] data = tlsutils.readopaque16(buf);

            supplementaldata.addelement(new supplementaldataentry(supp_data_type, data));
        }

        return supplementaldata;
    }

    protected static void writeextensions(outputstream output, hashtable extensions)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();

        enumeration keys = extensions.keys();
        while (keys.hasmoreelements())
        {
            integer exttype = (integer)keys.nextelement();
            byte[] extvalue = (byte[])extensions.get(exttype);

            tlsutils.writeuint16(exttype.intvalue(), buf);
            tlsutils.writeopaque16(extvalue, buf);
        }

        byte[] extbytes = buf.tobytearray();

        tlsutils.writeopaque16(extbytes, output);
    }

    protected static void writesupplementaldata(outputstream output, vector supplementaldata)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();

        for (int i = 0; i < supplementaldata.size(); ++i)
        {
            supplementaldataentry entry = (supplementaldataentry)supplementaldata.elementat(i);

            tlsutils.writeuint16(entry.getdatatype(), buf);
            tlsutils.writeopaque16(entry.getdata(), buf);
        }

        byte[] supp_data = buf.tobytearray();

        tlsutils.writeopaque24(supp_data, output);
    }

    protected static int getprfalgorithm(int ciphersuite)
    {

        switch (ciphersuite)
        {
        case ciphersuite.tls_dh_dss_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_rsa_with_aes_128_cbc_sha256:
        case ciphersuite.tls_dh_dss_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdh_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_ecdhe_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_rsa_with_aes_128_gcm_sha256:
        case ciphersuite.tls_dh_dss_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dh_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dhe_dss_with_aes_256_cbc_sha256:
        case ciphersuite.tls_dhe_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_rsa_with_aes_256_cbc_sha256:
        case ciphersuite.tls_rsa_with_null_sha256:
            return prfalgorithm.tls_prf_sha256;

        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_cbc_sha384:
        case ciphersuite.tls_dh_dss_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dh_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dhe_dss_with_aes_256_gcm_sha384:
        case ciphersuite.tls_dhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdh_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_ecdhe_rsa_with_aes_256_gcm_sha384:
        case ciphersuite.tls_rsa_with_aes_256_gcm_sha384:
            return prfalgorithm.tls_prf_sha384;

        default:
            return prfalgorithm.tls_prf_legacy;
        }
    }
}
