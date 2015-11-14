package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;

class dtlsrecordlayer
    implements datagramtransport
{

    private static final int record_header_length = 13;
    private static final int max_fragment_length = 1 << 14;
    private static final long tcp_msl = 1000l * 60 * 2;
    private static final long retransmit_timeout = tcp_msl * 2;

    private final datagramtransport transport;
    private final tlscontext context;
    private final tlspeer peer;

    private final bytequeue recordqueue = new bytequeue();

    private volatile boolean closed = false;
    private volatile boolean failed = false;
    private volatile protocolversion discoveredpeerversion = null;
    private volatile boolean inhandshake;
    private dtlsepoch currentepoch, pendingepoch;
    private dtlsepoch readepoch, writeepoch;

    private dtlshandshakeretransmit retransmit = null;
    private dtlsepoch retransmitepoch = null;
    private long retransmitexpiry = 0;

    dtlsrecordlayer(datagramtransport transport, tlscontext context, tlspeer peer, short contenttype)
    {
        this.transport = transport;
        this.context = context;
        this.peer = peer;

        this.inhandshake = true;

        this.currentepoch = new dtlsepoch(0, new tlsnullcipher(context));
        this.pendingepoch = null;
        this.readepoch = currentepoch;
        this.writeepoch = currentepoch;
    }

    protocolversion getdiscoveredpeerversion()
    {
        return discoveredpeerversion;
    }

    void initpendingepoch(tlscipher pendingcipher)
    {
        if (pendingepoch != null)
        {
            throw new illegalstateexception();
        }

        /*
         * todo "in order to ensure that any given sequence/epoch pair is unique, implementations
         * must not allow the same epoch value to be reused within two times the tcp maximum segment
         * lifetime."
         */

        // todo check for overflow
        this.pendingepoch = new dtlsepoch(writeepoch.getepoch() + 1, pendingcipher);
    }

    void handshakesuccessful(dtlshandshakeretransmit retransmit)
    {
        if (readepoch == currentepoch || writeepoch == currentepoch)
        {
            // todo
            throw new illegalstateexception();
        }

        if (retransmit != null)
        {
            this.retransmit = retransmit;
            this.retransmitepoch = currentepoch;
            this.retransmitexpiry = system.currenttimemillis() + retransmit_timeout;
        }

        this.inhandshake = false;
        this.currentepoch = pendingepoch;
        this.pendingepoch = null;
    }

    void resetwriteepoch()
    {
        if (retransmitepoch != null)
        {
            this.writeepoch = retransmitepoch;
        }
        else
        {
            this.writeepoch = currentepoch;
        }
    }

    public int getreceivelimit()
        throws ioexception
    {
        return math.min(max_fragment_length,
            readepoch.getcipher().getplaintextlimit(transport.getreceivelimit() - record_header_length));
    }

    public int getsendlimit()
        throws ioexception
    {
        return math.min(max_fragment_length,
            writeepoch.getcipher().getplaintextlimit(transport.getsendlimit() - record_header_length));
    }

    public int receive(byte[] buf, int off, int len, int waitmillis)
        throws ioexception
    {

        byte[] record = null;

        for (; ; )
        {

            int receivelimit = math.min(len, getreceivelimit()) + record_header_length;
            if (record == null || record.length < receivelimit)
            {
                record = new byte[receivelimit];
            }

            try
            {
                if (retransmit != null && system.currenttimemillis() > retransmitexpiry)
                {
                    retransmit = null;
                    retransmitepoch = null;
                }

                int received = receiverecord(record, 0, receivelimit, waitmillis);
                if (received < 0)
                {
                    return received;
                }
                if (received < record_header_length)
                {
                    continue;
                }
                int length = tlsutils.readuint16(record, 11);
                if (received != (length + record_header_length))
                {
                    continue;
                }

                short type = tlsutils.readuint8(record, 0);

                // todo support user-specified custom protocols?
                switch (type)
                {
                case contenttype.alert:
                case contenttype.application_data:
                case contenttype.change_cipher_spec:
                case contenttype.handshake:
                    break;
                default:
                    // todo exception?
                    continue;
                }

                int epoch = tlsutils.readuint16(record, 3);

                dtlsepoch recordepoch = null;
                if (epoch == readepoch.getepoch())
                {
                    recordepoch = readepoch;
                }
                else if (type == contenttype.handshake && retransmitepoch != null
                    && epoch == retransmitepoch.getepoch())
                {
                    recordepoch = retransmitepoch;
                }

                if (recordepoch == null)
                {
                    continue;
                }

                long seq = tlsutils.readuint48(record, 5);
                if (recordepoch.getreplaywindow().shoulddiscard(seq))
                {
                    continue;
                }

                protocolversion version = tlsutils.readversion(record, 1);
                if (discoveredpeerversion != null && !discoveredpeerversion.equals(version))
                {
                    continue;
                }

                byte[] plaintext = recordepoch.getcipher().decodeciphertext(
                    getmacsequencenumber(recordepoch.getepoch(), seq), type, record, record_header_length,
                    received - record_header_length);

                recordepoch.getreplaywindow().reportauthenticated(seq);

                if (discoveredpeerversion == null)
                {
                    discoveredpeerversion = version;
                }

                switch (type)
                {
                case contenttype.alert:
                {

                    if (plaintext.length == 2)
                    {
                        short alertlevel = plaintext[0];
                        short alertdescription = plaintext[1];

                        peer.notifyalertreceived(alertlevel, alertdescription);

                        if (alertlevel == alertlevel.fatal)
                        {
                            fail(alertdescription);
                            throw new tlsfatalalert(alertdescription);
                        }

                        // todo can close_notify be a fatal alert?
                        if (alertdescription == alertdescription.close_notify)
                        {
                            closetransport();
                        }
                    }
                    else
                    {
                        // todo what exception?
                    }

                    continue;
                }
                case contenttype.application_data:
                {
                    if (inhandshake)
                    {
                        // todo consider buffering application data for new epoch that arrives
                        // out-of-order with the finished message
                        continue;
                    }
                    break;
                }
                case contenttype.change_cipher_spec:
                {
                    // implicitly receive change_cipher_spec and change to pending cipher state

                    if (plaintext.length != 1 || plaintext[0] != 1)
                    {
                        continue;
                    }

                    if (pendingepoch != null)
                    {
                        readepoch = pendingepoch;
                    }

                    continue;
                }
                case contenttype.handshake:
                {
                    if (!inhandshake)
                    {
                        if (retransmit != null)
                        {
                            retransmit.receivedhandshakerecord(epoch, plaintext, 0, plaintext.length);
                        }

                        // todo consider support for hellorequest
                        continue;
                    }
                }
                }

                /*
                 * note: if we receive any non-handshake data in the new epoch implies the peer has
                 * received our final flight.
                 */
                if (!inhandshake && retransmit != null)
                {
                    this.retransmit = null;
                    this.retransmitepoch = null;
                }

                system.arraycopy(plaintext, 0, buf, off, plaintext.length);
                return plaintext.length;
            }
            catch (ioexception e)
            {
                // note: assume this is a timeout for the moment
                throw e;
            }
        }
    }

    public void send(byte[] buf, int off, int len)
        throws ioexception
    {

        short contenttype = contenttype.application_data;

        if (this.inhandshake || this.writeepoch == this.retransmitepoch)
        {

            contenttype = contenttype.handshake;

            short handshaketype = tlsutils.readuint8(buf, off);
            if (handshaketype == handshaketype.finished)
            {

                dtlsepoch nextepoch = null;
                if (this.inhandshake)
                {
                    nextepoch = pendingepoch;
                }
                else if (this.writeepoch == this.retransmitepoch)
                {
                    nextepoch = currentepoch;
                }

                if (nextepoch == null)
                {
                    // todo
                    throw new illegalstateexception();
                }

                // implicitly send change_cipher_spec and change to pending cipher state

                // todo send change_cipher_spec and finished records in single datagram?
                byte[] data = new byte[]{1};
                sendrecord(contenttype.change_cipher_spec, data, 0, data.length);

                writeepoch = nextepoch;
            }
        }

        sendrecord(contenttype, buf, off, len);
    }

    public void close()
        throws ioexception
    {
        if (!closed)
        {
            if (inhandshake)
            {
                warn(alertdescription.user_canceled, "user canceled handshake");
            }
            closetransport();
        }
    }

    void fail(short alertdescription)
    {
        if (!closed)
        {
            try
            {
                raisealert(alertlevel.fatal, alertdescription, null, null);
            }
            catch (exception e)
            {
                // ignore
            }

            failed = true;

            closetransport();
        }
    }

    void warn(short alertdescription, string message)
        throws ioexception
    {
        raisealert(alertlevel.warning, alertdescription, message, null);
    }

    private void closetransport()
    {
        if (!closed)
        {
            /*
             * rfc 5246 7.2.1. unless some other fatal alert has been transmitted, each party is
             * required to send a close_notify alert before closing the write side of the
             * connection. the other party must respond with a close_notify alert of its own and
             * close down the connection immediately, discarding any pending writes.
             */

            try
            {
                if (!failed)
                {
                    warn(alertdescription.close_notify, null);
                }
                transport.close();
            }
            catch (exception e)
            {
                // ignore
            }

            closed = true;
        }
    }

    private void raisealert(short alertlevel, short alertdescription, string message, exception cause)
        throws ioexception
    {

        peer.notifyalertraised(alertlevel, alertdescription, message, cause);

        byte[] error = new byte[2];
        error[0] = (byte)alertlevel;
        error[1] = (byte)alertdescription;

        sendrecord(contenttype.alert, error, 0, 2);
    }

    private int receiverecord(byte[] buf, int off, int len, int waitmillis)
        throws ioexception
    {
        if (recordqueue.size() > 0)
        {
            int length = 0;
            if (recordqueue.size() >= record_header_length)
            {
                byte[] lengthbytes = new byte[2];
                recordqueue.read(lengthbytes, 0, 2, 11);
                length = tlsutils.readuint16(lengthbytes, 0);
            }

            int received = math.min(recordqueue.size(), record_header_length + length);
            recordqueue.read(buf, off, received, 0);
            recordqueue.removedata(received);
            return received;
        }

        int received = transport.receive(buf, off, len, waitmillis);
        if (received >= record_header_length)
        {
            int fragmentlength = tlsutils.readuint16(buf, off + 11);
            int recordlength = record_header_length + fragmentlength;
            if (received > recordlength)
            {
                recordqueue.adddata(buf, off + recordlength, received - recordlength);
                received = recordlength;
            }
        }

        return received;
    }

    private void sendrecord(short contenttype, byte[] buf, int off, int len)
        throws ioexception
    {

        /*
         * rfc 5264 6.2.1 implementations must not send zero-length fragments of handshake, alert,
         * or changecipherspec content types.
         */
        if (len < 1 && contenttype != contenttype.application_data)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        int recordepoch = writeepoch.getepoch();
        long recordsequencenumber = writeepoch.allocatesequencenumber();

        byte[] ciphertext = writeepoch.getcipher().encodeplaintext(
            getmacsequencenumber(recordepoch, recordsequencenumber), contenttype, buf, off, len);

        if (ciphertext.length > max_fragment_length)
        {
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        byte[] record = new byte[ciphertext.length + record_header_length];
        tlsutils.writeuint8(contenttype, record, 0);
        protocolversion version = discoveredpeerversion != null ? discoveredpeerversion : context.getclientversion();
        tlsutils.writeversion(version, record, 1);
        tlsutils.writeuint16(recordepoch, record, 3);
        tlsutils.writeuint48(recordsequencenumber, record, 5);
        tlsutils.writeuint16(ciphertext.length, record, 11);
        system.arraycopy(ciphertext, 0, record, record_header_length, ciphertext.length);

        transport.send(record, 0, record.length);
    }

    private static long getmacsequencenumber(int epoch, long sequence_number)
    {
        return ((long)epoch << 48) | sequence_number;
    }
}
