package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.util.enumeration;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.util.integers;

class dtlsreliablehandshake
{

    private final static int max_receive_ahead = 10;

    private final dtlsrecordlayer recordlayer;

    private tlshandshakehash hash = new deferredhash();

    private hashtable currentinboundflight = new hashtable();
    private hashtable previousinboundflight = null;
    private vector outboundflight = new vector();
    private boolean sending = true;

    private int message_seq = 0, next_receive_seq = 0;

    dtlsreliablehandshake(tlscontext context, dtlsrecordlayer transport)
    {
        this.recordlayer = transport;
        this.hash.init(context);
    }

    void notifyhellocomplete()
    {
        this.hash = this.hash.commit();
    }

    byte[] getcurrenthash()
    {
        tlshandshakehash copyofhash = hash.fork();
        byte[] result = new byte[copyofhash.getdigestsize()];
        copyofhash.dofinal(result, 0);
        return result;
    }

    void sendmessage(short msg_type, byte[] body)
        throws ioexception
    {

        if (!sending)
        {
            checkinboundflight();
            sending = true;
            outboundflight.removeallelements();
        }

        message message = new message(message_seq++, msg_type, body);

        outboundflight.addelement(message);

        writemessage(message);
        updatehandshakemessagesdigest(message);
    }

    message receivemessage()
        throws ioexception
    {

        if (sending)
        {
            sending = false;
            prepareinboundflight();
        }

        // check if we already have the next message waiting
        {
            dtlsreassembler next = (dtlsreassembler)currentinboundflight.get(integers.valueof(next_receive_seq));
            if (next != null)
            {
                byte[] body = next.getbodyifcomplete();
                if (body != null)
                {
                    previousinboundflight = null;
                    return updatehandshakemessagesdigest(new message(next_receive_seq++, next.gettype(), body));
                }
            }
        }

        byte[] buf = null;

        // todo check the conditions under which we should reset this
        int readtimeoutmillis = 1000;

        for (; ; )
        {

            int receivelimit = recordlayer.getreceivelimit();
            if (buf == null || buf.length < receivelimit)
            {
                buf = new byte[receivelimit];
            }

            // todo handle records containing multiple handshake messages

            try
            {
                for (; ; )
                {
                    int received = recordlayer.receive(buf, 0, receivelimit, readtimeoutmillis);
                    if (received < 0)
                    {
                        break;
                    }
                    if (received < 12)
                    {
                        continue;
                    }
                    int fragment_length = tlsutils.readuint24(buf, 9);
                    if (received != (fragment_length + 12))
                    {
                        continue;
                    }
                    int seq = tlsutils.readuint16(buf, 4);
                    if (seq > (next_receive_seq + max_receive_ahead))
                    {
                        continue;
                    }
                    short msg_type = tlsutils.readuint8(buf, 0);
                    int length = tlsutils.readuint24(buf, 1);
                    int fragment_offset = tlsutils.readuint24(buf, 6);
                    if (fragment_offset + fragment_length > length)
                    {
                        continue;
                    }

                    if (seq < next_receive_seq)
                    {
                        /*
                         * note: if we receive the previous flight of incoming messages in full
                         * again, retransmit our last flight
                         */
                        if (previousinboundflight != null)
                        {
                            dtlsreassembler reassembler = (dtlsreassembler)previousinboundflight.get(integers
                                .valueof(seq));
                            if (reassembler != null)
                            {

                                reassembler.contributefragment(msg_type, length, buf, 12, fragment_offset,
                                    fragment_length);

                                if (checkall(previousinboundflight))
                                {

                                    resendoutboundflight();

                                    /*
                                     * todo[dtls] implementations should back off handshake packet
                                     * size during the retransmit backoff.
                                     */
                                    readtimeoutmillis = math.min(readtimeoutmillis * 2, 60000);

                                    resetall(previousinboundflight);
                                }
                            }
                        }
                    }
                    else
                    {

                        dtlsreassembler reassembler = (dtlsreassembler)currentinboundflight.get(integers.valueof(seq));
                        if (reassembler == null)
                        {
                            reassembler = new dtlsreassembler(msg_type, length);
                            currentinboundflight.put(integers.valueof(seq), reassembler);
                        }

                        reassembler.contributefragment(msg_type, length, buf, 12, fragment_offset, fragment_length);

                        if (seq == next_receive_seq)
                        {
                            byte[] body = reassembler.getbodyifcomplete();
                            if (body != null)
                            {
                                previousinboundflight = null;
                                return updatehandshakemessagesdigest(new message(next_receive_seq++,
                                    reassembler.gettype(), body));
                            }
                        }
                    }
                }
            }
            catch (ioexception e)
            {
                // note: assume this is a timeout for the moment
            }

            resendoutboundflight();

            /*
             * todo[dtls] implementations should back off handshake packet size during the
             * retransmit backoff.
             */
            readtimeoutmillis = math.min(readtimeoutmillis * 2, 60000);
        }
    }

    void finish()
    {
        dtlshandshakeretransmit retransmit = null;
        if (!sending)
        {
            checkinboundflight();
        }
        else if (currentinboundflight != null)
        {
            /*
             * rfc 6347 4.2.4. in addition, for at least twice the default msl defined for [tcp],
             * when in the finished state, the node that transmits the last flight (the server in an
             * ordinary handshake or the client in a resumed handshake) must respond to a retransmit
             * of the peer's last flight with a retransmit of the last flight.
             */
            retransmit = new dtlshandshakeretransmit()
            {
                public void receivedhandshakerecord(int epoch, byte[] buf, int off, int len)
                    throws ioexception
                {
                    /*
                     * todo need to handle the case where the previous inbound flight contains
                     * messages from two epochs.
                     */
                    if (len < 12)
                    {
                        return;
                    }
                    int fragment_length = tlsutils.readuint24(buf, off + 9);
                    if (len != (fragment_length + 12))
                    {
                        return;
                    }
                    int seq = tlsutils.readuint16(buf, off + 4);
                    if (seq >= next_receive_seq)
                    {
                        return;
                    }

                    short msg_type = tlsutils.readuint8(buf, off);

                    // todo this is a hack that only works until we try to support renegotiation
                    int expectedepoch = msg_type == handshaketype.finished ? 1 : 0;
                    if (epoch != expectedepoch)
                    {
                        return;
                    }

                    int length = tlsutils.readuint24(buf, off + 1);
                    int fragment_offset = tlsutils.readuint24(buf, off + 6);
                    if (fragment_offset + fragment_length > length)
                    {
                        return;
                    }

                    dtlsreassembler reassembler = (dtlsreassembler)currentinboundflight.get(integers.valueof(seq));
                    if (reassembler != null)
                    {
                        reassembler.contributefragment(msg_type, length, buf, off + 12, fragment_offset,
                            fragment_length);
                        if (checkall(currentinboundflight))
                        {
                            resendoutboundflight();
                            resetall(currentinboundflight);
                        }
                    }
                }
            };
        }

        recordlayer.handshakesuccessful(retransmit);
    }

    void resethandshakemessagesdigest()
    {
        hash.reset();
    }

    /**
     * check that there are no "extra" messages left in the current inbound flight
     */
    private void checkinboundflight()
    {
        enumeration e = currentinboundflight.keys();
        while (e.hasmoreelements())
        {
            integer key = (integer)e.nextelement();
            if (key.intvalue() >= next_receive_seq)
            {
                // todo should this be considered an error?
            }
        }
    }

    private void prepareinboundflight()
    {
        resetall(currentinboundflight);
        previousinboundflight = currentinboundflight;
        currentinboundflight = new hashtable();
    }

    private void resendoutboundflight()
        throws ioexception
    {
        recordlayer.resetwriteepoch();
        for (int i = 0; i < outboundflight.size(); ++i)
        {
            writemessage((message)outboundflight.elementat(i));
        }
    }

    private message updatehandshakemessagesdigest(message message)
        throws ioexception
    {
        if (message.gettype() != handshaketype.hello_request)
        {
            byte[] body = message.getbody();
            byte[] buf = new byte[12];
            tlsutils.writeuint8(message.gettype(), buf, 0);
            tlsutils.writeuint24(body.length, buf, 1);
            tlsutils.writeuint16(message.getseq(), buf, 4);
            tlsutils.writeuint24(0, buf, 6);
            tlsutils.writeuint24(body.length, buf, 9);
            hash.update(buf, 0, buf.length);
            hash.update(body, 0, body.length);
        }
        return message;
    }

    private void writemessage(message message)
        throws ioexception
    {

        int sendlimit = recordlayer.getsendlimit();
        int fragmentlimit = sendlimit - 12;

        // todo support a higher minimum fragment size?
        if (fragmentlimit < 1)
        {
            // todo should we be throwing an exception here?
            throw new tlsfatalalert(alertdescription.internal_error);
        }

        int length = message.getbody().length;

        // note: must still send a fragment if body is empty
        int fragment_offset = 0;
        do
        {
            int fragment_length = math.min(length - fragment_offset, fragmentlimit);
            writehandshakefragment(message, fragment_offset, fragment_length);
            fragment_offset += fragment_length;
        }
        while (fragment_offset < length);
    }

    private void writehandshakefragment(message message, int fragment_offset, int fragment_length)
        throws ioexception
    {

        bytearrayoutputstream buf = new bytearrayoutputstream();
        tlsutils.writeuint8(message.gettype(), buf);
        tlsutils.writeuint24(message.getbody().length, buf);
        tlsutils.writeuint16(message.getseq(), buf);
        tlsutils.writeuint24(fragment_offset, buf);
        tlsutils.writeuint24(fragment_length, buf);
        buf.write(message.getbody(), fragment_offset, fragment_length);

        byte[] fragment = buf.tobytearray();

        recordlayer.send(fragment, 0, fragment.length);
    }

    private static boolean checkall(hashtable inboundflight)
    {
        enumeration e = inboundflight.elements();
        while (e.hasmoreelements())
        {
            if (((dtlsreassembler)e.nextelement()).getbodyifcomplete() == null)
            {
                return false;
            }
        }
        return true;
    }

    private static void resetall(hashtable inboundflight)
    {
        enumeration e = inboundflight.elements();
        while (e.hasmoreelements())
        {
            ((dtlsreassembler)e.nextelement()).reset();
        }
    }

    static class message
    {

        private final int message_seq;
        private final short msg_type;
        private final byte[] body;

        private message(int message_seq, short msg_type, byte[] body)
        {
            this.message_seq = message_seq;
            this.msg_type = msg_type;
            this.body = body;
        }

        public int getseq()
        {
            return message_seq;
        }

        public short gettype()
        {
            return msg_type;
        }

        public byte[] getbody()
        {
            return body;
        }
    }
}
