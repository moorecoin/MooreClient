package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.net.datagrampacket;
import java.net.datagramsocket;

public class udptransport
    implements datagramtransport
{

    private final static int min_ip_overhead = 20;
    private final static int max_ip_overhead = min_ip_overhead + 64;
    private final static int udp_overhead = 8;

    private final datagramsocket socket;
    private final int receivelimit, sendlimit;

    public udptransport(datagramsocket socket, int mtu)
        throws ioexception
    {

        if (!socket.isbound() || !socket.isconnected())
        {
            throw new illegalargumentexception("'socket' must be bound and connected");
        }

        this.socket = socket;

        // note: as of jdk 1.6, can use networkinterface.getmtu

        this.receivelimit = mtu - min_ip_overhead - udp_overhead;
        this.sendlimit = mtu - max_ip_overhead - udp_overhead;
    }

    public int getreceivelimit()
    {
        return receivelimit;
    }

    public int getsendlimit()
    {
        // todo[dtls] implement path-mtu discovery?
        return sendlimit;
    }

    public int receive(byte[] buf, int off, int len, int waitmillis)
        throws ioexception
    {
        socket.setsotimeout(waitmillis);
        datagrampacket packet = new datagrampacket(buf, off, len);
        socket.receive(packet);
        return packet.getlength();
    }

    public void send(byte[] buf, int off, int len)
        throws ioexception
    {
        if (len > getsendlimit())
        {
            /*
             * rfc 4347 4.1.1. "if the application attempts to send a record larger than the mtu,
             * the dtls implementation should generate an error, thus avoiding sending a packet
             * which will be fragmented."
             */
            // todo exception
        }

        datagrampacket packet = new datagrampacket(buf, off, len);
        socket.send(packet);
    }

    public void close()
        throws ioexception
    {
        socket.close();
    }
}
