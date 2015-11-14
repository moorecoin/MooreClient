package org.ripple.bouncycastle.crypto.tls;

import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;

public class newsessionticket
{

    protected long ticketlifetimehint;
    protected byte[] ticket;

    public newsessionticket(long ticketlifetimehint, byte[] ticket)
    {
        this.ticketlifetimehint = ticketlifetimehint;
        this.ticket = ticket;
    }

    public long getticketlifetimehint()
    {
        return ticketlifetimehint;
    }

    public byte[] getticket()
    {
        return ticket;
    }

    public void encode(outputstream output)
        throws ioexception
    {
        tlsutils.writeuint32(ticketlifetimehint, output);
        tlsutils.writeopaque16(ticket, output);
    }

    public static newsessionticket parse(inputstream input)
        throws ioexception
    {
        long ticketlifetimehint = tlsutils.readuint32(input);
        byte[] ticket = tlsutils.readopaque16(input);
        return new newsessionticket(ticketlifetimehint, ticket);
    }
}
