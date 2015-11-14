package org.ripple.bouncycastle.asn1;

import java.io.bytearrayinputstream;
import java.io.eofexception;
import java.io.filterinputstream;
import java.io.ioexception;
import java.io.inputstream;

import org.ripple.bouncycastle.util.io.streams;

/**
 * a general purpose asn.1 decoder - note: this class differs from the
 * others in that it returns null after it has read the last object in
 * the stream. if an asn.1 null is encountered a der/ber null object is
 * returned.
 */
public class asn1inputstream
    extends filterinputstream
    implements bertags
{
    private final int limit;
    private final boolean lazyevaluate;

    private final byte[][] tmpbuffers;

    public asn1inputstream(
        inputstream is)
    {
        this(is, streamutil.findlimit(is));
    }

    /**
     * create an asn1inputstream based on the input byte array. the length of der objects in
     * the stream is automatically limited to the length of the input array.
     * 
     * @param input array containing asn.1 encoded data.
     */
    public asn1inputstream(
        byte[] input)
    {
        this(new bytearrayinputstream(input), input.length);
    }

    /**
     * create an asn1inputstream based on the input byte array. the length of der objects in
     * the stream is automatically limited to the length of the input array.
     *
     * @param input array containing asn.1 encoded data.
     * @param lazyevaluate true if parsing inside constructed objects can be delayed.
     */
    public asn1inputstream(
        byte[] input,
        boolean lazyevaluate)
    {
        this(new bytearrayinputstream(input), input.length, lazyevaluate);
    }
    
    /**
     * create an asn1inputstream where no der object will be longer than limit.
     * 
     * @param input stream containing asn.1 encoded data.
     * @param limit maximum size of a der encoded object.
     */
    public asn1inputstream(
        inputstream input,
        int         limit)
    {
        this(input, limit, false);
    }

    /**
     * create an asn1inputstream where no der object will be longer than limit, and constructed
     * objects such as sequences will be parsed lazily.
     *
     * @param input stream containing asn.1 encoded data.
     * @param lazyevaluate true if parsing inside constructed objects can be delayed.
     */
    public asn1inputstream(
        inputstream input,
        boolean     lazyevaluate)
    {
        this(input, streamutil.findlimit(input), lazyevaluate);
    }

    /**
     * create an asn1inputstream where no der object will be longer than limit, and constructed
     * objects such as sequences will be parsed lazily.
     *
     * @param input stream containing asn.1 encoded data.
     * @param limit maximum size of a der encoded object.
     * @param lazyevaluate true if parsing inside constructed objects can be delayed.
     */
    public asn1inputstream(
        inputstream input,
        int         limit,
        boolean     lazyevaluate)
    {
        super(input);
        this.limit = limit;
        this.lazyevaluate = lazyevaluate;
        this.tmpbuffers = new byte[11][];
    }

    int getlimit()
    {
        return limit;
    }

    protected int readlength()
        throws ioexception
    {
        return readlength(this, limit);
    }

    protected void readfully(
        byte[]  bytes)
        throws ioexception
    {
        if (streams.readfully(this, bytes) != bytes.length)
        {
            throw new eofexception("eof encountered in middle of object");
        }
    }

    /**
     * build an object given its tag and the number of bytes to construct it from.
     */
    protected asn1primitive buildobject(
        int       tag,
        int       tagno,
        int       length)
        throws ioexception
    {
        boolean isconstructed = (tag & constructed) != 0;

        definitelengthinputstream defin = new definitelengthinputstream(this, length);

        if ((tag & application) != 0)
        {
            return new derapplicationspecific(isconstructed, tagno, defin.tobytearray());
        }

        if ((tag & tagged) != 0)
        {
            return new asn1streamparser(defin).readtaggedobject(isconstructed, tagno);
        }

        if (isconstructed)
        {
            // todo there are other tags that may be constructed (e.g. bit_string)
            switch (tagno)
            {
                case octet_string:
                    //
                    // yes, people actually do this...
                    //
                    asn1encodablevector v = buildderencodablevector(defin);
                    asn1octetstring[] strings = new asn1octetstring[v.size()];

                    for (int i = 0; i != strings.length; i++)
                    {
                        strings[i] = (asn1octetstring)v.get(i);
                    }

                    return new beroctetstring(strings);
                case sequence:
                    if (lazyevaluate)
                    {
                        return new lazyencodedsequence(defin.tobytearray());
                    }
                    else
                    {
                        return derfactory.createsequence(buildderencodablevector(defin));   
                    }
                case set:
                    return derfactory.createset(buildderencodablevector(defin));
                case external:
                    return new derexternal(buildderencodablevector(defin));                
                default:
                    throw new ioexception("unknown tag " + tagno + " encountered");
            }
        }

        return createprimitivederobject(tagno, defin, tmpbuffers);
    }

    asn1encodablevector buildencodablevector()
        throws ioexception
    {
        asn1encodablevector v = new asn1encodablevector();
        asn1primitive o;

        while ((o = readobject()) != null)
        {
            v.add(o);
        }

        return v;
    }

    asn1encodablevector buildderencodablevector(
        definitelengthinputstream din) throws ioexception
    {
        return new asn1inputstream(din).buildencodablevector();
    }

    public asn1primitive readobject()
        throws ioexception
    {
        int tag = read();
        if (tag <= 0)
        {
            if (tag == 0)
            {
                throw new ioexception("unexpected end-of-contents marker");
            }

            return null;
        }

        //
        // calculate tag number
        //
        int tagno = readtagnumber(this, tag);

        boolean isconstructed = (tag & constructed) != 0;

        //
        // calculate length
        //
        int length = readlength();

        if (length < 0) // indefinite length method
        {
            if (!isconstructed)
            {
                throw new ioexception("indefinite length primitive encoding encountered");
            }

            indefinitelengthinputstream indin = new indefinitelengthinputstream(this, limit);
            asn1streamparser sp = new asn1streamparser(indin, limit);

            if ((tag & application) != 0)
            {
                return new berapplicationspecificparser(tagno, sp).getloadedobject();
            }

            if ((tag & tagged) != 0)
            {
                return new bertaggedobjectparser(true, tagno, sp).getloadedobject();
            }

            // todo there are other tags that may be constructed (e.g. bit_string)
            switch (tagno)
            {
                case octet_string:
                    return new beroctetstringparser(sp).getloadedobject();
                case sequence:
                    return new bersequenceparser(sp).getloadedobject();
                case set:
                    return new bersetparser(sp).getloadedobject();
                case external:
                    return new derexternalparser(sp).getloadedobject();
                default:
                    throw new ioexception("unknown ber object encountered");
            }
        }
        else
        {
            try
            {
                return buildobject(tag, tagno, length);
            }
            catch (illegalargumentexception e)
            {
                throw new asn1exception("corrupted stream detected", e);
            }
        }
    }

    static int readtagnumber(inputstream s, int tag) 
        throws ioexception
    {
        int tagno = tag & 0x1f;

        //
        // with tagged object tag number is bottom 5 bits, or stored at the start of the content
        //
        if (tagno == 0x1f)
        {
            tagno = 0;

            int b = s.read();

            // x.690-0207 8.1.2.4.2
            // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
            if ((b & 0x7f) == 0) // note: -1 will pass
            {
                throw new ioexception("corrupted stream - invalid high tag number found");
            }

            while ((b >= 0) && ((b & 0x80) != 0))
            {
                tagno |= (b & 0x7f);
                tagno <<= 7;
                b = s.read();
            }

            if (b < 0)
            {
                throw new eofexception("eof found inside tag value.");
            }
            
            tagno |= (b & 0x7f);
        }
        
        return tagno;
    }

    static int readlength(inputstream s, int limit)
        throws ioexception
    {
        int length = s.read();
        if (length < 0)
        {
            throw new eofexception("eof found when length expected");
        }

        if (length == 0x80)
        {
            return -1;      // indefinite-length encoding
        }

        if (length > 127)
        {
            int size = length & 0x7f;

            // note: the invalid long form "0xff" (see x.690 8.1.3.5c) will be caught here
            if (size > 4)
            {
                throw new ioexception("der length more than 4 bytes: " + size);
            }

            length = 0;
            for (int i = 0; i < size; i++)
            {
                int next = s.read();

                if (next < 0)
                {
                    throw new eofexception("eof found reading length");
                }

                length = (length << 8) + next;
            }

            if (length < 0)
            {
                throw new ioexception("corrupted stream - negative length found");
            }

            if (length >= limit)   // after all we must have read at least 1 byte
            {
                throw new ioexception("corrupted stream - out of bounds length found");
            }
        }

        return length;
    }

    private static byte[] getbuffer(definitelengthinputstream defin, byte[][] tmpbuffers)
        throws ioexception
    {
        int len = defin.getremaining();
        if (defin.getremaining() < tmpbuffers.length)
        {
            byte[] buf = tmpbuffers[len];

            if (buf == null)
            {
                buf = tmpbuffers[len] = new byte[len];
            }

            streams.readfully(defin, buf);

            return buf;
        }
        else
        {
            return defin.tobytearray();
        }
    }

    private static char[] getbmpcharbuffer(definitelengthinputstream defin)
        throws ioexception
    {
        int len = defin.getremaining() / 2;
        char[] buf = new char[len];
        int totalread = 0;
        while (totalread < len)
        {
            int ch1 = defin.read();
            if (ch1 < 0)
            {
                break;
            }
            int ch2 = defin.read();
            if (ch2 < 0)
            {
                break;
            }
            buf[totalread++] = (char)((ch1 << 8) | (ch2 & 0xff));
        }

        return buf;
    }

    static asn1primitive createprimitivederobject(
        int     tagno,
        definitelengthinputstream defin,
        byte[][] tmpbuffers)
        throws ioexception
    {
        switch (tagno)
        {
            case bit_string:
                return derbitstring.frominputstream(defin.getremaining(), defin);
            case bmp_string:
                return new derbmpstring(getbmpcharbuffer(defin));
            case boolean:
                return asn1boolean.fromoctetstring(getbuffer(defin, tmpbuffers));
            case enumerated:
                return asn1enumerated.fromoctetstring(getbuffer(defin, tmpbuffers));
            case generalized_time:
                return new asn1generalizedtime(defin.tobytearray());
            case general_string:
                return new dergeneralstring(defin.tobytearray());
            case ia5_string:
                return new deria5string(defin.tobytearray());
            case integer:
                return new asn1integer(defin.tobytearray());
            case null:
                return dernull.instance;   // actual content is ignored (enforce 0 length?)
            case numeric_string:
                return new dernumericstring(defin.tobytearray());
            case object_identifier:
                return asn1objectidentifier.fromoctetstring(getbuffer(defin, tmpbuffers));
            case octet_string:
                return new deroctetstring(defin.tobytearray());
            case printable_string:
                return new derprintablestring(defin.tobytearray());
            case t61_string:
                return new dert61string(defin.tobytearray());
            case universal_string:
                return new deruniversalstring(defin.tobytearray());
            case utc_time:
                return new asn1utctime(defin.tobytearray());
            case utf8_string:
                return new derutf8string(defin.tobytearray());
            case visible_string:
                return new dervisiblestring(defin.tobytearray());
            default:
                throw new ioexception("unknown tag " + tagno + " encountered");
        }
    }
}
