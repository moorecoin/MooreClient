package org.ripple.bouncycastle.asn1;

import java.io.bytearrayinputstream;
import java.io.ioexception;
import java.io.inputstream;

public class asn1streamparser
{
    private final inputstream _in;
    private final int         _limit;
    private final byte[][] tmpbuffers;

    public asn1streamparser(
        inputstream in)
    {
        this(in, streamutil.findlimit(in));
    }

    public asn1streamparser(
        inputstream in,
        int         limit)
    {
        this._in = in;
        this._limit = limit;

        this.tmpbuffers = new byte[11][];
    }

    public asn1streamparser(
        byte[] encoding)
    {
        this(new bytearrayinputstream(encoding), encoding.length);
    }

    asn1encodable readindef(int tagvalue) throws ioexception
    {
        // note: indef => constructed

        // todo there are other tags that may be constructed (e.g. bit_string)
        switch (tagvalue)
        {
            case bertags.external:
                return new derexternalparser(this);
            case bertags.octet_string:
                return new beroctetstringparser(this);
            case bertags.sequence:
                return new bersequenceparser(this);
            case bertags.set:
                return new bersetparser(this);
            default:
                throw new asn1exception("unknown ber object encountered: 0x" + integer.tohexstring(tagvalue));
        }
    }

    asn1encodable readimplicit(boolean constructed, int tag) throws ioexception
    {
        if (_in instanceof indefinitelengthinputstream)
        {
            if (!constructed)
            {
                throw new ioexception("indefinite length primitive encoding encountered");
            }
            
            return readindef(tag);
        }

        if (constructed)
        {
            switch (tag)
            {
                case bertags.set:
                    return new dersetparser(this);
                case bertags.sequence:
                    return new dersequenceparser(this);
                case bertags.octet_string:
                    return new beroctetstringparser(this);
            }
        }
        else
        {
            switch (tag)
            {
                case bertags.set:
                    throw new asn1exception("sequences must use constructed encoding (see x.690 8.9.1/8.10.1)");
                case bertags.sequence:
                    throw new asn1exception("sets must use constructed encoding (see x.690 8.11.1/8.12.1)");
                case bertags.octet_string:
                    return new deroctetstringparser((definitelengthinputstream)_in);
            }
        }

        // todo asn1exception
        throw new runtimeexception("implicit tagging not implemented");
    }

    asn1primitive readtaggedobject(boolean constructed, int tag) throws ioexception
    {
        if (!constructed)
        {
            // note: !constructed => implicit
            definitelengthinputstream defin = (definitelengthinputstream)_in;
            return new dertaggedobject(false, tag, new deroctetstring(defin.tobytearray()));
        }

        asn1encodablevector v = readvector();

        if (_in instanceof indefinitelengthinputstream)
        {
            return v.size() == 1
                ?   new bertaggedobject(true, tag, v.get(0))
                :   new bertaggedobject(false, tag, berfactory.createsequence(v));
        }

        return v.size() == 1
            ?   new dertaggedobject(true, tag, v.get(0))
            :   new dertaggedobject(false, tag, derfactory.createsequence(v));
    }

    public asn1encodable readobject()
        throws ioexception
    {
        int tag = _in.read();
        if (tag == -1)
        {
            return null;
        }

        //
        // turn of looking for "00" while we resolve the tag
        //
        set00check(false);

        //
        // calculate tag number
        //
        int tagno = asn1inputstream.readtagnumber(_in, tag);

        boolean isconstructed = (tag & bertags.constructed) != 0;

        //
        // calculate length
        //
        int length = asn1inputstream.readlength(_in, _limit);

        if (length < 0) // indefinite length method
        {
            if (!isconstructed)
            {
                throw new ioexception("indefinite length primitive encoding encountered");
            }

            indefinitelengthinputstream indin = new indefinitelengthinputstream(_in, _limit);
            asn1streamparser sp = new asn1streamparser(indin, _limit);

            if ((tag & bertags.application) != 0)
            {
                return new berapplicationspecificparser(tagno, sp);
            }

            if ((tag & bertags.tagged) != 0)
            {
                return new bertaggedobjectparser(true, tagno, sp);
            }

            return sp.readindef(tagno);
        }
        else
        {
            definitelengthinputstream defin = new definitelengthinputstream(_in, length);

            if ((tag & bertags.application) != 0)
            {
                return new derapplicationspecific(isconstructed, tagno, defin.tobytearray());
            }

            if ((tag & bertags.tagged) != 0)
            {
                return new bertaggedobjectparser(isconstructed, tagno, new asn1streamparser(defin));
            }

            if (isconstructed)
            {
                // todo there are other tags that may be constructed (e.g. bit_string)
                switch (tagno)
                {
                    case bertags.octet_string:
                        //
                        // yes, people actually do this...
                        //
                        return new beroctetstringparser(new asn1streamparser(defin));
                    case bertags.sequence:
                        return new dersequenceparser(new asn1streamparser(defin));
                    case bertags.set:
                        return new dersetparser(new asn1streamparser(defin));
                    case bertags.external:
                        return new derexternalparser(new asn1streamparser(defin));
                    default:
                        throw new ioexception("unknown tag " + tagno + " encountered");
                }
            }

            // some primitive encodings can be handled by parsers too...
            switch (tagno)
            {
                case bertags.octet_string:
                    return new deroctetstringparser(defin);
            }

            try
            {
                return asn1inputstream.createprimitivederobject(tagno, defin, tmpbuffers);
            }
            catch (illegalargumentexception e)
            {
                throw new asn1exception("corrupted stream detected", e);
            }
        }
    }

    private void set00check(boolean enabled)
    {
        if (_in instanceof indefinitelengthinputstream)
        {
            ((indefinitelengthinputstream)_in).seteofon00(enabled);
        }
    }

    asn1encodablevector readvector() throws ioexception
    {
        asn1encodablevector v = new asn1encodablevector();

        asn1encodable obj;
        while ((obj = readobject()) != null)
        {
            if (obj instanceof inmemoryrepresentable)
            {
                v.add(((inmemoryrepresentable)obj).getloadedobject());
            }
            else
            {
                v.add(obj.toasn1primitive());
            }
        }

        return v;
    }
}
