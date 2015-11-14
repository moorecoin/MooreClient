package org.moorecoinlab.btc;

import com.google.common.base.charsets;
import com.google.common.base.joiner;
import com.google.common.collect.lists;
import com.google.common.collect.ordering;
import com.google.common.io.baseencoding;
import com.google.common.io.resources;
import com.google.common.primitives.ints;
import com.google.common.primitives.unsignedlongs;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.ripple.bouncycastle.crypto.digests.ripemd160digest;

import java.io.ioexception;
import java.io.outputstream;
import java.math.biginteger;
import java.net.url;
import java.nio.bytebuffer;
import java.security.messagedigest;
import java.security.nosuchalgorithmexception;
import java.util.*;
import java.util.concurrent.arrayblockingqueue;
import java.util.concurrent.blockingqueue;
import java.util.concurrent.timeunit;

import static com.google.common.base.preconditions.checkargument;
import static com.google.common.util.concurrent.uninterruptibles.sleepuninterruptibly;

/**
 * a collection of various utility methods that are helpful for working with the bitcoin protocol.
 * to enable debug logging from the library, run with -dbitcoinj.logging=true on your command line.
 */
public class bitutil {
    public static boolean debug = false;
    public static final int address_version = 0;

    private static final messagedigest digest;
    static {
        try {
            digest = messagedigest.getinstance("sha-256");
        } catch (nosuchalgorithmexception e) {
            throw new runtimeexception(e);  // can't happen.
        }
    }

    /** the string that prefixes all text messages signed using bitcoin keys. */
    public static final string bitcoin_signed_message_header = "bitcoin signed message:\n";
    public static final byte[] bitcoin_signed_message_header_bytes = bitcoin_signed_message_header.getbytes(charsets.utf_8);

    private static blockingqueue<boolean> mocksleepqueue;


    /**
     * returns the given byte array hex encoded.
     */
    public static string bytestohexstring(byte[] bytes) {
        stringbuffer buf = new stringbuffer(bytes.length * 2);
        for (byte b : bytes) {
            string s = integer.tostring(0xff & b, 16);
            if (s.length() < 2)
                buf.append('0');
            buf.append(s);
        }
        return buf.tostring();
    }

    /**
     * the regular {@link java.math.biginteger#tobytearray()} method isn't quite what we often need: it appends a
     * leading zero to indicate that the number is positive and may need padding.
     *
     * @param b the integer to format into a byte array
     * @param numbytes the desired size of the resulting byte array
     * @return numbytes byte long array.
     */
    public static byte[] bigintegertobytes(biginteger b, int numbytes) {
        if (b == null) {
            return null;
        }
        byte[] bytes = new byte[numbytes];
        byte[] bibytes = b.tobytearray();
        int start = (bibytes.length == numbytes + 1) ? 1 : 0;
        int length = math.min(bibytes.length, numbytes);
        system.arraycopy(bibytes, start, bytes, numbytes - length, length);
        return bytes;
    }

    public static void uint32tobytearraybe(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xff & (val >> 24));
        out[offset + 1] = (byte) (0xff & (val >> 16));
        out[offset + 2] = (byte) (0xff & (val >> 8));
        out[offset + 3] = (byte) (0xff & (val >> 0));
    }

    public static void uint32tobytearrayle(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xff & (val >> 0));
        out[offset + 1] = (byte) (0xff & (val >> 8));
        out[offset + 2] = (byte) (0xff & (val >> 16));
        out[offset + 3] = (byte) (0xff & (val >> 24));
    }

    public static void uint64tobytearrayle(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xff & (val >> 0));
        out[offset + 1] = (byte) (0xff & (val >> 8));
        out[offset + 2] = (byte) (0xff & (val >> 16));
        out[offset + 3] = (byte) (0xff & (val >> 24));
        out[offset + 4] = (byte) (0xff & (val >> 32));
        out[offset + 5] = (byte) (0xff & (val >> 40));
        out[offset + 6] = (byte) (0xff & (val >> 48));
        out[offset + 7] = (byte) (0xff & (val >> 56));
    }

    public static void uint32tobytestreamle(long val, outputstream stream) throws ioexception {
        stream.write((int) (0xff & (val >> 0)));
        stream.write((int) (0xff & (val >> 8)));
        stream.write((int) (0xff & (val >> 16)));
        stream.write((int) (0xff & (val >> 24)));
    }

    public static void int64tobytestreamle(long val, outputstream stream) throws ioexception {
        stream.write((int) (0xff & (val >> 0)));
        stream.write((int) (0xff & (val >> 8)));
        stream.write((int) (0xff & (val >> 16)));
        stream.write((int) (0xff & (val >> 24)));
        stream.write((int) (0xff & (val >> 32)));
        stream.write((int) (0xff & (val >> 40)));
        stream.write((int) (0xff & (val >> 48)));
        stream.write((int) (0xff & (val >> 56)));
    }

    public static void uint64tobytestreamle(biginteger val, outputstream stream) throws ioexception {
        byte[] bytes = val.tobytearray();
        if (bytes.length > 8) {
            throw new runtimeexception("input too large to encode into a uint64");
        }
        bytes = reversebytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0; i < 8 - bytes.length; i++)
                stream.write(0);
        }
    }

    /**
     * see {@link bitutil#doubledigest(byte[], int, int)}.
     */
    public static byte[] doubledigest(byte[] input) {
        return doubledigest(input, 0, input.length);
    }

    /**
     * calculates the sha-256 hash of the given byte range, and then hashes the resulting hash again. this is
     * standard procedure in bitcoin. the resulting hash is in big endian form.
     */
    public static byte[] doubledigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    public static byte[] singledigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            return digest.digest();
        }
    }

    /**
     * calculates sha256(sha256(byte range 1 + byte range 2)).
     */
    public static byte[] doubledigesttwobuffers(byte[] input1, int offset1, int length1,
                                                byte[] input2, int offset2, int length2) {
        synchronized (digest) {
            digest.reset();
            digest.update(input1, offset1, length1);
            digest.update(input2, offset2, length2);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    /**
     * work around lack of unsigned types in java.
     */
    public static boolean islessthanunsigned(long n1, long n2) {
        return unsignedlongs.compare(n1, n2) < 0;
    }

    /**
     * work around lack of unsigned types in java.
     */
    public static boolean islessthanorequaltounsigned(long n1, long n2) {
        return unsignedlongs.compare(n1, n2) <= 0;
    }

    /**
     * hex encoding used throughout the framework. use with hex.encode(byte[]) or hex.decode(charsequence).
     */
    public static final baseencoding hex = baseencoding.base16().lowercase();

    /**
     * returns a copy of the given byte array in reverse order.
     */
    public static byte[] reversebytes(byte[] bytes) {
        // we could use the xor trick here but it's easier to understand if we don't. if we find this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }

    /**
     * returns a copy of the given byte array with the bytes of each double-word (4 bytes) reversed.
     *
     * @param bytes length must be divisible by 4.
     * @param trimlength trim output to this length.  if positive, must be divisible by 4.
     */
    public static byte[] reversedwordbytes(byte[] bytes, int trimlength) {
        checkargument(bytes.length % 4 == 0);
        checkargument(trimlength < 0 || trimlength % 4 == 0);

        byte[] rev = new byte[trimlength >= 0 && bytes.length > trimlength ? trimlength : bytes.length];

        for (int i = 0; i < rev.length; i += 4) {
            system.arraycopy(bytes, i, rev, i , 4);
            for (int j = 0; j < 4; j++) {
                rev[i + j] = bytes[i + 3 - j];
            }
        }
        return rev;
    }

    public static long readuint32(byte[] bytes, int offset) { //bytes to unsigned int
        return ((bytes[offset++] & 0xffl) << 0) |
                ((bytes[offset++] & 0xffl) << 8) |
                ((bytes[offset++] & 0xffl) << 16) |
                ((bytes[offset] & 0xffl) << 24);
    }

    public static long readint64(byte[] bytes, int offset) { //bytes to long
        return ((bytes[offset++] & 0xffl) << 0) |
                ((bytes[offset++] & 0xffl) << 8) |
                ((bytes[offset++] & 0xffl) << 16) |
                ((bytes[offset++] & 0xffl) << 24) |
                ((bytes[offset++] & 0xffl) << 32) |
                ((bytes[offset++] & 0xffl) << 40) |
                ((bytes[offset++] & 0xffl) << 48) |
                ((bytes[offset] & 0xffl) << 56);
    }


    public static byte[] longtobytes(long x) {
        bytebuffer buffer = bytebuffer.allocate(8);
        buffer.putlong(0, x);
        return buffer.array();
    }

    public static long bytestolong(byte[] bytes) {
        bytebuffer buffer = bytebuffer.allocate(8);
        buffer.put(bytes, 0, bytes.length);
        buffer.flip();//need flip
        return buffer.getlong();
    }

    public static long readuint32be(byte[] bytes, int offset) {
        return ((bytes[offset + 0] & 0xffl) << 24) |
                ((bytes[offset + 1] & 0xffl) << 16) |
                ((bytes[offset + 2] & 0xffl) << 8) |
                ((bytes[offset + 3] & 0xffl) << 0);
    }

    public static int readuint16be(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | bytes[offset + 1] & 0xff;
    }

    /**
     * calculates ripemd160(sha256(input)). this is used in address calculations.
     */
    public static byte[] sha256hash160(byte[] input) {
        try {
            byte[] sha256 = messagedigest.getinstance("sha-256").digest(input);
            ripemd160digest digest = new ripemd160digest();
            digest.update(sha256, 0, sha256.length);
            byte[] out = new byte[20];
            digest.dofinal(out, 0);
            return out;
        } catch (nosuchalgorithmexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    /**
     * check if bitcoin address format ?
     * @param addr
     * @return
     */
    public static boolean isbtcaddress(string addr) {
        try {
            //todo
            // address tmp = new address(0, addr);
        } catch (exception e) {
            if(debug) e.printstacktrace();
            return false;
        }
        return true;
    }

    /**
     * mpi encoded numbers are produced by the openssl bn_bn2mpi function. they consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     * @param haslength can be set to false if the given array is missing the 4 byte length field
     */
    public static biginteger decodempi(byte[] mpi, boolean haslength) {
        byte[] buf;
        if (haslength) {
            int length = (int) readuint32be(mpi, 0);
            buf = new byte[length];
            system.arraycopy(mpi, 4, buf, 0, length);
        } else
            buf = mpi;
        if (buf.length == 0)
            return biginteger.zero;
        boolean isnegative = (buf[0] & 0x80) == 0x80;
        if (isnegative)
            buf[0] &= 0x7f;
        biginteger result = new biginteger(buf);
        return isnegative ? result.negate() : result;
    }

    /**
     * mpi encoded numbers are produced by the openssl bn_bn2mpi function. they consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format (with a sign bit).
     * @param includelength indicates whether the 4 byte length field should be included
     */
    public static byte[] encodempi(biginteger value, boolean includelength) {
        if (value.equals(biginteger.zero)) {
            if (!includelength)
                return new byte[] {};
            else
                return new byte[] {0x00, 0x00, 0x00, 0x00};
        }
        boolean isnegative = value.signum() < 0;
        if (isnegative)
            value = value.negate();
        byte[] array = value.tobytearray();
        int length = array.length;
        if ((array[0] & 0x80) == 0x80)
            length++;
        if (includelength) {
            byte[] result = new byte[length + 4];
            system.arraycopy(array, 0, result, length - array.length + 3, array.length);
            uint32tobytearraybe(length, result, 0);
            if (isnegative)
                result[4] |= 0x80;
            return result;
        } else {
            byte[] result;
            if (length != array.length) {
                result = new byte[length];
                system.arraycopy(array, 0, result, 1, array.length);
            }else
                result = array;
            if (isnegative)
                result[0] |= 0x80;
            return result;
        }
    }

    /**
     * <p>the "compact" format is a representation of a whole number n using an unsigned 32 bit number similar to a
     * floating point format. the most significant 8 bits are the unsigned exponent of base 256. this exponent can
     * be thought of as "number of bytes of n". the lower 23 bits are the mantissa. bit number 24 (0x800000) represents
     * the sign of n. therefore, n = (-1^sign) * mantissa * 256^(exponent-3).</p>
     *
     * <p>satoshi's original implementation used bn_bn2mpi() and bn_mpi2bn(). mpi uses the most significant bit of the
     * first byte as sign. thus 0x1234560000 is compact 0x05123456 and 0xc0de000000 is compact 0x0600c0de. compact
     * 0x05c0de00 would be -0x40de000000.</p>
     *
     * <p>bitcoin only uses this "compact" format for encoding difficulty targets, which are unsigned 256bit quantities.
     * thus, all the complexities of the sign bit and using base 256 are probably an implementation accident.</p>
     */
    public static biginteger decodecompactbits(long compact) {
        int size = ((int) (compact >> 24)) & 0xff;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte) size;
        if (size >= 1) bytes[4] = (byte) ((compact >> 16) & 0xff);
        if (size >= 2) bytes[5] = (byte) ((compact >> 8) & 0xff);
        if (size >= 3) bytes[6] = (byte) ((compact >> 0) & 0xff);
        return decodempi(bytes, true);
    }

    /**
     * @see bitutil#decodecompactbits(long)
     */
    public static long encodecompactbits(biginteger value) {
        long result;
        int size = value.tobytearray().length;
        if (size <= 3)
            result = value.longvalue() << 8 * (3 - size);
        else
            result = value.shiftright(8 * (size - 3)).longvalue();
        // the 0x00800000 bit denotes the sign.
        // thus, if it is already set, divide the mantissa by 256 and increase the exponent.
        if ((result & 0x00800000l) != 0) {
            result >>= 8;
            size++;
        }
        result |= size << 24;
        result |= value.signum() == -1 ? 0x00800000 : 0;
        return result;
    }

    /**
     * if non-null, overrides the return value of now().
     */
    public static volatile date mocktime;

    /**
     * advances (or rewinds) the mock clock by the given number of seconds.
     */
    public static date rollmockclock(int seconds) {
        return rollmockclockmillis(seconds * 1000);
    }

    /**
     * advances (or rewinds) the mock clock by the given number of milliseconds.
     */
    public static date rollmockclockmillis(long millis) {
        if (mocktime == null)
            throw new illegalstateexception("you need to use setmockclock() first.");
        mocktime = new date(mocktime.gettime() + millis);
        return mocktime;
    }

    /**
     * sets the mock clock to the current time.
     */
    public static void setmockclock() {
        mocktime = new date();
    }

    /**
     * sets the mock clock to the given time (in seconds).
     */
    public static void setmockclock(long mockclockseconds) {
        mocktime = new date(mockclockseconds * 1000);
    }

    /**
     * returns the current time, or a mocked out equivalent.
     */
    public static date now() {
        if (mocktime != null)
            return mocktime;
        else
            return new date();
    }

    // todo: replace usages of this where the result is / 1000 with currenttimeseconds.
    /** returns the current time in milliseconds since the epoch, or a mocked out equivalent. */
    public static long currenttimemillis() {
        if (mocktime != null)
            return mocktime.gettime();
        else
            return system.currenttimemillis();
    }

    public static long currenttimeseconds() {
        return currenttimemillis() / 1000;
    }

    public static byte[] copyof(byte[] in, int length) {
        byte[] out = new byte[length];
        system.arraycopy(in, 0, out, 0, math.min(length, in.length));
        return out;
    }

    /**
     * creates a copy of bytes and appends b to the end of it
     */
    public static byte[] appendbyte(byte[] bytes, byte b) {
        byte[] result = arrays.copyof(bytes, bytes.length + 1);
        result[result.length - 1] = b;
        return result;
    }

    /**
     * attempts to parselist the given string as arbitrary-length hex or base58 and then return the results, or null if
     * neither parselist was successful.
     */
    public static byte[] parseashexorbase58(string data) {
        try {
            return hex.decode(data);
        } catch (exception e) {
            // didn't decode as hex, try base58.
            try {
                return base58.decodechecked(data);
            } catch (moorecoinexception e1) {
                return null;
            }
        }
    }

    public static boolean iswindows() {
        return system.getproperty("os.name").tolowercase().contains("win");
    }


    // 00000001, 00000010, 00000100, 00001000, ...
    private static final int bitmask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

    /** checks if the given bit is set in data, using little endian (not the same as java native big endian) */
    public static boolean checkbitle(byte[] data, int index) {
        return (data[index >>> 3] & bitmask[7 & index]) != 0;
    }

    /** sets the given bit in data to one, using little endian (not the same as java native big endian) */
    public static void setbitle(byte[] data, int index) {
        data[index >>> 3] |= bitmask[7 & index];
    }

    /** sleep for a span of time, or mock sleep if enabled */
    public static void sleep(long millis) {
        if (mocksleepqueue == null) {
            sleepuninterruptibly(millis, timeunit.milliseconds);
        } else {
            try {
                boolean ismultipass = mocksleepqueue.take();
                rollmockclockmillis(millis);
                if (ismultipass)
                    mocksleepqueue.offer(true);
            } catch (interruptedexception e) {
                // ignored.
            }
        }
    }

    /** enable or disable mock sleep.  if enabled, set mock time to current time. */
    public static void setmocksleep(boolean isenable) {
        if (isenable) {
            mocksleepqueue = new arrayblockingqueue<boolean>(1);
            mocktime = new date(system.currenttimemillis());
        } else {
            mocksleepqueue = null;
        }
    }

    /** let sleeping thread pass the synchronization point.  */
    public static void passmocksleep() {
        mocksleepqueue.offer(false);
    }

    /** let the sleeping thread pass the synchronization point any number of times. */
    public static void finishmocksleep() {
        if (mocksleepqueue != null) {
            mocksleepqueue.offer(true);
        }
    }

    public static boolean isandroidruntime() {
        final string runtime = system.getproperty("java.runtime.name");
        return runtime != null && runtime.equals("android runtime");
    }

    private static class pair implements comparable<pair> {
        int item, count;
        public pair(int item, int count) { this.count = count; this.item = item; }
        @override public int compareto(pair o) { return -ints.compare(count, o.count); }
    }

    public static int maxofmostfreq(int... items) {
        // java 6 sucks.
        arraylist<integer> list = new arraylist<integer>(items.length);
        for (int item : items) list.add(item);
        return maxofmostfreq(list);
    }

    public static int maxofmostfreq(list<integer> items) {
        if (items.isempty())
            return 0;
        // this would be much easier in a functional language (or in java 8).
        items = ordering.natural().reverse().sortedcopy(items);
        linkedlist<pair> pairs = lists.newlinkedlist();
        pairs.add(new pair(items.get(0), 0));
        for (int item : items) {
            pair pair = pairs.getlast();
            if (pair.item != item)
                pairs.add((pair = new pair(item, 0)));
            pair.count++;
        }
        // pairs now contains a uniqified list of the sorted inputs, with counts for how often that item appeared.
        // now sort by how frequently they occur, and pick the max of the most frequent.
        collections.sort(pairs);
        int maxcount = pairs.getfirst().count;
        int maxitem = pairs.getfirst().item;
        for (pair pair : pairs) {
            if (pair.count != maxcount)
                break;
            maxitem = math.max(maxitem, pair.item);
        }
        return maxitem;
    }

    /**
     * reads and joins together with lf char (\n) all the lines from given file. it's assumed that file is in utf-8.
     */
    public static string getresourceasstring(url url) throws ioexception {
        list<string> lines = resources.readlines(url, charsets.utf_8);
        return joiner.on('\n').join(lines);
    }
}
