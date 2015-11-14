package org.ripple.bouncycastle.crypto.tls;

import java.io.bytearrayinputstream;
import java.io.bytearrayoutputstream;
import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;
import java.io.outputstream;
import java.util.hashtable;
import java.util.vector;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.asn1.x509.subjectpublickeyinfo;
import org.ripple.bouncycastle.asn1.x509.x509objectidentifiers;
import org.ripple.bouncycastle.crypto.digest;
import org.ripple.bouncycastle.crypto.digests.md5digest;
import org.ripple.bouncycastle.crypto.digests.sha1digest;
import org.ripple.bouncycastle.crypto.digests.sha224digest;
import org.ripple.bouncycastle.crypto.digests.sha256digest;
import org.ripple.bouncycastle.crypto.digests.sha384digest;
import org.ripple.bouncycastle.crypto.digests.sha512digest;
import org.ripple.bouncycastle.crypto.macs.hmac;
import org.ripple.bouncycastle.crypto.params.asymmetrickeyparameter;
import org.ripple.bouncycastle.crypto.params.dsapublickeyparameters;
import org.ripple.bouncycastle.crypto.params.ecpublickeyparameters;
import org.ripple.bouncycastle.crypto.params.keyparameter;
import org.ripple.bouncycastle.crypto.params.rsakeyparameters;
import org.ripple.bouncycastle.crypto.util.publickeyfactory;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.strings;
import org.ripple.bouncycastle.util.io.streams;

/**
 * some helper functions for microtls.
 */
public class tlsutils
{
    public static byte[] empty_bytes = new byte[0];

    public static final integer ext_signature_algorithms = integers.valueof(extensiontype.signature_algorithms);

    public static boolean isvaliduint8(short i)
    {
        return (i & 0xff) == i;
    }

    public static boolean isvaliduint16(int i)
    {
        return (i & 0xffff) == i;
    }

    public static boolean isvaliduint24(int i)
    {
        return (i & 0xffffff) == i;
    }

    public static boolean isvaliduint32(long i)
    {
        return (i & 0xffffffffl) == i;
    }

    public static boolean isvaliduint48(long i)
    {
        return (i & 0xffffffffffffl) == i;
    }

    public static boolean isvaliduint64(long i)
    {
        return true;
    }

    public static void writeuint8(short i, outputstream output)
        throws ioexception
    {
        output.write(i);
    }

    public static void writeuint8(short i, byte[] buf, int offset)
    {
        buf[offset] = (byte)i;
    }

    public static void writeuint16(int i, outputstream output)
        throws ioexception
    {
        output.write(i >> 8);
        output.write(i);
    }

    public static void writeuint16(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 8);
        buf[offset + 1] = (byte)i;
    }

    public static void writeuint24(int i, outputstream output)
        throws ioexception
    {
        output.write(i >> 16);
        output.write(i >> 8);
        output.write(i);
    }

    public static void writeuint24(int i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 16);
        buf[offset + 1] = (byte)(i >> 8);
        buf[offset + 2] = (byte)(i);
    }

    public static void writeuint32(long i, outputstream output)
        throws ioexception
    {
        output.write((int)(i >> 24));
        output.write((int)(i >> 16));
        output.write((int)(i >> 8));
        output.write((int)(i));
    }

    public static void writeuint32(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 24);
        buf[offset + 1] = (byte)(i >> 16);
        buf[offset + 2] = (byte)(i >> 8);
        buf[offset + 3] = (byte)(i);
    }

    public static void writeuint48(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 40);
        buf[offset + 1] = (byte)(i >> 32);
        buf[offset + 2] = (byte)(i >> 24);
        buf[offset + 3] = (byte)(i >> 16);
        buf[offset + 4] = (byte)(i >> 8);
        buf[offset + 5] = (byte)(i);
    }

    public static void writeuint64(long i, outputstream output)
        throws ioexception
    {
        output.write((int)(i >> 56));
        output.write((int)(i >> 48));
        output.write((int)(i >> 40));
        output.write((int)(i >> 32));
        output.write((int)(i >> 24));
        output.write((int)(i >> 16));
        output.write((int)(i >> 8));
        output.write((int)(i));
    }

    public static void writeuint64(long i, byte[] buf, int offset)
    {
        buf[offset] = (byte)(i >> 56);
        buf[offset + 1] = (byte)(i >> 48);
        buf[offset + 2] = (byte)(i >> 40);
        buf[offset + 3] = (byte)(i >> 32);
        buf[offset + 4] = (byte)(i >> 24);
        buf[offset + 5] = (byte)(i >> 16);
        buf[offset + 6] = (byte)(i >> 8);
        buf[offset + 7] = (byte)(i);
    }

    public static void writeopaque8(byte[] buf, outputstream output)
        throws ioexception
    {
        writeuint8((short)buf.length, output);
        output.write(buf);
    }

    public static void writeopaque16(byte[] buf, outputstream output)
        throws ioexception
    {
        writeuint16(buf.length, output);
        output.write(buf);
    }

    public static void writeopaque24(byte[] buf, outputstream output)
        throws ioexception
    {
        writeuint24(buf.length, output);
        output.write(buf);
    }

    public static void writeuint8array(short[] uints, outputstream output)
        throws ioexception
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeuint8(uints[i], output);
        }
    }

    public static void writeuint16array(int[] uints, outputstream output)
        throws ioexception
    {
        for (int i = 0; i < uints.length; ++i)
        {
            writeuint16(uints[i], output);
        }
    }

    public static short readuint8(inputstream input)
        throws ioexception
    {
        int i = input.read();
        if (i < 0)
        {
            throw new eofexception();
        }
        return (short)i;
    }

    public static short readuint8(byte[] buf, int offset)
    {
        return (short)buf[offset];
    }

    public static int readuint16(inputstream input)
        throws ioexception
    {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0)
        {
            throw new eofexception();
        }
        return i1 << 8 | i2;
    }

    public static int readuint16(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    public static int readuint24(inputstream input)
        throws ioexception
    {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        if (i3 < 0)
        {
            throw new eofexception();
        }
        return (i1 << 16) | (i2 << 8) | i3;
    }

    public static int readuint24(byte[] buf, int offset)
    {
        int n = (buf[offset] & 0xff) << 16;
        n |= (buf[++offset] & 0xff) << 8;
        n |= (buf[++offset] & 0xff);
        return n;
    }

    public static long readuint32(inputstream input)
        throws ioexception
    {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        int i4 = input.read();
        if (i4 < 0)
        {
            throw new eofexception();
        }
        return (((long)i1) << 24) | (((long)i2) << 16) | (((long)i3) << 8) | ((long)i4);
    }

    public static long readuint48(inputstream input)
        throws ioexception
    {
        int i1 = input.read();
        int i2 = input.read();
        int i3 = input.read();
        int i4 = input.read();
        int i5 = input.read();
        int i6 = input.read();
        if (i6 < 0)
        {
            throw new eofexception();
        }
        return (((long)i1) << 40) | (((long)i2) << 32) | (((long)i3) << 24) | (((long)i4) << 16) | (((long)i5) << 8) | ((long)i6);
    }

    public static long readuint48(byte[] buf, int offset)
    {
        int hi = readuint24(buf, offset);
        int lo = readuint24(buf, offset + 3);
        return ((long)(hi & 0xffffffffl) << 24) | (long)(lo & 0xffffffffl);
    }

    public static byte[] readfully(int length, inputstream input)
        throws ioexception
    {
        if (length < 1)
        {
            return empty_bytes;
        }
        byte[] buf = new byte[length];
        if (length != streams.readfully(input, buf))
        {
            throw new eofexception();
        }
        return buf;
    }

    public static void readfully(byte[] buf, inputstream input)
        throws ioexception
    {
        int length = buf.length;
        if (length > 0 && length != streams.readfully(input, buf))
        {
            throw new eofexception();
        }
    }

    public static byte[] readopaque8(inputstream input)
        throws ioexception
    {
        short length = readuint8(input);
        return readfully(length, input);
    }

    public static byte[] readopaque16(inputstream input)
        throws ioexception
    {
        int length = readuint16(input);
        return readfully(length, input);
    }

    public static byte[] readopaque24(inputstream input)
        throws ioexception
    {
        int length = readuint24(input);
        return readfully(length, input);
    }

    public static short[] readuint8array(int count, inputstream input)
        throws ioexception
    {
        short[] uints = new short[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readuint8(input);
        }
        return uints;
    }

    public static int[] readuint16array(int count, inputstream input)
        throws ioexception
    {
        int[] uints = new int[count];
        for (int i = 0; i < count; ++i)
        {
            uints[i] = readuint16(input);
        }
        return uints;
    }

    public static protocolversion readversion(byte[] buf, int offset)
        throws ioexception
    {
        return protocolversion.get(buf[offset] & 0xff, buf[offset + 1] & 0xff);
    }

    public static protocolversion readversion(inputstream input)
        throws ioexception
    {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0)
        {
            throw new eofexception();
        }
        return protocolversion.get(i1, i2);
    }

    public static int readversionraw(inputstream input)
        throws ioexception
    {
        int i1 = input.read();
        int i2 = input.read();
        if (i2 < 0)
        {
            throw new eofexception();
        }
        return (i1 << 8) | i2;
    }

    public static void writegmtunixtime(byte[] buf, int offset)
    {
        int t = (int)(system.currenttimemillis() / 1000l);
        buf[offset] = (byte)(t >> 24);
        buf[offset + 1] = (byte)(t >> 16);
        buf[offset + 2] = (byte)(t >> 8);
        buf[offset + 3] = (byte)t;
    }

    public static void writeversion(protocolversion version, outputstream output)
        throws ioexception
    {
        output.write(version.getmajorversion());
        output.write(version.getminorversion());
    }

    public static void writeversion(protocolversion version, byte[] buf, int offset)
        throws ioexception
    {
        buf[offset] = (byte)version.getmajorversion();
        buf[offset + 1] = (byte)version.getminorversion();
    }

    public static vector getdefaultdsssignaturealgorithms()
    {
        return vectorofone(new signatureandhashalgorithm(hashalgorithm.sha1, signaturealgorithm.dsa));
    }

    public static vector getdefaultecdsasignaturealgorithms()
    {
        return vectorofone(new signatureandhashalgorithm(hashalgorithm.sha1, signaturealgorithm.ecdsa));
    }

    public static vector getdefaultrsasignaturealgorithms()
    {
        return vectorofone(new signatureandhashalgorithm(hashalgorithm.sha1, signaturealgorithm.rsa));
    }

    public static boolean issignaturealgorithmsextensionallowed(protocolversion clientversion)
    {
        return protocolversion.tlsv12.isequalorearlierversionof(clientversion.getequivalenttlsversion());
    }

    /**
     * add a 'signature_algorithms' extension to existing extensions.
     *
     * @param extensions                   a {@link hashtable} to add the extension to.
     * @param supportedsignaturealgorithms {@link vector} containing at least 1 {@link signatureandhashalgorithm}.
     * @throws ioexception
     */
    public static void addsignaturealgorithmsextension(hashtable extensions, vector supportedsignaturealgorithms)
        throws ioexception
    {
        extensions.put(ext_signature_algorithms, createsignaturealgorithmsextension(supportedsignaturealgorithms));
    }

    /**
     * get a 'signature_algorithms' extension from extensions.
     *
     * @param extensions a {@link hashtable} to get the extension from, if it is present.
     * @return a {@link vector} containing at least 1 {@link signatureandhashalgorithm}, or null.
     * @throws ioexception
     */
    public static vector getsignaturealgorithmsextension(hashtable extensions)
        throws ioexception
    {

        if (extensions == null)
        {
            return null;
        }
        byte[] extensionvalue = (byte[])extensions.get(ext_signature_algorithms);
        if (extensionvalue == null)
        {
            return null;
        }
        return readsignaturealgorithmsextension(extensionvalue);
    }

    /**
     * create a 'signature_algorithms' extension value.
     *
     * @param supportedsignaturealgorithms a {@link vector} containing at least 1 {@link signatureandhashalgorithm}.
     * @return a byte array suitable for use as an extension value.
     * @throws ioexception
     */
    public static byte[] createsignaturealgorithmsextension(vector supportedsignaturealgorithms)
        throws ioexception
    {

        if (supportedsignaturealgorithms == null || supportedsignaturealgorithms.size() < 1 || supportedsignaturealgorithms.size() >= (1 << 15))
        {
            throw new illegalargumentexception(
                "'supportedsignaturealgorithms' must have length from 1 to (2^15 - 1)");
        }

        bytearrayoutputstream buf = new bytearrayoutputstream();

        // supported_signature_algorithms
        tlsutils.writeuint16(2 * supportedsignaturealgorithms.size(), buf);
        for (int i = 0; i < supportedsignaturealgorithms.size(); ++i)
        {
            signatureandhashalgorithm entry = (signatureandhashalgorithm)supportedsignaturealgorithms.elementat(i);
            entry.encode(buf);
        }

        return buf.tobytearray();
    }

    /**
     * read a 'signature_algorithms' extension value.
     *
     * @param extensionvalue the extension value.
     * @return a {@link vector} containing at least 1 {@link signatureandhashalgorithm}.
     * @throws ioexception
     */
    public static vector readsignaturealgorithmsextension(byte[] extensionvalue)
        throws ioexception
    {

        if (extensionvalue == null)
        {
            throw new illegalargumentexception("'extensionvalue' cannot be null");
        }

        bytearrayinputstream buf = new bytearrayinputstream(extensionvalue);

        // supported_signature_algorithms
        int length = tlsutils.readuint16(buf);
        if (length < 2 || (length & 1) != 0)
        {
            throw new tlsfatalalert(alertdescription.decode_error);
        }
        int count = length / 2;
        vector result = new vector(count);
        for (int i = 0; i < count; ++i)
        {
            signatureandhashalgorithm entry = signatureandhashalgorithm.parse(buf);
            result.addelement(entry);
        }

        tlsprotocol.assertempty(buf);

        return result;
    }

    public static byte[] prf(tlscontext context, byte[] secret, string asciilabel, byte[] seed, int size)
    {
        protocolversion version = context.getserverversion();

        if (version.isssl())
        {
            throw new illegalstateexception("no prf available for sslv3 session");
        }

        byte[] label = strings.tobytearray(asciilabel);
        byte[] labelseed = concat(label, seed);

        int prfalgorithm = context.getsecurityparameters().getprfalgorithm();

        if (prfalgorithm == prfalgorithm.tls_prf_legacy)
        {
            if (!protocolversion.tlsv12.isequalorearlierversionof(version.getequivalenttlsversion()))
            {
                return prf_legacy(secret, label, labelseed, size);
            }

            prfalgorithm = prfalgorithm.tls_prf_sha256;
        }

        digest prfdigest = createprfhash(prfalgorithm);
        byte[] buf = new byte[size];
        hmac_hash(prfdigest, secret, labelseed, buf);
        return buf;
    }

    static byte[] prf_legacy(byte[] secret, byte[] label, byte[] labelseed, int size)
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        system.arraycopy(secret, 0, s1, 0, s_half);
        system.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[size];
        byte[] b2 = new byte[size];
        hmac_hash(new md5digest(), s1, labelseed, b1);
        hmac_hash(new sha1digest(), s2, labelseed, b2);
        for (int i = 0; i < size; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }

    static byte[] concat(byte[] a, byte[] b)
    {
        byte[] c = new byte[a.length + b.length];
        system.arraycopy(a, 0, c, 0, a.length);
        system.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    static void hmac_hash(digest digest, byte[] secret, byte[] seed, byte[] out)
    {
        hmac mac = new hmac(digest);
        keyparameter param = new keyparameter(secret);
        byte[] a = seed;
        int size = digest.getdigestsize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getmacsize()];
        byte[] buf2 = new byte[mac.getmacsize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.dofinal(buf, 0);
            a = buf;
            mac.init(param);
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.dofinal(buf2, 0);
            system.arraycopy(buf2, 0, out, (size * i), math.min(size, out.length - (size * i)));
        }
    }

    static void validatekeyusage(org.ripple.bouncycastle.asn1.x509.certificate c, int keyusagebits)
        throws ioexception
    {
        extensions exts = c.gettbscertificate().getextensions();
        if (exts != null)
        {
            keyusage ku = keyusage.fromextensions(exts);
            if (ku != null)
            {
                int bits = ku.getbytes()[0] & 0xff;
                if ((bits & keyusagebits) != keyusagebits)
                {
                    throw new tlsfatalalert(alertdescription.certificate_unknown);
                }
            }
        }
    }

    static byte[] calculatekeyblock(tlscontext context, int size)
    {
        securityparameters securityparameters = context.getsecurityparameters();
        byte[] master_secret = securityparameters.getmastersecret();
        byte[] seed = concat(securityparameters.getserverrandom(),
            securityparameters.getclientrandom());

        if (context.getserverversion().isssl())
        {
            return calculatekeyblock_ssl(master_secret, seed, size);
        }

        return prf(context, master_secret, exporterlabel.key_expansion, seed, size);
    }

    static byte[] calculatekeyblock_ssl(byte[] master_secret, byte[] random, int size)
    {
        digest md5 = new md5digest();
        digest sha1 = new sha1digest();
        int md5size = md5.getdigestsize();
        byte[] shatmp = new byte[sha1.getdigestsize()];
        byte[] tmp = new byte[size + md5size];

        int i = 0, pos = 0;
        while (pos < size)
        {
            byte[] ssl3const = ssl3_const[i];

            sha1.update(ssl3const, 0, ssl3const.length);
            sha1.update(master_secret, 0, master_secret.length);
            sha1.update(random, 0, random.length);
            sha1.dofinal(shatmp, 0);

            md5.update(master_secret, 0, master_secret.length);
            md5.update(shatmp, 0, shatmp.length);
            md5.dofinal(tmp, pos);

            pos += md5size;
            ++i;
        }

        byte rval[] = new byte[size];
        system.arraycopy(tmp, 0, rval, 0, size);
        return rval;
    }

    static byte[] calculatemastersecret(tlscontext context, byte[] pre_master_secret)
    {
        securityparameters securityparameters = context.getsecurityparameters();
        byte[] seed = concat(securityparameters.getclientrandom(), securityparameters.getserverrandom());

        if (context.getserverversion().isssl())
        {
            return calculatemastersecret_ssl(pre_master_secret, seed);
        }

        return prf(context, pre_master_secret, exporterlabel.master_secret, seed, 48);
    }

    static byte[] calculatemastersecret_ssl(byte[] pre_master_secret, byte[] random)
    {
        digest md5 = new md5digest();
        digest sha1 = new sha1digest();
        int md5size = md5.getdigestsize();
        byte[] shatmp = new byte[sha1.getdigestsize()];

        byte[] rval = new byte[md5size * 3];
        int pos = 0;

        for (int i = 0; i < 3; ++i)
        {
            byte[] ssl3const = ssl3_const[i];

            sha1.update(ssl3const, 0, ssl3const.length);
            sha1.update(pre_master_secret, 0, pre_master_secret.length);
            sha1.update(random, 0, random.length);
            sha1.dofinal(shatmp, 0);

            md5.update(pre_master_secret, 0, pre_master_secret.length);
            md5.update(shatmp, 0, shatmp.length);
            md5.dofinal(rval, pos);

            pos += md5size;
        }

        return rval;
    }

    static byte[] calculateverifydata(tlscontext context, string asciilabel, byte[] handshakehash)
    {
        if (context.getserverversion().isssl())
        {
            return handshakehash;
        }

        securityparameters securityparameters = context.getsecurityparameters();
        byte[] master_secret = securityparameters.getmastersecret();
        int verify_data_length = securityparameters.getverifydatalength();

        return prf(context, master_secret, asciilabel, handshakehash, verify_data_length);
    }

    public static final digest createhash(int hashalgorithm)
    {
        switch (hashalgorithm)
        {
        case hashalgorithm.md5:
            return new md5digest();
        case hashalgorithm.sha1:
            return new sha1digest();
        case hashalgorithm.sha224:
            return new sha224digest();
        case hashalgorithm.sha256:
            return new sha256digest();
        case hashalgorithm.sha384:
            return new sha384digest();
        case hashalgorithm.sha512:
            return new sha512digest();
        default:
            throw new illegalargumentexception("unknown hashalgorithm");
        }
    }

    public static final digest clonehash(int hashalgorithm, digest hash)
    {
        switch (hashalgorithm)
        {
        case hashalgorithm.md5:
            return new md5digest((md5digest)hash);
        case hashalgorithm.sha1:
            return new sha1digest((sha1digest)hash);
        case hashalgorithm.sha224:
            return new sha224digest((sha224digest)hash);
        case hashalgorithm.sha256:
            return new sha256digest((sha256digest)hash);
        case hashalgorithm.sha384:
            return new sha384digest((sha384digest)hash);
        case hashalgorithm.sha512:
            return new sha512digest((sha512digest)hash);
        default:
            throw new illegalargumentexception("unknown hashalgorithm");
        }
    }

    public static final digest createprfhash(int prfalgorithm)
    {
        switch (prfalgorithm)
        {
        case prfalgorithm.tls_prf_legacy:
            return new combinedhash();
        default:
            return createhash(gethashalgorithmforprfalgorithm(prfalgorithm));
        }
    }

    public static final digest cloneprfhash(int prfalgorithm, digest hash)
    {
        switch (prfalgorithm)
        {
        case prfalgorithm.tls_prf_legacy:
            return new combinedhash((combinedhash)hash);
        default:
            return clonehash(gethashalgorithmforprfalgorithm(prfalgorithm), hash);
        }
    }

    public static final short gethashalgorithmforprfalgorithm(int prfalgorithm)
    {
        switch (prfalgorithm)
        {
        case prfalgorithm.tls_prf_legacy:
            throw new illegalargumentexception("legacy prf not a valid algorithm");
        case prfalgorithm.tls_prf_sha256:
            return hashalgorithm.sha256;
        case prfalgorithm.tls_prf_sha384:
            return hashalgorithm.sha384;
        default:
            throw new illegalargumentexception("unknown prfalgorithm");
        }
    }

    public static asn1objectidentifier getoidforhashalgorithm(int hashalgorithm)
    {
        switch (hashalgorithm)
        {
        case hashalgorithm.md5:
            return pkcsobjectidentifiers.md5;
        case hashalgorithm.sha1:
            return x509objectidentifiers.id_sha1;
        case hashalgorithm.sha224:
            return nistobjectidentifiers.id_sha224;
        case hashalgorithm.sha256:
            return nistobjectidentifiers.id_sha256;
        case hashalgorithm.sha384:
            return nistobjectidentifiers.id_sha384;
        case hashalgorithm.sha512:
            return nistobjectidentifiers.id_sha512;
        default:
            throw new illegalargumentexception("unknown hashalgorithm");
        }
    }

    static short getclientcertificatetype(certificate clientcertificate, certificate servercertificate)
        throws ioexception
    {
        if (clientcertificate.isempty())
        {
            return -1;
        }

        org.ripple.bouncycastle.asn1.x509.certificate x509cert = clientcertificate.getcertificateat(0);
        subjectpublickeyinfo keyinfo = x509cert.getsubjectpublickeyinfo();
        try
        {
            asymmetrickeyparameter publickey = publickeyfactory.createkey(keyinfo);
            if (publickey.isprivate())
            {
                throw new tlsfatalalert(alertdescription.internal_error);
            }

            /*
             * todo rfc 5246 7.4.6. the certificates must be signed using an acceptable hash/
             * signature algorithm pair, as described in section 7.4.4. note that this relaxes the
             * constraints on certificate-signing algorithms found in prior versions of tls.
             */

            /*
             * rfc 5246 7.4.6. client certificate
             */

            /*
             * rsa public key; the certificate must allow the key to be used for signing with the
             * signature scheme and hash algorithm that will be employed in the certificate verify
             * message.
             */
            if (publickey instanceof rsakeyparameters)
            {
                validatekeyusage(x509cert, keyusage.digitalsignature);
                return clientcertificatetype.rsa_sign;
            }

            /*
             * dsa public key; the certificate must allow the key to be used for signing with the
             * hash algorithm that will be employed in the certificate verify message.
             */
            if (publickey instanceof dsapublickeyparameters)
            {
                validatekeyusage(x509cert, keyusage.digitalsignature);
                return clientcertificatetype.dss_sign;
            }

            /*
             * ecdsa-capable public key; the certificate must allow the key to be used for signing
             * with the hash algorithm that will be employed in the certificate verify message; the
             * public key must use a curve and point format supported by the server.
             */
            if (publickey instanceof ecpublickeyparameters)
            {
                validatekeyusage(x509cert, keyusage.digitalsignature);
                // todo check the curve and point format
                return clientcertificatetype.ecdsa_sign;
            }

            // todo add support for clientcertificatetype.*_fixed_*

        }
        catch (exception e)
        {
        }

        throw new tlsfatalalert(alertdescription.unsupported_certificate);
    }

    public static boolean hassigningcapability(short clientcertificatetype)
    {
        switch (clientcertificatetype)
        {
        case clientcertificatetype.dss_sign:
        case clientcertificatetype.ecdsa_sign:
        case clientcertificatetype.rsa_sign:
            return true;
        default:
            return false;
        }
    }

    public static tlssigner createtlssigner(short clientcertificatetype)
    {
        switch (clientcertificatetype)
        {
        case clientcertificatetype.dss_sign:
            return new tlsdsssigner();
        case clientcertificatetype.ecdsa_sign:
            return new tlsecdsasigner();
        case clientcertificatetype.rsa_sign:
            return new tlsrsasigner();
        default:
            throw new illegalargumentexception("'clientcertificatetype' is not a type with signing capability");
        }
    }

    static final byte[] ssl_client = {0x43, 0x4c, 0x4e, 0x54};
    static final byte[] ssl_server = {0x53, 0x52, 0x56, 0x52};

    // ssl3 magic mix constants ("a", "bb", "ccc", ...)
    static final byte[][] ssl3_const = genconst();

    private static byte[][] genconst()
    {
        int n = 10;
        byte[][] arr = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            byte[] b = new byte[i + 1];
            arrays.fill(b, (byte)('a' + i));
            arr[i] = b;
        }
        return arr;
    }

    private static vector vectorofone(object obj)
    {
        vector v = new vector(1);
        v.addelement(obj);
        return v;
    }
}
