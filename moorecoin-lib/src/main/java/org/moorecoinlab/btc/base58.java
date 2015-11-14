package org.moorecoinlab.btc;


import org.moorecoinlab.core.exception.moorecoinexception;

import java.io.unsupportedencodingexception;
import java.math.biginteger;
import java.util.arrays;

/**
 *
 * <p>base58 is a way to encode bitcoin addresses as numbers and letters. note that this is not the same base58 as used by
 * flickr, which you may see reference to around the internet.</p>
 *
 *
 * <p>satoshi says: why base-58 instead of standard base-64 encoding?<p>
 *
 * <ul>
 * <li>don't want 0oil characters that look the same in some fonts and
 *     could be used to create visually identical looking account numbers.</li>
 * <li>a string with non-alphanumeric characters is not as easily accepted as an account number.</li>
 * <li>e-mail usually won't line-break if there's no punctuation to break at.</li>
 * <li>doubleclicking selects the whole number as one word if it's all alphanumeric.</li>
 * </ul>
 */
public class base58 {
    public static final char[] alphabet = "123456789abcdefghjklmnpqrstuvwxyzabcdefghijkmnopqrstuvwxyz".tochararray();
    public static final int ver_address = 0;

    private static final int[] indexes = new int[128];
    static {
        for (int i = 0; i < indexes.length; i++) {
            indexes[i] = -1;
        }
        for (int i = 0; i < alphabet.length; i++) {
            indexes[alphabet[i]] = i;
        }
    }

    /** encodes the given bytes in base58. no checksum is appended. */
    public static string encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        input = copyofrange(input, 0, input.length);
        // count leading zeroes.
        int zerocount = 0;
        while (zerocount < input.length && input[zerocount] == 0) {
            ++zerocount;
        }
        // the actual encoding.
        byte[] temp = new byte[input.length * 2];
        int j = temp.length;

        int startat = zerocount;
        while (startat < input.length) {
            byte mod = divmod58(input, startat);
            if (input[startat] == 0) {
                ++startat;
            }
            temp[--j] = (byte) alphabet[mod];
        }

        // strip extra '1' if there are some after decoding.
        while (j < temp.length && temp[j] == alphabet[0]) {
            ++j;
        }
        // add as many leading '1' as there were leading zeros.
        while (--zerocount >= 0) {
            temp[--j] = (byte) alphabet[0];
        }

        byte[] output = copyofrange(temp, j, temp.length);
        try {
            return new string(output, "us-ascii");
        } catch (unsupportedencodingexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    public static byte[] decode(string input) throws moorecoinexception {
        if (input.length() == 0) {
            return new byte[0];
        }
        byte[] input58 = new byte[input.length()];
        // transform the string to a base58 byte sequence
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charat(i);

            int digit58 = -1;
            if (c >= 0 && c < 128) {
                digit58 = indexes[c];
            }
            if (digit58 < 0) {
                throw new moorecoinexception("illegal character " + c + " at " + i);
            }

            input58[i] = (byte) digit58;
        }
        // count leading zeroes
        int zerocount = 0;
        while (zerocount < input58.length && input58[zerocount] == 0) {
            ++zerocount;
        }
        // the encoding
        byte[] temp = new byte[input.length()];
        int j = temp.length;

        int startat = zerocount;
        while (startat < input58.length) {
            byte mod = divmod256(input58, startat);
            if (input58[startat] == 0) {
                ++startat;
            }

            temp[--j] = mod;
        }
        // do no add extra leading zeroes, move j to first non null byte.
        while (j < temp.length && temp[j] == 0) {
            ++j;
        }

        return copyofrange(temp, j - zerocount, temp.length);
    }

    public static biginteger decodetobiginteger(string input) throws moorecoinexception {
        return new biginteger(1, decode(input));
    }

    /**
     * uses the checksum in the last 4 bytes of the decoded data to verify the rest are correct. the checksum is
     * removed from the returned data.
     *
     * @throws org.moorecoinlab.core.exception.moorecoinexception if the input is not base 58 or the checksum does not validate.
     */
    public static byte[] decodechecked(string input) throws moorecoinexception {
        byte tmp [] = decode(input);
        if (tmp.length < 4)
            throw new moorecoinexception("input too short");
        byte[] bytes = copyofrange(tmp, 0, tmp.length - 4);
        byte[] checksum = copyofrange(tmp, tmp.length - 4, tmp.length);

        tmp = bitutil.doubledigest(bytes);
        byte[] hash = copyofrange(tmp, 0, 4);
        if (!arrays.equals(checksum, hash))
            throw new moorecoinexception("checksum does not validate");

        return bytes;
    }

    //
    // number -> number / 58, returns number % 58
    //
    private static byte divmod58(byte[] number, int startat) {
        int remainder = 0;
        for (int i = startat; i < number.length; i++) {
            int digit256 = (int) number[i] & 0xff;
            int temp = remainder * 256 + digit256;

            number[i] = (byte) (temp / 58);

            remainder = temp % 58;
        }

        return (byte) remainder;
    }

    //
    // number -> number / 256, returns number % 256
    //
    private static byte divmod256(byte[] number58, int startat) {
        int remainder = 0;
        for (int i = startat; i < number58.length; i++) {
            int digit58 = (int) number58[i] & 0xff;
            int temp = remainder * 58 + digit58;

            number58[i] = (byte) (temp / 256);

            remainder = temp % 256;
        }

        return (byte) remainder;
    }

    private static byte[] copyofrange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        system.arraycopy(source, from, range, 0, range.length);

        return range;
    }
}
