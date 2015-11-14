package org.moorecoinlab.core.hash;

import org.moorecoinlab.core.utils;
import org.moorecoinlab.core.exception.moorecoinexception;

import java.io.unsupportedencodingexception;
import java.math.biginteger;
import java.util.arrays;


public class b58 {
    public static final int ver_account_id        = 0;
    public static final int ver_family_seed       = 33;
    public static final int ver_none              = 1;
    public static final int ver_node_public       = 28;
    public static final int ver_node_private      = 32;
    public static final int ver_account_public    = 35;
    public static final int ver_account_private   = 34;
    public static final int ver_family_generator  = 41;

    public static final int len_address           = 34;
    public static final int len_family_seed       = 29;
    public static final int len_family_seed_hex   = 16;
    public static final int len_private_key       = 32;
    public static final int len_public_key        = 33;

    public static final string default_alphabet = "rpshnaf39wbudneghjklm4pqrst7vwxyz2bcdecg65jkm8ofqi1tuvaxyz";


    private static final b58 instance = new b58();
    private int[] mindexes;
    private char[] malphabet;


    public static b58 getinstance() {
        return instance;
    }

    public b58() {
        setalphabet(default_alphabet);
        buildindexes();
    }

    private void setalphabet(string alphabet) {
        malphabet = alphabet.tochararray();
    }

    private void buildindexes() {
        mindexes = new int[128];

        for (int i = 0; i < mindexes.length; i++) {
            mindexes[i] = -1;
        }
        for (int i = 0; i < malphabet.length; i++) {
            mindexes[malphabet[i]] = i;
        }
    }

    public string encodetostringchecked(byte[] input, int version) {
        try {
            return new string(encodetobyteschecked(input, version), "us-ascii");
        } catch (unsupportedencodingexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    public byte[] encodetobyteschecked(byte[] input, int version) {
        byte[] buffer = new byte[input.length + 1];
        buffer[0] = (byte) version;
        system.arraycopy(input, 0, buffer, 1, input.length);
        byte[] checksum = copyofrange(utils.doubledigest(buffer), 0, 4);
        byte[] output = new byte[buffer.length + checksum.length];
        system.arraycopy(buffer, 0, output, 0, buffer.length);
        system.arraycopy(checksum, 0, output, buffer.length, checksum.length);
        return encodetobytes(output);
    }

    public string encodetostring(byte[] input) {
        byte[] output = encodetobytes(input);
        try {
            return new string(output, "us-ascii");
        } catch (unsupportedencodingexception e) {
            throw new runtimeexception(e);  // cannot happen.
        }
    }

    /**
     * encodes the given bytes in base58. no checksum is appended.
     */
    public byte[] encodetobytes(byte[] input) {
        if (input.length == 0) {
            return new byte[0];
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
            temp[--j] = (byte) malphabet[mod];
        }

        // strip extra '1' if there are some after decoding.
        while (j < temp.length && temp[j] == malphabet[0]) {
            ++j;
        }
        // add as many leading '1' as there were leading zeros.
        while (--zerocount >= 0) {
            temp[--j] = (byte) malphabet[0];
        }

        byte[] output;
        output = copyofrange(temp, j, temp.length);
        return output;
    }

    public byte[] decode(string input) throws moorecoinexception {
        if (input.length() == 0) {
            return new byte[0];
        }
        byte[] input58 = new byte[input.length()];
        // transform the string to a base58 byte sequence
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charat(i);

            int digit58 = -1;
            if (c >= 0 && c < 128) {
                digit58 = mindexes[c];
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

    public biginteger decodetobiginteger(string input) throws moorecoinexception {
        return new biginteger(1, decode(input));

    }

    /**
     * uses the checksum in the last 4 bytes of the decoded data to verify the rest are correct. the checksum is
     * removed from the returned data.
     *
     * @throws org.moorecoinlab.core.exception.moorecoinexception if the input is not basefields 58 or the checksum does not validate.
     */
    public byte[] decodechecked(string input, int version) throws moorecoinexception {
        byte buffer[] = decode(input);
        if (buffer.length < 4)
            throw new moorecoinexception("input too short");
        byte actualversion = buffer[0];
        if (actualversion != version) {
            throw new moorecoinexception("bro, version is wrong yo:" + input + " ver=" + actualversion + " need=" + version);
        }

        byte[] tohash = copyofrange(buffer, 0, buffer.length - 4);
        byte[] hashed = copyofrange(utils.doubledigest(tohash), 0, 4);
        byte[] checksum = copyofrange(buffer, buffer.length - 4, buffer.length);

        if (!arrays.equals(checksum, hashed))
            throw new moorecoinexception("checksum does not validate");

        return copyofrange(buffer, 1, buffer.length - 4);
    }


    /** family seed */
    public byte[] decodefamilyseed(string seed) throws moorecoinexception {
        return decodechecked(seed, ver_family_seed);
    }

    public string encodefamilyseed(byte[] bytes) {
        return encodetostringchecked(bytes, ver_family_seed);
    }

    /** addrress */
    public byte[] decodeaddress(string address) throws moorecoinexception {
        return decodechecked(address, ver_account_id);
    }

    public string encodeaddress(byte[] bytes) {
        return encodetostringchecked(bytes, ver_account_id);
    }

    /** node public (by fau) */
    public byte[] decodenodepublic(string np) throws moorecoinexception {
        return decodechecked(np, ver_node_public);
    }

    public string encodenodepublic(byte[] bytes) {
        return encodetostringchecked(bytes, ver_node_public);
    }

    /** account public (by fau) */
    public byte[] decodeaccountpublic(string ap) throws moorecoinexception {
        return decodechecked(ap, ver_account_public);
    }

    public string encodeaccountpublic(byte[] bytes) {
        return encodetostringchecked(bytes, ver_account_public);
    }


    //--------------------------  private section   --------------------------
    //
    // number -> number / 58, returns number % 58
    //
    private byte divmod58(byte[] number, int startat) {
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
    private byte divmod256(byte[] number58, int startat) {
        int remainder = 0;
        for (int i = startat; i < number58.length; i++) {
            int digit58 = (int) number58[i] & 0xff;
            int temp = remainder * 58 + digit58;

            number58[i] = (byte) (temp / 256);

            remainder = temp % 256;
        }

        return (byte) remainder;
    }

    private byte[] copyofrange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        system.arraycopy(source, from, range, 0, range.length);

        return range;
    }
}
