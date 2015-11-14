/**
 * copyright 2011 google inc.
 *
 * licensed under the apache license, version 2.0 (the "license");
 * you may not use this file except in compliance with the license.
 * you may obtain a copy of the license at
 *
 *    http://www.apache.org/licenses/license-2.0
 *
 * unless required by applicable law or agreed to in writing, software
 * distributed under the license is distributed on an "as is" basis,
 * without warranties or conditions of any kind, either express or implied.
 * see the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.moorecoinlab.btc;

import org.moorecoinlab.btc.account.versionedchecksummedbytes;
import org.moorecoinlab.core.exception.moorecoinexception;

import java.math.biginteger;

/**
 * parses and generates private keys in the form used by the bitcoin "dumpprivkey" command. this is the private key
 * bytes with a header byte and 4 checksum bytes at the end.
 */
public class dumpedprivatekey extends versionedchecksummedbytes {
    // used by eckey.getprivatekeyencoded()
    dumpedprivatekey(int ver, byte[] keybytes) {
        super(ver, keybytes);
        if (keybytes.length != 32)  // 256 bit keys
            throw new runtimeexception("keys are 256 bits, so you must provide 32 bytes, got " +
                    keybytes.length + " bytes");
    }

    /**
     * parses the given private key as created by the "dumpprivkey" bitcoin c++ rpc.
     *
     * @param ver  the expected network parameters of the key. if you don't care, provide null.
     * @param encoded the base58 encoded string.
     */
    public dumpedprivatekey(int ver, string encoded) throws moorecoinexception {
        super(encoded);
        if (version != ver)
            throw new moorecoinexception("mismatched version number, trying to cross networks? " + version +
                    " vs " + ver);
    }

    /**
     * returns an eckey created from this encoded private key.
     */
    public eckey getkey() {
        return new eckey(new biginteger(1, bytes));
    }
}
