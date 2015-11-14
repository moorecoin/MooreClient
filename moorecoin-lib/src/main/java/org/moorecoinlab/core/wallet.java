package org.moorecoinlab.core;

import org.moorecoinlab.btc.bitutil;
import org.moorecoinlab.core.exception.moorecoinexception;
import org.moorecoinlab.core.hash.b58;
import org.moorecoinlab.core.hash.rfc1751;
import org.moorecoinlab.crypto.ecdsa.ikeypair;
import org.moorecoinlab.crypto.ecdsa.seed;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.random;


/**
 * wallet contains seed, accountid, keypairs
 *
 * @author fau
 */
public class wallet {
    private accountid accountid;
    private byte[] master_seed_hex; //128 bit
    private string master_seed; //equal to "rippled -q wallet_propose masterpassphrase"
    private ikeypair keypair;
    private string passphrase;
    private string master_key;

    /**
     * create a brand new wallet, random seed
     */
    public wallet() {
        random rand = new random(system.currenttimemillis());
        long l1 = rand.nextlong();
        master_seed_hex = new byte[16];
        bitutil.uint64tobytearrayle(l1, master_seed_hex, 0);
        long l2 = rand.nextlong();
        bitutil.uint64tobytearrayle(l2, master_seed_hex, 8);
        master_seed = b58.encodefamilyseed(master_seed_hex);
        keypair = seed.createkeypair(master_seed_hex);
        accountid = accountid.fromkeypair(keypair);
        master_key = rfc1751.key2english(master_seed_hex);
    }

    /**
     * create a wallet, from a special passphrase
     */
    public wallet(string passphrase) {
        passphrase = passphrase;
        master_seed_hex = seed.passphrasetoseedbytes(passphrase);
        master_seed = b58.encodefamilyseed(master_seed_hex);
        keypair = seed.createkeypair(master_seed_hex);
        accountid = accountid.fromkeypair(keypair);
        master_key = rfc1751.key2english(master_seed_hex);
    }

    public static wallet fromprivatekey(string privstr) {
        byte[] hex = seed.genseedfrombtcpriv(privstr);
        ikeypair kp = seed.createkeypair(hex);
        wallet ret = new wallet();
        ret.accountid = accountid.fromkeypair(kp);
        ret.master_seed_hex = hex;
        ret.master_seed = b58.encodefamilyseed(hex);
        ret.keypair = kp;
        ret.master_key = rfc1751.key2english(hex);
        return ret;
    }

    public static wallet fromseedstring(string seed) {
        if (seed == null || seed.length() < b58.len_family_seed - 2 || !seed.startswith("s"))
            throw new moorecoinexception("accountid.fromseedstring() param error: " + seed);
        byte[] b16 = b58.decodefamilyseed(seed);
        if (b16.length != 16) throw new moorecoinexception("decodefamilyseed() not 16 bytes: " + hex.tohexstring(b16));
        ikeypair kp = seed.createkeypair(b16);
        wallet ret = new wallet();
        ret.accountid = accountid.fromkeypair(kp);
        ret.master_seed_hex = b16;
        ret.master_seed = b58.encodefamilyseed(b16);
        ret.master_key = rfc1751.key2english(b16);
        ret.keypair = kp;
        return ret;
    }

    public accountid account() {
        return this.accountid;
    }

    public ikeypair keypair() {
        return this.keypair;
    }

    public string seed() {
        return this.master_seed;
    }

    public byte[] seedhex() {
        return this.master_seed_hex;
    }

    public string passphrase() {
        return this.passphrase;
    }

    public string getmaster_key() {
        return master_key;
    }

    @override
    public string tostring() {
        stringbuffer ret = new stringbuffer(1024);
        ret.append("account_id : ").append(accountid.address)
                .append("\tmaster_seed : ").append(master_seed)
                .append("\tmaster_seed_hex : ").append(hex.tohexstring(master_seed_hex))
                .append("\tmaster_key: ").append(master_key);
        if (keypair != null) {
            ret.append("\tpubkey=").append(keypair.pubhex())
                    .append("\tprikey=").append(keypair.privhex());
        }
        if (passphrase != null) {
            ret.append("\tpassphrase=").append(passphrase);
        }
        return ret.tostring();
    }

    public static b58 b58 = b58.getinstance();

}
