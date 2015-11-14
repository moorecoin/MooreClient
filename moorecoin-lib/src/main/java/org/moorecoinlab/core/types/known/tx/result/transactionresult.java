package org.moorecoinlab.core.types.known.tx.result;


import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.starray;
import org.moorecoinlab.core.stobject;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.index;
import org.moorecoinlab.core.serialized.enums.engineresult;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.serialized.enums.transactiontype;
import org.moorecoinlab.core.types.known.tx.transaction;
import org.moorecoinlab.core.uint.uint32;
import org.json.jsonexception;
import org.json.jsonobject;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.hashmap;
import java.util.map;

public class transactionresult implements comparable<transactionresult>{
    // the json formatting of transaction results is a mess
    public enum source {
        request_tx_result,
        request_account_tx,
        request_account_tx_binary,
        request_tx_binary,
        ledger_transactions_expanded_with_ledger_index_injected,
        transaction_subscription_notification
    }

    public engineresult engineresult;
    public uint32 ledgerindex;
    public hash256 hash;

    // todo, consider just killing this field, as not all have them
    public hash256 ledgerhash;
    // todo, in practice this class is only for validated results so ...
    public boolean validated;

    public transactionresult(long ledgerindex, hash256 hash, transaction txn, transactionmeta meta) {
        this.ledgerindex = new uint32(ledgerindex);
        this.hash = hash;
        this.txn = txn;
        this.meta = meta;
        this.engineresult = meta.engineresult();
        this.validated = true;
    }

    public transaction txn;
    public transactionmeta meta;
    public jsonobject message;

    public boolean ispayment() {
        return transactiontype() == transactiontype.payment;
    }

    public transactiontype transactiontype() {
        return txn.transactiontype();
    }

    public accountid createdaccount() {
        accountid destination    =  null;
        hash256   destinationindex =  null;

        if (transactiontype() == transactiontype.payment && meta.has(field.affectednodes)) {
            starray affected = meta.get(starray.affectednodes);
            for (stobject node : affected) {
                if (node.has(stobject.creatednode)) {
                    stobject created = node.get(stobject.creatednode);
                    if (stobject.ledgerentrytype(created) == ledgerentrytype.accountroot) {
                        if (destination == null) {
                            destination = txn.get(accountid.destination);
                            destinationindex = index.accountroot(destination);
                        }
                        if (destinationindex.equals(created.get(hash256.ledgerindex))) {
                            return destination;
                        }
                    }
                }
            }
        }
        return null;
    }

    public map<accountid, stobject> modifiedroots() {
        hashmap<accountid, stobject> accounts = null;

        if (meta.has(field.affectednodes)) {
            accounts = new hashmap<accountid, stobject>();
            starray affected = meta.get(starray.affectednodes);
            for (stobject node : affected) {
                if (node.has(field.modifiednode)) {
                    node = node.get(stobject.modifiednode);
                    if (stobject.ledgerentrytype(node) == ledgerentrytype.accountroot) {
                        stobject finalfields = node.get(stobject.finalfields);
                        accountid key;

                        if (finalfields != null) {
                            key = finalfields.get(accountid.account);
                            accounts.put(key, node);
                        }
                    }
                }
            }
        }
        return accounts;
    }

    public accountid initiatingaccount() {
        return txn.get(accountid.account);
    }

    public int compareto(transactionresult o2) {
        transactionresult o1 = this;
        int i = o1.ledgerindex.subtract(o2.ledgerindex).intvalue();
        if (i != 0) {
            return i;
        } else {
            uint32 o1_tix = o1.meta.transactionindex();
            uint32 o2_tix = o2.meta.transactionindex();
            return o1_tix.subtract(o2_tix).intvalue();
        }
    }

    public static transactionresult fromjson(jsonobject json) {
        boolean binary;

        string metakey = json.has("meta") ? "meta" : "metadata";

        string txkey = json.has("transaction") ? "transaction" :
                       json.has("tx") ? "tx" :
                       json.has("tx_blob") ? "tx_blob" : null;

        if (txkey == null && !json.has("transactiontype")) {
            throw new runtimeexception("this json isn't a transaction " + json);
        }

        try {
            binary = txkey != null && json.get(txkey) instanceof string;

            transaction txn;
            if (txkey == null) {
                // this should parse the `hash` field
                txn = (transaction) stobject.fromjsonobject(json);
            } else {
                txn = (transaction) parseobject(json, txkey, binary);
                if (json.has("hash")) {
                    txn.put(hash256.hash, hash256.fromhex(json.getstring("hash")));
                } else if (binary) {
                    byte[] decode = hex.decode(json.getstring(txkey));
                    txn.put(hash256.hash, index.transactionid(decode));
                }
            }

            transactionmeta meta = (transactionmeta) parseobject(json, metakey, binary);
            long ledger_index = json.optlong("ledger_index", 0);
            if (ledger_index == 0 && !binary) {
                ledger_index = json.getjsonobject(txkey).getlong("ledger_index");
            }

            transactionresult tr = new transactionresult(ledger_index, txn.get(hash256.hash), txn, meta);
            if (json.has("ledger_hash")) {
                tr.ledgerhash = hash256.fromhex(json.getstring("ledger_hash"));
            }
            return tr;

        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
    }

    private static stobject parseobject(jsonobject json, string key, boolean binary) throws jsonexception {
        if (binary) {
            return stobject.translate.fromhex(json.getstring(key));
        } else {
            jsonobject tx_json = json.getjsonobject(key);
            return stobject.translate.fromjsonobject(tx_json);
        }
    }

    public transactionresult(jsonobject json, source resultmessagesource) {
        message = json;

        try {
            if (resultmessagesource == source.transaction_subscription_notification) {

                engineresult = engineresult.valueof(json.getstring("engine_result"));
                validated = json.getboolean("validated");
                ledgerhash = hash256.translate.fromstring(json.getstring("ledger_hash"));
                ledgerindex = new uint32(json.getlong("ledger_index"));

                if (json.has("transaction")) {
                    txn = (transaction) stobject.fromjsonobject(json.getjsonobject("transaction"));
                    hash = txn.get(hash256.hash);
                }

                if (json.has("meta")) {
                    meta = (transactionmeta) stobject.fromjsonobject(json.getjsonobject("meta"));
                }
            }
            else if (resultmessagesource == source.ledger_transactions_expanded_with_ledger_index_injected) {
                validated = true;
                meta = (transactionmeta) stobject.translate.fromjsonobject(json.getjsonobject("metadata"));
                txn = (transaction) stobject.translate.fromjsonobject(json);
                hash = txn.get(hash256.hash);
                engineresult = meta.engineresult();
                ledgerindex = new uint32(json.getlong("ledger_index"));
                ledgerhash = null;

            } else if (resultmessagesource == source.request_tx_result) {
                validated = json.optboolean("validated", false);
                if (validated && !json.has("meta")) {
                    throw new illegalstateexception("it's validated, why doesn't it have meta??");
                }
                if (validated) {
                    meta = (transactionmeta) stobject.fromjsonobject(json.getjsonobject("meta"));
                    engineresult = meta.engineresult();
                    txn = (transaction) stobject.fromjsonobject(json);
                    hash = txn.get(hash256.hash);
                    ledgerhash = null; // xxxxxx
                    ledgerindex = new uint32(json.getlong("ledger_index"));

                }
            } else if (resultmessagesource == source.request_account_tx) {
                validated = json.optboolean("validated", false);
                if (validated && !json.has("meta")) {
                    throw new illegalstateexception("it's validated, why doesn't it have meta??");
                }
                if (validated) {
                    jsonobject tx = json.getjsonobject("tx");
                    meta = (transactionmeta) stobject.fromjsonobject(json.getjsonobject("meta"));
                    engineresult = meta.engineresult();
                    this.txn = (transaction) stobject.fromjsonobject(tx);
                    hash = this.txn.get(hash256.hash);
                    ledgerindex = new uint32(tx.getlong("ledger_index"));
                    ledgerhash = null;
                }
            } else if (resultmessagesource == source.request_account_tx_binary || resultmessagesource == source.request_tx_binary) {
                validated = json.optboolean("validated", false);
                if (validated && !json.has("meta")) {
                    throw new illegalstateexception("it's validated, why doesn't it have meta??");
                }
                if (validated) {
                    /*
                    {
                      "ledger_index": 3378767,
                      "meta": "201 ...",
                      "tx_blob": "120 ...",
                      "validated": true
                    },
                    */
                    boolean account_tx = resultmessagesource == source.request_account_tx_binary;

                    string tx = json.getstring(account_tx ? "tx_blob" : "tx");
                    byte[] decodedtx = hex.decode(tx);
                    meta = (transactionmeta) stobject.translate.fromhex(json.getstring("meta"));
                    this.txn = (transaction) stobject.translate.frombytes(decodedtx);

                    if (account_tx) {
                        hash = index.transactionid(decodedtx);
                    } else {
                        hash = hash256.translate.fromhex(json.getstring("hash"));
                    }
                    this.txn.put(field.hash, hash);

                    engineresult = meta.engineresult();
                    ledgerindex = new uint32(json.getlong("ledger_index"));
                    ledgerhash = null;
                }
            }

        } catch (jsonexception e) {
            throw new runtimeexception(e);
        }
    }
}
