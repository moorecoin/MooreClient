package org.moorecoinlab.core.types.known.sle.entries;


import org.moorecoinlab.core.*;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.index;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;
import org.moorecoinlab.core.types.known.sle.threadedledgerentry;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.core.uint.uint64;

import java.math.bigdecimal;
import java.util.collection;
import java.util.comparator;
import java.util.iterator;

public class offer extends threadedledgerentry {
    public offer() {
        super(ledgerentrytype.offer);
    }

    /**
     * use the bookdirectory field
     *
     * @return how much must `pay` to `get` one.
     *
     */
    public bigdecimal directoryaskquality() {
        return quality.frombookdirectory(bookdirectory(),
                takerpays().isnative(),
                takergets().isnative());
    }

    /**
     * @return how much must `pay` to `get` one.
     */
    public bigdecimal askquality() {
        return takerpays().computequality(takergets());
    }

    /**
     * @return how much `get` if `pay` one.
     */
    public bigdecimal bidquality() {
        return takergets().computequality(takerpays());
    }

    /**
     *
     * @return one of takergets issue, eg 1/usd/bitstamp or 1/eur/snapswap
     */
    public amount getsone() {
        return takergets().one();
    }
    /**
     *
     * @return one of takerpays issue, eg 1/usd/bitstamp or 1/eur/snapswap
     */
    public amount paysone() {
        return takerpays().one();
    }

    public string getpaycurrencypair() {
        return takergets().currencystring() + "/" +
               takerpays().currencystring();
    }

    public stobject executed(stobject finalfields) {
        // where `this` is an affectednode nodeasprevious
        stobject executed = new stobject();
        executed.put(amount.takerpays, finalfields.get(amount.takerpays).subtract(takerpays()));
        executed.put(amount.takergets, finalfields.get(amount.takergets).subtract(takergets()));
        return executed;
    }

    private hash256 lineindex(amount amt) {
        issue issue = amt.issue();
        if (amt.isnative()) throw new assertionerror();
        return index.ripplestate(account(), issue.issuer(), issue.currency());
    }

    public vector256 lineindexes() {
        vector256 ret = new vector256();
        for (amount amt : new amount[]{takergets(), takerpays()}) {
            if (!amt.isnative()){
                ret.add(lineindex(amt));
            }
        }
        return ret;
    }

    public hash256 bookbase() {
        return index.bookstart(takerpays().issue(), takergets().issue());
    }

    public boolean belongstobook(hash256 bookbase) {
        byte[] basebytes = bookbase.bytes();
        byte[] directorybytes = bookdirectory().bytes();

        for (int i = 0; i < 24; i++) {
            if (basebytes[i] != directorybytes[i]) {
                return false;
            }
        }
        return true;
    }

    public boolean sellingownfunds() {
        return account().equals(takergets().issuer());
    }

    public amount takergetsfunded() {
        return has(field.taker_gets_funded) ? get(amount.taker_gets_funded) : takergets();
    }
    public amount takerpaysfunded() {
        return has(field.taker_pays_funded) ? get(amount.taker_pays_funded) : takerpays();
    }

    public static comparator<offer> qualityascending = new comparator<offer>() {
        @override
        public int compare(offer lhs, offer rhs) {
            return lhs.directoryaskquality().compareto(rhs.directoryaskquality());
        }
    };

    public static iterator<offer> iteratecollection(collection<stobject> offers) {
        final iterator<stobject> iterator = offers.iterator();

        return new iterator<offer>() {
            @override
            public boolean hasnext() {
                return iterator.hasnext();
            }

            @override
            public offer next() {
                return (offer) iterator.next();
            }

            @override
            public void remove() {
                iterator.remove();

            }
        };
    }

    public hash256 booknodedirectoryindex() {
        return index.directorynode(bookdirectory(), booknode());
    }

    public hash256 ownernodedirectoryindex() {
        hash256 ownerdir = index.ownerdirectory(account());
        return index.directorynode(ownerdir, ownernode());
    }


    public uint32 sequence() {return get(uint32.sequence);}
    public uint32 expiration() {return get(uint32.expiration);}
    public uint64 booknode() {return get(uint64.booknode);}
    public uint64 ownernode() {return get(uint64.ownernode);}
    public hash256 bookdirectory() {return get(hash256.bookdirectory);}
    public amount takerpays() {return get(amount.takerpays);}
    public amount takergets() {return get(amount.takergets);}
    public accountid account() {return get(accountid.account);}
    public void sequence(uint32 val) {put(field.sequence, val);}
    public void expiration(uint32 val) {put(field.expiration, val);}
    public void booknode(uint64 val) {put(field.booknode, val);}
    public void ownernode(uint64 val) {put(field.ownernode, val);}
    public void bookdirectory(hash256 val) {put(field.bookdirectory, val);}
    public void takerpays(amount val) {put(field.takerpays, val);}
    public void takergets(amount val) {put(field.takergets, val);}
    public void account(accountid val) {put(field.account, val);}

    public hash256[] directoryindexes() {
        return new hash256[]{booknodedirectoryindex(), ownernodedirectoryindex()};
    }

    public void setofferdefaults() {
        if (booknode() == null) {
            booknode(new uint64(0));
        }
        if (ownernode() == null) {
            ownernode(new uint64(0));
        }
    }
}
