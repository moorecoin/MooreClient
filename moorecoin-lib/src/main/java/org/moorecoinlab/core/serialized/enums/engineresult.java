package org.moorecoinlab.core.serialized.enums;

import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.typetranslator;
import org.ripple.bouncycastle.util.encoders.hex;

import java.util.treemap;

public enum engineresult implements serializedtype
{
    tellocal_error(-399, "local failure."),
    telbad_domain (-398, "domain too long."),
    telbad_path_count (-397, "malformed: too many paths."),
    telbad_public_key (-396, "public key too long."),
    telfailed_processing (-395, "failed to correctly process transaction."),
    telinsuf_fee_p (-394, "fee insufficient."),
    telno_dst_partial (-393, "partial payment to create account not allowed."),

    temmalformed (-299, "malformed transaction."),
    tembad_amount (-298, "can only send positive amounts."),
    tembad_auth_master (-297, "auth for unclaimed account needs correct master key."),
    tembad_currency (-296, "malformed: bad currency."),
    tembad_expiration (-295, "malformed: bad expiration."),
    tembad_fee (-294, "invalid fee, negative or not vrp."),
    tembad_issuer (-293, "malformed: bad issuer."),
    tembad_limit (-292, "limits must be non-negative."),
    tembad_offer (-291, "malformed: bad offer."),
    tembad_path (-290, "malformed: bad path."),
    tembad_path_loop (-289, "malformed: loop in path."),
    tembad_send_vrp_limit(-288, "malformed: limit quality is not allowed for vrp to vrp."),
    tembad_send_vrp_max(-287, "malformed: send max is not allowed for vrp to vrp."),
    tembad_send_vrp_no_direct(-286, "malformed: no ripple direct is not allowed for vrp to vrp."),
    tembad_send_vrp_partial(-285, "malformed: partial payment is not allowed for vrp to vrp."),
    tembad_send_vrp_paths(-284, "malformed: paths are not allowed for vrp to vrp."),
    tembad_sequence (-283, "malformed: sequence is not in the past."),
    tembad_signature (-282, "malformed: bad signature."),
    tembad_src_account (-281, "malformed: bad source account."),
    tembad_transfer_rate(-280, "malformed: bad transfer rate"),
    temdst_is_src (-279, "destination may not be source."),
    temdst_needed (-278, "destination not specified."),
    teminvalid (-277, "the transaction is ill-formed."),
    teminvalid_flag (-276, "the transaction has an invalid flag."),
    temredundant (-275, "sends same currency to self."),
    temredundant_send_max (-274, "send max is redundant."),
    temripple_empty (-273, "pathset with no paths."),

    temuncertain (-272, "in process of determining result. never returned."),
    temunknown (-271, "the transactions requires logic not implemented yet."),

    teffailure (-199, "failed to apply."),
    tefalready (-198, "the exact transaction was already in this ledger."),
    tefbad_add_auth (-197, "not authorized to add account."),
    tefbad_auth (-196, "transaction's public key is not authorized."),
    tefbad_ledger (-195, "ledger in unexpected state."),
    tefcreated (-194, "can't add an already created account."),
    tefdst_tag_needed (-193, "destination tag required."),
    tefexception (-192, "unexpected program state."),
    tefinternal (-191, "internal error."),
    tefno_auth_required (-190, "auth is not required."),
    tefpast_seq (-189, "this sequence number has already past."),
    tefwrong_prior (-188, "tefwrong_prior"),
    tefmaster_disabled (-187, "tefmaster_disabled"),
    tefmax_ledger (-186, "ledger sequence too high."),

    terretry (-99, "retry transaction."),
    terfunds_spent (-98, "can't set password, password set funds already spent."),
    terinsuf_fee_b (-97, "accountid balance can't pay fee."),
    terno_account (-96, "the source account does not exist."),
    terno_auth (-95, "not authorized to hold ious."),
    terno_line (-94, "no such line."),
    terowners (-93, "non-zero owner count."),
    terpre_seq (-92, "missing/inapplicable prior transaction."),
    terlast (-91, "process last."),
    terno_ripple(-90, "process last."),

    tessuccess (0, "the transaction was applied."),
    tecclaim (100, "fee claimed. sequence used. no action."),
    tecpath_partial (101, "path could not send full amount."),
    tecunfunded_add (102, "insufficient vrp balance for walletadd."),
    tecunfunded_offer (103, "insufficient balance to fund created offer."),
    tecunfunded_payment (104, "insufficient vrp balance to send."),
    tecfailed_processing (105, "failed to correctly process transaction."),
    tecdir_full (121, "can not add entry to full directory."),
    tecinsuf_reserve_line (122, "insufficient reserve to add trust line."),
    tecinsuf_reserve_offer (123, "insufficient reserve to create offer."),
    tecno_dst (124, "destination does not exist. send vrp to create it."),
    tecno_dst_insuf_vrp(125, "destination does not exist. too little vrp sent to create it."),
    tecno_line_insuf_reserve (126, "no such line. too little reserve to create it."),
    tecno_line_redundant (127, "can't set non-existant line to default."),
    tecpath_dry (128, "path could not send partial amount."),
    tecunfunded (129, "one of _add, _offer, or _send. deprecated."),
    tecmaster_disabled (130, "tecmaster_disabled"),
    tecno_regular_key (131, "tecno_regular_key"),
    tecowners (132, "tecowners"),
    tecno_issuer(133, "issuer account does not exist."),
    tecno_auth(134, "not authorized to hold asset."),
    tecno_line(135, "no such line."),
    tecinsuff_fee(136,  "insufficient balance to pay fee."),
    tecfrozen(137, "asset is frozen."),
    tecno_target(138, "target account does not exist."),
    tecno_permission(139, "no permission to perform requested operation."),
    tecno_entry(140, "no matching entry found."),
    tecinsufficient_reserve(141, "insufficient reserve to complete requested operation.");

    public int asinteger() {
        return ord;
    }

    int ord;
    string human;
    engineresult class_ = null;

    engineresult(int i, string s) {
        human = s;
        ord = i;
    }

    private static treemap<integer, engineresult> bycode;

    static {
        bycode = new treemap<integer, engineresult>();
        for (engineresult ter : engineresult.values()) {
            bycode.put(ter.ord, ter);
        }
    }

    public static engineresult fromnumber(number i) {
        return bycode.get(i.intvalue());
    }


    /*serialized type implementation*/
    @override
    public byte[] tobytes() {
        return new byte[]{(byte) ord};
    }

    @override
    public void tobytessink(bytessink to) {
        to.add((byte) ord);
    }

    @override
    public object tojson() {
        return tostring();
    }

    @override
    public string tohex() {
        return hex.tohexstring(tobytes());
    }

    public static class translator extends typetranslator<engineresult> {
        @override
        public engineresult fromparser(binaryparser parser, integer hint) {
            return frominteger((int) parser.read(1)[0]);
        }

        @override
        public engineresult fromstring(string value) {
            return engineresult.valueof(value);
        }

        @override
        public engineresult frominteger(int integer) {
            return fromnumber(integer);
        }
    }

    public static translator translate = new translator();

    // result classes
    public static engineresult resultclass(engineresult result) {
        if (result.ord >= tellocal_error.ord && result.ord < temmalformed.ord) {
            return tellocal_error;
        }
        if (result.ord >= temmalformed.ord && result.ord < teffailure.ord) {
            return temmalformed;
        }
        if (result.ord >= teffailure.ord && result.ord < terretry.ord) {
            return teffailure;
        }
        if (result.ord >= terretry.ord && result.ord < tessuccess.ord) {
            return terretry;
        }
        if (result.ord >= tessuccess.ord && result.ord < tecclaim.ord) {
            return tessuccess;
        }
        return tecclaim;
    }
    public engineresult resultclass() {
        return class_;
    }
    static {
        for (engineresult engineresult : engineresult.values()) {
            engineresult.class_ = resultclass(engineresult);
        }
    }

}


