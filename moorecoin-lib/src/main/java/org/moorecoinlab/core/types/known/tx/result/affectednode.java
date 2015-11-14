package org.moorecoinlab.core.types.known.tx.result;

import org.moorecoinlab.core.stobject;
import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.serialized.enums.ledgerentrytype;

public class affectednode extends stobject {
    field field;
    stobject nested;

    public affectednode(stobject source) {
        fields = source.getfields();
        field = getfield();
        nested = getnested();
    }

    public boolean waspreviousnode() {
        return isdeletednode() || ismodifiednode();
    }

    public boolean iscreatednode() {
        return field == field.creatednode;
    }

    public boolean isdeletednode() {
        return field == field.deletednode;
    }

    public boolean ismodifiednode() {
        return field == field.modifiednode;
    }

    public field getfield() {
        return fields.firstkey();
    }

    public hash256 ledgerindex() {
        return nested.get(hash256.ledgerindex);
    }

    public ledgerentrytype ledgerentrytype() {
        return ledgerentrytype(nested);
    }

    private stobject getnested() {
        return (stobject) get(getfield());
    }

    public stobject nodeasprevious() {
        return rebuildfrommeta(true);
    }

    public stobject nodeasfinal() {
        return rebuildfrommeta(false);
    }

    public stobject rebuildfrommeta(boolean layerprevious) {
        stobject mixed = new stobject();
        boolean created = iscreatednode();

        field wrapperfield = created ? field.creatednode :
                isdeletednode() ? field.deletednode :
                        field.modifiednode;

        stobject wrapped = (stobject) get(wrapperfield);

        field finalfields = created ? field.newfields :
                field.finalfields;

        if (!wrapped.has(finalfields)) {
            return stobject.formatted(new stobject(wrapped.getfields()));
        }

        stobject finals = (stobject) wrapped.get(finalfields);
        for (field field : finals) {
            mixed.put(field, finals.get(field));
        }

        // directorynode ledgerentrytype won't have `previousfields`
        if (layerprevious && wrapped.has(field.previousfields)) {
            stobject previous = wrapped.get(stobject.previousfields);
            stobject changed = new stobject();
            mixed.put(field.finalfields, changed);

            for (field field : previous) {
                mixed.put(field, previous.get(field));
                changed.put(field, finals.get(field));
            }
        }

        for (field field : wrapped) {
            switch (field) {
                case newfields:
                case previousfields:
                case finalfields:
                    continue;
                default:
                    serializedtype value = wrapped.get(field);

                    if (field == field.ledgerindex) {
                        field = field.index;
                    }
                    mixed.put(field, value);

            }
        }
        return stobject.formatted(mixed);
    }

    public static boolean isaffectednode(stobject source) {
        return (source.size() == 1 && (
                source.has(deletednode) ||
                source.has(creatednode) ||
                source.has(modifiednode)));
    }
}
