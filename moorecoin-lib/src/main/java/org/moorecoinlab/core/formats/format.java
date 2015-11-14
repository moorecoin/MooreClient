package org.moorecoinlab.core.formats;

import org.moorecoinlab.core.fields.field;

import java.util.enummap;

public class format {
    public void addcommonfields(){}

    enummap<field, requirement> requirementenummap = new enummap<field, requirement>(field.class);

    public format(object[] args) {
        if ((!(args.length % 2 == 0)) || args.length < 2) {
            throw new illegalargumentexception("varargs length should be a minimum multiple of 2");
        }
        for (int i = 0; i < args.length; i+= 2) {
            field f = (field) args[i];
            requirement r = (requirement) args[i + 1];
            put(f, r);
        }
    }

    protected void put(field f, requirement r) {
        requirementenummap.put(f, r);
    }

    public static enum requirement {
        invalid(-1),
        required( 0),
        optional( 1),
        default( 2);
        requirement(int i) {}
    }

}
