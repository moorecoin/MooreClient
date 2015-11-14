package org.moorecoinlab.core.serialized;

import org.json.jsonarray;
import org.json.jsonobject;

import java.util.list;
import java.util.map;

public enum value {
    unknown,
    string,
    json_object,
    json_array,
    list,
    map,
    number,
    byte,
    double,
    float,
    integer,
    long,
    short, boolean;

    static public value typeof (object object) {
        if (object instanceof string) {
            return string;
        }
        else if (object instanceof number) {
            if (object instanceof byte) {
                return byte;
            }
            else if (object instanceof double) {
                return double;
            }
            else if (object instanceof float) {
                return float;
            }
            else if (object instanceof integer) {
                return integer;
            }
            else if (object instanceof long) {
                return long;
            }
            else if (object instanceof short) {
                return short;
            }
            return number;
        }
        else if (object instanceof jsonobject) {
            return json_object;
        }
        else if (object instanceof jsonarray) {
            return json_array;
        }
        else if (object instanceof map) {
            return map;
        }
        else if (object instanceof boolean) {
            return boolean;
        }
        else if (object instanceof list) {
            return list;
        }
        else {
            return unknown;
        }
    }
}
