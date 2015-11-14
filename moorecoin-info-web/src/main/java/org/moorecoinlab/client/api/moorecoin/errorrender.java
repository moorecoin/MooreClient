package org.moorecoinlab.client.api.render;

import com.google.gson.gson;

import java.util.hashmap;
import java.util.map;

public class errorrender {
    public static string render(int code, string message){
        map<string, object> render = new hashmap<>();
        render.put("code", code);
        render.put("message", message);
        return new gson().tojson(render);
    }
}
