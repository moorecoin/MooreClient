package org.moorecoinlab.client;

import org.moorecoinlab.core.exception.moorecoinexception;

import java.util.map;

public interface clientprocessor {

    static final string uri = "http://"+ org.moorecoinlab.client.util.config.getinstance().getproperty("client.server.host")+":"+ org.moorecoinlab.client.util.config.getinstance().getproperty("client.server.port");
    static final string admin_uri = "http://"+ org.moorecoinlab.client.util.config.getinstance().getproperty("client.server.admin.host") + ":"+ org.moorecoinlab.client.util.config.getinstance().getproperty("client.server.port");
    static final string model_server = org.moorecoinlab.client.util.config.getinstance().getproperty("model.api.server");

    public string processresponse(map<string, string> params) throws moorecoinexception;
}
