package com.jaradat.ddosmitigator.core;

public class Request {
    private final String ipAddress;
    private final String url;

    public Request(String ipAddress, String url) {
        this.ipAddress = ipAddress;
        this.url = url;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUrl() {
        return url;
    }
}