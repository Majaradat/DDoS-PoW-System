package com.jaradat.ddosmitigator.simulator;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.jaradat.ddosmitigator.core.Request;

public class TrafficSimulator {

    private final Random random = new Random();

    /**
     * Simulates a burst of traffic from a simple bot that repeatedly hits one URL.
     * @param ipAddress The source IP of the bot.
     * @param requestCount The number of requests to generate in this burst.
     * @return A list of simulated Request objects.
     */
    public List<Request> simulateDumbBotAttack(String ipAddress, int requestCount) {
        System.out.println("--- Simulating a dumb bot attack from " + ipAddress + " with " + requestCount + " requests ---");
        List<Request> traffic = new ArrayList<>();
        String targetUrl = "/api/v1/login"; // Bots often target a single, expensive endpoint.
        for (int i = 0; i < requestCount; i++) {
            traffic.add(new Request(ipAddress, targetUrl));
        }
        return traffic;
    }

    /**
     * Simulates a short burst of traffic from a normal user visiting a few pages.
     * @param ipAddress The source IP of the user.
     * @return A list of simulated Request objects.
     */
    public List<Request> simulateNormalUser(String ipAddress) {
        System.out.println("--- Simulating a normal user from " + ipAddress + " ---");
        List<Request> traffic = new ArrayList<>();
        traffic.add(new Request(ipAddress, "/"));
        traffic.add(new Request(ipAddress, "/products/item123"));
        traffic.add(new Request(ipAddress, "/about-us"));
        traffic.add(new Request(ipAddress, "/contact"));
        return traffic;
    }
}