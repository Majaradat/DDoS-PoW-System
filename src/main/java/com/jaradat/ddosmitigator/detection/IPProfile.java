package com.jaradat.ddosmitigator.detection;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;

public class IPProfile {

    private final String ipAddress;
    private final Queue<Long> requestTimestamps;
    private final Map<String, Integer> requestUrlCounts;
    private final long firstRequestTimestamp;
    private int totalRequestCount = 0;

    /**
     * Constructor to create a new profile for a given IP address.
     */
    public IPProfile(String ipAddress) {
        this.ipAddress = ipAddress;
        this.requestTimestamps = new LinkedList<>();
        this.requestUrlCounts = new HashMap<>();
        this.firstRequestTimestamp = System.currentTimeMillis(); // Record the creation time
    }

    /**
     * Adds a new request to this profile, updating our metrics.
     * This is like writing a new line in the notebook page for this IP.
     */
    public void addRequest(String url) {
        this.requestTimestamps.add(System.currentTimeMillis());
        this.requestUrlCounts.put(url, this.requestUrlCounts.getOrDefault(url, 0) + 1);
        this.totalRequestCount++;
    }

    /**
     * Calculates the requests per second over a given time window.
     * This version is more accurate for bursts of traffic.
     */
    public double getCurrentRPS(int windowSizeInSeconds) {
        long windowInMillis = windowSizeInSeconds * 1000L;
        long currentTime = System.currentTimeMillis();
        
        // This is the "sliding window" logic. Remove old timestamps.
        while (!requestTimestamps.isEmpty() && requestTimestamps.peek() < currentTime - windowInMillis) {
            requestTimestamps.poll();
        }
        
        // If there are no recent requests, the RPS is 0.
        if (requestTimestamps.isEmpty()) {
            return 0.0;
        }
        
        // Calculate the actual duration of the requests currently in the window.
        long durationInMillis = currentTime - requestTimestamps.peek();
        
        // We treat any duration less than a second as one full second to get a stable rate.
        double durationInSeconds = Math.max(1.0, durationInMillis / 1000.0);
        
        return (double) requestTimestamps.size() / durationInSeconds;
    }
    
    /**
     * Calculates a score from 0.0 to 1.0 indicating how repetitive the traffic is.
     * A score of 1.0 means all requests went to the same URL.
     */
    public double getRepetitionScore() {
        if (totalRequestCount == 0) {
            return 0.0;
        }
        int maxCount = 0;
        if (!requestUrlCounts.isEmpty()) {
            maxCount = Collections.max(requestUrlCounts.values());
        }
        return (double) maxCount / totalRequestCount;
    }

    /**
     * Calculates how long this IP's session has been active, in seconds.
     */
    public long getSessionDurationSeconds() {
        return (System.currentTimeMillis() - this.firstRequestTimestamp) / 1000L;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}