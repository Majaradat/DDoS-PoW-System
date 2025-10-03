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

    // --- NEW STATEFUL VARIABLES ---
    // The current severity level based on traffic metrics.
    private int currentSeverity = 0;
    // The timestamp when a threat was first detected. 0 if no threat.
    private long firstDetectionTimestamp = 0;

    public IPProfile(String ipAddress) {
        this.ipAddress = ipAddress;
        this.requestTimestamps = new LinkedList<>();
        this.requestUrlCounts = new HashMap<>();
        this.firstRequestTimestamp = System.currentTimeMillis();
    }

    public void addRequest(String url) {
        this.requestTimestamps.add(System.currentTimeMillis());
        this.requestUrlCounts.put(url, this.requestUrlCounts.getOrDefault(url, 0) + 1);
        this.totalRequestCount++;
    }

    public double getCurrentRPS(int windowSizeInSeconds) {
        long windowInMillis = windowSizeInSeconds * 1000L;
        long currentTime = System.currentTimeMillis();
        
        while (!requestTimestamps.isEmpty() && requestTimestamps.peek() < currentTime - windowInMillis) {
            requestTimestamps.poll();
        }
        
        if (requestTimestamps.isEmpty()) {
            return 0.0;
        }
        
        long durationInMillis = currentTime - requestTimestamps.peek();
        double durationInSeconds = Math.max(1.0, durationInMillis / 1000.0);
        
        return (double) requestTimestamps.size() / durationInSeconds;
    }

    public double getRepetitionScore() {
        if (totalRequestCount == 0) return 0.0;
        int maxCount = requestUrlCounts.isEmpty() ? 0 : Collections.max(requestUrlCounts.values());
        return (double) maxCount / totalRequestCount;
    }

    public long getSessionDurationSeconds() {
        return (System.currentTimeMillis() - this.firstRequestTimestamp) / 1000L;
    }

    // --- NEW STATE MANAGEMENT METHODS ---

    public int getCurrentSeverity() {
        return currentSeverity;
    }

    public void updateSeverity(int newSeverity) {
        if (newSeverity > 0 && this.currentSeverity == 0) {
            // This is the first time we've detected a threat for this profile
            this.firstDetectionTimestamp = System.currentTimeMillis();
        } else if (newSeverity == 0) {
            // The threat has passed, reset the detection timestamp
            this.firstDetectionTimestamp = 0;
        }
        this.currentSeverity = newSeverity;
    }

    public long getFirstDetectionTimestamp() {
        return firstDetectionTimestamp;
    }
    
    public int getActionableSeverity() {
        return this.currentSeverity;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
}