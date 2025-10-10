package com.jaradat.ddosmitigator.detection;

import com.jaradat.ddosmitigator.core.Request;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The core brain of the system. It analyzes traffic, manages IP profiles,
 * and determines the threat level using an "observation window".
 */
public class DetectionEngine {

    private final Map<String, IPProfile> activeProfiles = new HashMap<>();
    private final PolicyManager policyManager;
    private final List<PolicyRule> rules;

    // Defines the "grace period" in milliseconds before taking action.
    private static final long OBSERVATION_WINDOW_MS = 2000; // 2 seconds
    private static final int TIME_WINDOW_SECONDS = 10;

    public DetectionEngine(PolicyManager policyManager) {
        this.policyManager = policyManager;
        this.rules = policyManager.getRules();
        // Sort rules by severity descending to check most severe first.
        this.rules.sort(Comparator.comparingInt(rule -> -rule.level));
    }

    /**
     * Main entry point for analysis. Processes a request and returns an "actionable" severity.
     * An actionable severity is only returned after the observation window has passed.
     * @return The severity level (e.g., 4) if action should be taken, otherwise 0.
     */
    public int processRequest(Request request) {
        String ip = request.getIpAddress();
        IPProfile profile = activeProfiles.computeIfAbsent(ip, IPProfile::new);
        profile.addRequest(request.getUrl());

        int currentSeverity = updateAndGetCurrentSeverity(profile);
        profile.setCurrentSeverity(currentSeverity); // Update the profile's memory

        // Check if the observation window has passed
        if (profile.getFirstDetectionTimestamp() > 0 && 
            (System.currentTimeMillis() - profile.getFirstDetectionTimestamp() > OBSERVATION_WINDOW_MS)) {
            return profile.getCurrentSeverity(); // Window passed, threat is confirmed and actionable.
        }

        return 0; // Still in observation window, no action should be taken yet.
    }

    /**
     * Calculates the current severity based on traffic metrics and rules.
     */
    private int updateAndGetCurrentSeverity(IPProfile profile) {
        double currentRPS = profile.getCurrentRPS(TIME_WINDOW_SECONDS);
        double repetitionScore = profile.getRepetitionScore();
        long sessionDuration = profile.getSessionDurationSeconds();

        for (PolicyRule rule : this.rules) {
            if (currentRPS >= rule.rps &&
                repetitionScore >= rule.repetitionScore &&
                sessionDuration < rule.sessionDurationSeconds) {
                return rule.level; // Return the highest matching severity level
            }
        }
        return 0; // No rules matched, traffic is normal.
    }
    
    /**
     * Helper method to get an IP's profile for the dashboard.
     */
    public IPProfile getProfile(String ip) {
        return activeProfiles.get(ip);
    }
}