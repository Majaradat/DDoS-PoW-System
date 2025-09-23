package com.jaradat.ddosmitigator.detection;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.jaradat.ddosmitigator.core.Request;

public class DetectionEngine {

    // A map to hold all the "notebook pages" (IP profiles) we are actively tracking.
    private final Map<String, IPProfile> activeProfiles = new HashMap<>();
    
    // A reference to our "rulebook".
    private final PolicyManager policyManager;
    
    // Defines our sliding window for RPS calculation.
    private static final int TIME_WINDOW_SECONDS = 10;

    public DetectionEngine(PolicyManager policyManager) {
        this.policyManager = policyManager;
    }

    /**
     * This is the main method of the engine. It analyzes a single request
     * and returns a severity level (0 for normal, 1-4 for attacks).
     */
    public int analyzeRequest(Request request) {
        String ip = request.getIpAddress();

        // Get the existing profile for this IP, or create a new one if it's the first time we've seen it.
        IPProfile profile = activeProfiles.computeIfAbsent(ip, IPProfile::new);

        // Add the new request to the profile.
        profile.addRequest(request.getUrl());

        // Get the latest behavioral metrics from the profile.
        double currentRPS = profile.getCurrentRPS(TIME_WINDOW_SECONDS);
        double repetitionScore = profile.getRepetitionScore();
        long sessionDuration = profile.getSessionDurationSeconds();

        // Check these metrics against our rules, starting from the most severe.
        List<PolicyRule> rules = policyManager.getRules();
        for (int i = rules.size() - 1; i >= 0; i--) {
            PolicyRule rule = rules.get(i);
            if (currentRPS >= (rule.rps * 0.9) &&  // Check if RPS is within 90% of the threshold
                repetitionScore >= rule.repetitionScore && 
                sessionDuration < rule.sessionDurationSeconds) {
                
                return rule.level; // We have a match! Return the severity level.
            }
        }

        return 0; // No rules matched, traffic is normal.
    }
}