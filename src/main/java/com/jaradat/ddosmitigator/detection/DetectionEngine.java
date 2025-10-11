package com.jaradat.ddosmitigator.detection;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.jaradat.ddosmitigator.core.Request;
import com.jaradat.ddosmitigator.mitigation.BlocklistService;

public class DetectionEngine {

    private final Map<String, IPProfile> activeProfiles = new HashMap<>();
    private final PolicyManager policyManager;
    private final BlocklistService blocklistService;
    private final List<PolicyRule> rules;

    private static final long OBSERVATION_WINDOW_MS = 2000;
    private static final int TIME_WINDOW_SECONDS = 10;

    public DetectionEngine(PolicyManager policyManager, BlocklistService blocklistService) {
        this.policyManager = policyManager;
        this.blocklistService = blocklistService;
        this.rules = policyManager.getRules();
        this.rules.sort(Comparator.comparingInt(rule -> -rule.level));
    }

    public int processRequest(Request request) {
        String ip = request.getIpAddress();

        if (blocklistService.isBlocked(ip)) {
            return -1; // Use -1 to signify a blocked request
        }

        IPProfile profile = activeProfiles.computeIfAbsent(ip, IPProfile::new);
        profile.addRequest(request.getUrl());

        int currentSeverity = updateAndGetCurrentSeverity(profile);
        profile.setCurrentSeverity(currentSeverity);

        if (profile.getFirstDetectionTimestamp() > 0 && 
            (System.currentTimeMillis() - profile.getFirstDetectionTimestamp() > OBSERVATION_WINDOW_MS)) {
            return profile.getCurrentSeverity();
        }

        return 0;
    }

    private int updateAndGetCurrentSeverity(IPProfile profile) {
        double currentRPS = profile.getCurrentRPS(TIME_WINDOW_SECONDS);
        double repetitionScore = profile.getRepetitionScore();
        long sessionDuration = profile.getSessionDurationSeconds();

        for (PolicyRule rule : this.rules) {
            if (currentRPS >= rule.rps &&
                repetitionScore >= rule.repetitionScore &&
                sessionDuration < rule.sessionDurationSeconds) {
                return rule.level;
            }
        }
        return 0;
    }
    
    public IPProfile getProfile(String ip) {
        return activeProfiles.get(ip);
    }
}