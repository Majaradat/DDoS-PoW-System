package com.jaradat.ddosmitigator;

import java.util.List;

import com.jaradat.ddosmitigator.challenge.Challenge;
import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.core.Request;
import com.jaradat.ddosmitigator.detection.DetectionEngine;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;

public class Main {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("--- Initializing DDoS Mitigation System ---");
        PolicyManager policyManager = new PolicyManager();
        TrafficSimulator simulator = new TrafficSimulator();
        ChallengeService challengeService = new ChallengeService();
        System.out.println("-----------------------------------------\n");

        // --- ACT 1: NORMAL USER ---
        System.out.println("--- ACT 1: Simulating a Legitimate User ---");
        DetectionEngine engine1 = new DetectionEngine(policyManager);
        String userIp = "192.168.1.100";
        List<Request> normalTraffic = simulator.simulateNormalUser(userIp);
        int userSeverity = 0;
        for (Request req : normalTraffic) {
            userSeverity = engine1.analyzeRequest(req);
        }
        System.out.println("Final Severity for " + userIp + ": " + userSeverity);
        System.out.println("RESULT: Legitimate user was not impacted.\n");
        Thread.sleep(2000);

        // --- ACT 2: "DUMB" BOT ATTACK ---
        System.out.println("--- ACT 2: Simulating a 'Dumb Bot' Flood Attack ---");
        DetectionEngine engine2 = new DetectionEngine(policyManager);
        String dumbBotIp = "10.20.30.40";
        int dumbBotSeverity = 0;
        for (int second = 1; second <= 3; second++) {
            List<Request> attackTraffic = simulator.simulateDumbBotAttack(dumbBotIp, 150); // More aggressive attack
            for (Request req : attackTraffic) {
                dumbBotSeverity = engine2.analyzeRequest(req);
            }
            System.out.println("End of Second " + second + ": Severity for " + dumbBotIp + " is now: " + dumbBotSeverity);
            Thread.sleep(1000);
        }
        System.out.println("[SYSTEM ACTION] Severity CRITICAL. Issuing PoW Challenge.");
        System.out.println("[SYSTEM ACTION] Dropping subsequent requests from non-compliant bot.");
        System.out.println("RESULT: Attack detected and traffic from the simple bot was blocked.\n");
        Thread.sleep(2000);

        // --- ACT 3: "SMART" BOT ATTACK ---
        System.out.println("--- ACT 3: Simulating a 'Smart Bot' Attack (with PoW solving) ---");
        DetectionEngine engine3 = new DetectionEngine(policyManager);
        String smartBotIp = "99.88.77.66";
        int smartBotSeverity = 0;
        List<Request> smartBotTraffic = simulator.simulateDumbBotAttack(smartBotIp, 100);
        for (Request req : smartBotTraffic) {
            smartBotSeverity = engine3.analyzeRequest(req);
        }
        System.out.println("End of First Burst: Severity for " + smartBotIp + " is now: " + smartBotSeverity);

        if (smartBotSeverity > 0) {
            // This is the key change to make the puzzle much harder for the demo.
            int difficulty = smartBotSeverity + 2;
            
            System.out.println("[SYSTEM ACTION] Issuing PoW Challenge with difficulty " + difficulty + " (requiring " + difficulty + " leading zeros).");
            Challenge challenge = challengeService.createChallenge(difficulty);
            
            System.out.println("[SMART BOT] Received challenge. Brute-forcing solution...");
            long startTime = System.currentTimeMillis();
            String solution = challengeService.solveChallenge(challenge); // This is the REAL work
            long endTime = System.currentTimeMillis();

            boolean isCorrect = challengeService.verifyChallenge(challenge, solution);
            double timeTaken = (endTime - startTime) / 1000.0;

            System.out.println("[SMART BOT] Solution found: " + solution + ". Verified: " + isCorrect);
            System.out.printf("RESULT: Sophisticated bot was crippled, spending %.2f seconds of CPU time to solve the puzzle.\n", timeTaken);
        }
    }
}
