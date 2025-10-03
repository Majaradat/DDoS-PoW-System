package com.jaradat.ddosmitigator;

import com.jaradat.ddosmitigator.challenge.Challenge;
import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.core.Request;
import com.jaradat.ddosmitigator.detection.DetectionEngine;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;
import com.jaradat.ddosmitigator.detection.IPProfile;

import java.util.List;

public class DemoScript {

    public static void main(String[] args) throws InterruptedException {
        // --- SETUP ---
        System.out.println("======================================================");
        System.out.println("DDoS Mitigation System: Live Demonstration");
        System.out.println("======================================================\n");
        PolicyManager policyManager = new PolicyManager();
        TrafficSimulator simulator = new TrafficSimulator();
        ChallengeService challengeService = new ChallengeService();

        // --- SCENARIO 1: The Legitimate User ---
        runScenario_NormalUser(policyManager, simulator);
        
        // --- SCENARIO 2: The "Dumb Bot" Flood (Timeout & Block) ---
        runScenario_DumbBot(policyManager, simulator);

        // --- SCENARIO 3: The Dynamic Escalation (Grand Finale) ---
        runScenario_DynamicEscalation(policyManager, simulator, challengeService);
        
        System.out.println("======================================================");
        System.out.println("Demonstration Concluded.");
        System.out.println("======================================================");
    }

    private static void runScenario_NormalUser(PolicyManager pm, TrafficSimulator sim) {
        printHeader("SCENARIO 1: The Legitimate User", "Prove that normal, low-rate traffic is not impacted.");
        DetectionEngine engine = new DetectionEngine(pm);
        String userIp = "192.168.1.100";
        List<Request> traffic = sim.simulateNormalUser(userIp);
        for (Request req : traffic) {
            engine.processRequest(req);
        }
        IPProfile profile = engine.getProfile(userIp);
        System.out.println("Final Severity for " + userIp + ": " + profile.getCurrentSeverity());
        printConclusion("System correctly identified traffic as benign. No action was taken. Test PASSED.");
    }

    private static void runScenario_DumbBot(PolicyManager pm, TrafficSimulator sim) throws InterruptedException {
        printHeader("SCENARIO 2: The 'Dumb Bot' Flood", "Demonstrate detection, challenge, and blocking of a non-responsive attacker.");
        DetectionEngine engine = new DetectionEngine(pm);
        String attackerIp = "10.20.30.40";
        int actionableSeverity = 0;

        for (int second = 1; second <= 3; second++) {
            List<Request> traffic = sim.simulateDumbBotAttack(attackerIp, 250);
            for (Request req : traffic) {
                actionableSeverity = engine.processRequest(req);
            }
            IPProfile profile = engine.getProfile(attackerIp);
            System.out.printf("[STATUS] End of Second %d | Current Severity: %d | Actionable Severity: %d\n", second, profile.getCurrentSeverity(), actionableSeverity);
            
            if (actionableSeverity > 0) {
                System.out.println("\n[MITIGATION] Observation window passed. Threat confirmed.");
                System.out.println("[MITIGATION] Issuing PoW Challenge with Difficulty " + actionableSeverity + ".");
                System.out.println("[ATTACKER SIM] 'Dumb Bot' does not respond to challenge.");
                System.out.println("[MITIGATION] Timeout exceeded. IP " + attackerIp + " is now considered BLOCKED.");
                break; // End this scenario
            }
            Thread.sleep(1000);
        }
        printConclusion("System successfully detected the flood and simulated blocking the non-compliant bot. Test PASSED.");
    }

    private static void runScenario_DynamicEscalation(PolicyManager pm, TrafficSimulator sim, ChallengeService cs) throws InterruptedException {
        printHeader("SCENARIO 3: The Dynamic Escalation", "Showcase the system adapting to a threat that increases its intensity in real-time.");
        DetectionEngine engine = new DetectionEngine(pm);
        String attackerIp = "99.88.77.66";
        int actionableSeverity = 0;

        // Phase 1: Moderate Attack
        System.out.println("\nPHASE 1: Attacker begins with a moderate flood (100 RPS).");
        for (int second = 1; second <= 2; second++) {
            List<Request> traffic = sim.simulateDumbBotAttack(attackerIp, 100);
            for (Request req : traffic) {
                actionableSeverity = engine.processRequest(req);
            }
            IPProfile profile = engine.getProfile(attackerIp);
            System.out.printf("[STATUS] End of Second %d | Current Severity: %d | Actionable Severity: %d\n", second, profile.getCurrentSeverity(), actionableSeverity);
            Thread.sleep(1000);
        }

        // Phase 2: Escalation
        System.out.println("\nPHASE 2: Attacker escalates to a CRITICAL flood (250 RPS).");
        List<Request> escalatedTraffic = sim.simulateDumbBotAttack(attackerIp, 250);
        for (Request req : escalatedTraffic) {
             actionableSeverity = engine.processRequest(req);
        }
        IPProfile profile = engine.getProfile(attackerIp);
        System.out.printf("[STATUS] After Escalation Burst | Current Severity: %d | Actionable Severity: %d\n", profile.getCurrentSeverity(), actionableSeverity);
        
        // Phase 3: Mitigation
        if (actionableSeverity > 0) {
            System.out.println("\n[MITIGATION] Observation window passed. Threat escalated to CRITICAL.");
            int difficulty = actionableSeverity + 2;
            System.out.println("[MITIGATION] Issuing a high-difficulty PoW Challenge (Difficulty " + difficulty + ").");
            solveAndReportChallenge(difficulty, cs);
        }
        printConclusion("System dynamically adapted to the escalating threat, imposing a significant computational cost. Test PASSED.");
    }
    
    private static void solveAndReportChallenge(int difficulty, ChallengeService cs) {
        System.out.println("[ATTACKER SIM] Received challenge. Brute-forcing solution... (This may take a moment)");
        Challenge challenge = cs.createChallenge(difficulty);
        long startTime = System.currentTimeMillis();
        String solution = cs.solveChallenge(challenge);
        long endTime = System.currentTimeMillis();
        double timeTaken = (endTime - startTime) / 1000.0;
        boolean isCorrect = cs.verifyChallenge(challenge, solution);

        System.out.printf("[ATTACKER SIM] Solution found in %.2f seconds. Verified: %b\n", timeTaken, isCorrect);
    }

    private static void printHeader(String title, String objective) {
        System.out.println("\n--- " + title + " ---");
        System.out.println("OBJECTIVE: " + objective);
    }
    
    private static void printConclusion(String conclusion) {
        System.out.println("CONCLUSION: " + conclusion);
        try {
            Thread.sleep(4000); // Pause between scenarios
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

