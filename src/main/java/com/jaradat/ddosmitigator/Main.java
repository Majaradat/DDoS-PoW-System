package com.jaradat.ddosmitigator;

import java.util.List;

import com.jaradat.ddosmitigator.core.Request;
import com.jaradat.ddosmitigator.detection.DetectionEngine;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;

public class Main {
    public static void main(String[] args) throws InterruptedException {
        // --- Setup ---
        PolicyManager policyManager = new PolicyManager();
        DetectionEngine engine = new DetectionEngine(policyManager);
        TrafficSimulator simulator = new TrafficSimulator();

        // --- Simulation ---
        String attackerIp = "10.20.30.40";
        
        System.out.println("--- Starting DDoS Simulation from " + attackerIp + " ---");

        // We will simulate the attack over 6 seconds.
        for (int second = 1; second <= 6; second++) {
            // Generate a burst of 50 requests for this second.
            List<Request> attackTraffic = simulator.simulateDumbBotAttack(attackerIp, 50);

            // Feed this burst into the engine.
            int finalSeverity = 0;
            for (Request req : attackTraffic) {
                finalSeverity = engine.analyzeRequest(req);
            }

            // Print the status at the end of the second.
            System.out.println("End of Second " + second + 
                               ": Severity for " + attackerIp + " is now: " + finalSeverity);

            // Pause for 1 second to simulate the passage of time.
            Thread.sleep(1000); 
        }
    }
}