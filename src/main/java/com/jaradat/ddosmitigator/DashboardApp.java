package com.jaradat.ddosmitigator;

import com.jaradat.ddosmitigator.challenge.ChallengeService;
import com.jaradat.ddosmitigator.detection.PolicyManager;
import com.jaradat.ddosmitigator.simulator.TrafficSimulator;
import io.javalin.Javalin;
import io.javalin.websocket.WsContext;

import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * This class is the main entry point for the web dashboard.
 * Its only responsibility is to start the web server and manage WebSocket connections.
 */
public class DashboardApp {

    private static final ConcurrentLinkedQueue<WsContext> wsContexts = new ConcurrentLinkedQueue<>();

    public static void main(String[] args) {
        // --- Initialize all the core components of our system ---
        PolicyManager policyManager = new PolicyManager();
        TrafficSimulator simulator = new TrafficSimulator();
        ChallengeService challengeService = new ChallengeService();

        // --- Start the web server ---
        Javalin app = Javalin.create(config -> {
            config.staticFiles.add("/public"); 
        }).start(7070);

        // --- Handle WebSocket connections ---
        app.ws("/dashboard-updates", ws -> {
            ws.onConnect(ctx -> {
                System.out.println("[WebSocket] New dashboard connected: " + ctx.sessionId());
                wsContexts.add(ctx);
                
                // When a browser connects, create and run the demo in a new thread.
                DemoRunner demo = new DemoRunner(policyManager, simulator, challengeService, wsContexts);
                new Thread(demo::run).start();
            });

            ws.onClose(ctx -> {
                System.out.println("[WebSocket] Dashboard disconnected: " + ctx.sessionId());
                wsContexts.remove(ctx);
            });
        });

        System.out.println("Dashboard is running at: http://localhost:7070");
        System.out.println("Open this URL in your browser to see the live demo.");
    }
}