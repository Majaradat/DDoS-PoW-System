# DDoS-PoW-System
DDoS Mitigation System (Proof-of-Work)

A Java-based simulation framework demonstrating how Client-Side Proof-of-Work (PoW) can be used to mitigate Application Layer (Layer 7) DDoS attacks by flipping the computational cost asymmetry back onto the attacker.

<img width="1894" height="877" alt="image" src="https://github.com/user-attachments/assets/9d0d47cd-d4df-47a4-a0af-f179c9769c72" />


🚀 Project Overview

This project simulates a web server under attack and demonstrates a defensive mechanism that dynamically issues cryptographic challenges (SHA-256 puzzles) to suspicious clients.

The system proves that by forcing clients to solve a computationally expensive puzzle before accessing resources, we can:

Protect Server Resources: The server verifies solutions in microseconds (O(1)), while attackers spend seconds (O(N)) solving them.

Filter Traffic: Legitimate users on standard hardware solve puzzles quickly (low difficulty), while high-volume botnets are stalled or blocked.

Punish Recidivism: Repeat offenders face exponentially harder challenges.

🛠️ Key Features

Real-Time SOC Dashboard: A modern web interface (WebSocket-based) to visualize traffic, attack severity, and mitigation events.

Dynamic Difficulty Scaling: Automatically adjusts puzzle difficulty based on traffic behavior (RPS, Repetition, Session Duration).

Multi-Threaded Solver Simulation: Includes a built-in stress tester that utilizes all CPU cores to demonstrate the real hardware impact of solving high-difficulty puzzles.

Cost Asymmetry Analysis: Calculates and displays the "Cost Ratio" (e.g., Attacker spent 4s, Server spent 0.0001s -> 40,000x Asymmetry).

Strike System: Tracks persistent threats and escalates penalties for repeat offenders.

🧪 Simulation Scenarios

The dashboard includes a control panel to trigger specific scenarios:

Legitimate User: Simulates normal human browsing behavior (Low RPS, varied URLs). System verdict: Benign.

Laggy/Burst User: Simulates a false-positive trigger (brief burst). System verdict: Observation Mode (Traffic allowed after monitoring).

Dumb Bot (Timeout): Simulates a simple script that cannot solve puzzles. System verdict: Blocked (Challenge Timeout).

Persistent Adversary: Simulates a sophisticated bot that solves the first puzzle but attacks again. System verdict: Punitive Escalation (Difficulty increased, Strike recorded).

CPU Stress Test: Unleashes a multi-threaded solver on your local machine to demonstrate 100% CPU utilization and verify the cryptographic difficulty.

🏗️ Architecture

Language: Java 21

Web Framework: Javalin (Lightweight Web Server)

Communication: WebSockets (Real-time updates)

Frontend: HTML5, CSS3 (Grid/Flexbox), Chart.js

Cryptography: SHA-256 (Java Security API)

Core Components

DetectionEngine: Analyzes incoming requests and assigns a Severity Score (0-4).

ChallengeService: Generates and validates SHA-256 puzzles.

TrafficSimulator: Generates synthetic traffic patterns for the demo.

DemoRunner: The orchestration engine that runs the scenarios and broadcasts events.

🚀 How to Run

Prerequisites:

Java JDK 21 or higher.

Maven.

Build the Project:

mvn clean install


Run the Application:

# Run the main class
java -cp target/classes:target/dependency/* com.jaradat.ddosmitigator.DashboardApp


(Or run DashboardApp.java directly from your IDE)

Access the Dashboard:
Open your browser and navigate to: http://localhost:7070

📊 Proof of Concept Data

Sample output from a Difficulty 6 Stress Test:

STRESS TEST RESULTS:

Cores Utilized: 8 (100% CPU Load)

Difficulty: 6 (Requires ~16.7 Million Hashes)

Attacker Time: 4.2531 s (Heavy Computation)

Defender Time: 0.0002 s (Instant Verification)

Cost Asymmetry: 21,265x (The attacker works 21,000 times harder than the defender)

📜 License

This project is for educational and demonstration purposes.
