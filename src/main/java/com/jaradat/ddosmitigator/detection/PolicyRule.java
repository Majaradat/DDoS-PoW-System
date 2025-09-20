package com.jaradat.ddosmitigator.detection;

public class PolicyRule {
    int level;
    String levelName;
    int rps;
    double repetitionScore;
    int sessionDurationSeconds;

    /**
     * This is a helper method that makes it easy to print the contents
     * of a PolicyRule object for testing and debugging.
     */
    @Override
    public String toString() {
        return "PolicyRule{" +
                "level=" + level +
                ", levelName='" + levelName + '\'' +
                ", rps=" + rps +
                '}';
    }
}
