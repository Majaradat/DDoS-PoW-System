package com.jaradat.ddosmitigator.challenge;

public class Challenge {
    private final String challengeString;
    private final int difficulty; // Number of leading zeros required in the hash

    public Challenge(String challengeString, int difficulty) {
        this.challengeString = challengeString;
        this.difficulty = difficulty;
    }

    public String getChallengeString() {
        return challengeString;
    }

    public int getDifficulty() {
        return difficulty;
    }
}