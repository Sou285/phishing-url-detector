package phishingdetector;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;
import javax.swing.JOptionPane;
import javax.swing.JProgressBar;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class PhishingDetectorGUI {

    public static void main(String[] args) {

        // MAIN WINDOW

        JFrame frame = new JFrame("Phishing URL Detector");

        frame.setSize(650, 500);

        frame.setLayout(new BorderLayout(10, 10));

        // TITLE

        JLabel titleLabel = new JLabel("PHISHING URL DETECTOR");

        titleLabel.setFont(
            new java.awt.Font("Arial", java.awt.Font.BOLD, 22)
        );

        JPanel titlePanel = new JPanel(new FlowLayout());

        titlePanel.add(titleLabel);

        // URL INPUT

        JLabel urlLabel = new JLabel("Enter URL:");

        urlLabel.setFont(
            new java.awt.Font("Arial", java.awt.Font.BOLD, 14)
        );

        JTextField urlField = new JTextField(40);

        JPanel urlPanel = new JPanel(new FlowLayout());

        urlPanel.add(urlLabel);
        urlPanel.add(urlField);

        // TOP PANEL

        JPanel topPanel = new JPanel(new BorderLayout());

        topPanel.add(titlePanel, BorderLayout.NORTH);
        topPanel.add(urlPanel, BorderLayout.CENTER);

        // CHECK BUTTON

        JButton checkButton = new JButton("CHECK URL");

        JButton clearButton = new JButton("CLEAR");

        JPanel buttonPanel = new JPanel(new FlowLayout());

        buttonPanel.add(checkButton);
        buttonPanel.add(clearButton);

        // RISK SCORE AND LEVEL

        JLabel scoreLabel = new JLabel("Risk Score: ");

        JLabel riskLabel = new JLabel("Risk Level: ");

        JLabel guideLabel = new JLabel(
            "LOW: 0-30   |   MEDIUM: 31-60   |   HIGH: 61+"
        );

        guideLabel.setFont(
            new java.awt.Font("Arial", java.awt.Font.PLAIN, 12)
        );

        JProgressBar riskBar = new JProgressBar(0, 100);

        riskBar.setStringPainted(true);

        riskBar.setValue(0);

        riskBar.setString("Risk");

        riskBar.setForeground(java.awt.Color.GRAY);

        scoreLabel.setFont(
            new java.awt.Font("Arial", java.awt.Font.BOLD, 14)
        );

        riskLabel.setFont(
            new java.awt.Font("Arial", java.awt.Font.BOLD, 14)
        );

        JPanel resultPanel = new JPanel(new FlowLayout());

        resultPanel.add(scoreLabel);
        resultPanel.add(riskLabel);
        resultPanel.add(riskBar);
        resultPanel.add(guideLabel);

        // WARNING AREA

        JTextArea resultArea = new JTextArea(12, 50);

        resultArea.setEditable(false);

        resultArea.setFont(
            new java.awt.Font("Arial", java.awt.Font.PLAIN, 14)
        );

        resultArea.setLineWrap(true);

        resultArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(resultArea);

        // CENTER PANEL

        JPanel centerPanel = new JPanel(new BorderLayout());

        centerPanel.add(buttonPanel, BorderLayout.NORTH);

        centerPanel.add(scrollPane, BorderLayout.CENTER);

        centerPanel.add(resultPanel, BorderLayout.SOUTH);

        // CHECK BUTTON ACTION

        checkButton.addActionListener(e -> {

            String url = urlField.getText();

            // Check empty URL

            if (url.trim().isEmpty()) {

                JOptionPane.showMessageDialog(
                    frame,
                    "Please enter a URL.",
                    "Input Required",
                    JOptionPane.WARNING_MESSAGE
                );

                return;
            }

            // Check URL format

            if (!url.startsWith("http://")
                    && !url.startsWith("https://")) {

                JOptionPane.showMessageDialog(
                    frame,
                    "Please enter a valid URL starting with http:// or https://",
                    "Invalid URL",
                    JOptionPane.WARNING_MESSAGE
                );

                return;
            }

            StringBuilder warnings = new StringBuilder();

            warnings.append("Detection Results\n");
            warnings.append("-----------------------------\n");

            // Calculate risk score using PhishingDetector

            int riskScore =
                PhishingDetector.calculateRiskScore(url);

            // Get risk level using PhishingDetector

            String riskLevel =
                PhishingDetector.getRiskLevel(riskScore);

            // RULE 1: HTTP

            if (PhishingDetector.usesHttp(url)) {

                warnings.append(
                    "Warning: URL uses HTTP (+10)\n"
                );
            }

            // RULE 2: IP ADDRESS

            if (PhishingDetector.hasIPAddress(url)) {

                warnings.append(
                    "Warning: URL contains an IP address (+25)\n"
                );
            }

            // RULE 3: @ SYMBOL

            if (PhishingDetector.hasAtSymbol(url)) {

                warnings.append(
                    "Warning: URL contains @ symbol (+20)\n"
                );
            }

            // RULE 4: SUSPICIOUS WORDS

            String[] foundWords =
                PhishingDetector.getSuspiciousWords(url);

            for (String word : foundWords) {

                warnings.append(
                    "Warning: Suspicious word found - "
                    + word + " (+5)\n"
                );
            }

            // RULE 5: LONG URL

            if (PhishingDetector.isLongURL(url)) {

                warnings.append(
                    "Warning: URL is unusually long (+10)\n"
                );
            }

            // RULE 6: TOO MANY SUBDOMAINS

            if (PhishingDetector.hasTooManySubdomains(url)) {

                warnings.append(
                    "Warning: URL has too many subdomains (+10)\n"
                );
            }

            // RULE 7: TOO MANY HYPHENS

            if (PhishingDetector.hasTooManyHyphens(url)) {

                warnings.append(
                    "Warning: URL has too many hyphens (+10)\n"
                );
            }

            // DISPLAY SCORE AND LEVEL

            scoreLabel.setText(
                "Risk Score: " + riskScore
            );

            riskLabel.setText(
                "Risk Level: " + riskLevel
            );

            riskBar.setValue(
                Math.min(riskScore, 100)
            );

            riskBar.setString(riskLevel);

            // CHANGE PROGRESS BAR COLOR

            if (riskScore <= 30) {

                riskBar.setForeground(
                    java.awt.Color.GREEN
                );

            } else if (riskScore <= 60) {

                riskBar.setForeground(
                    java.awt.Color.YELLOW
                );

            } else {

                riskBar.setForeground(
                    java.awt.Color.RED
                );
            }

            // DISPLAY WARNINGS

            if (riskScore == 0) {

                warnings.append(
                    "No suspicious characteristics detected.\n"
                );
            }

            // GET RECOMMENDATION

            String recommendation =
                PhishingDetector.getRecommendation(riskScore);

            // DISPLAY FINAL RESULT

            warnings.append(
                "\nFinal Result: " + riskLevel
            );

            warnings.append(
                "\n\nRecommendation:\n"
                + recommendation
            );

            resultArea.setText(
                warnings.toString()
            );

        });

        // CLEAR BUTTON ACTION

        clearButton.addActionListener(e -> {

            // Clear URL input
            urlField.setText("");

            // Reset score and risk level
            scoreLabel.setText("Risk Score: ");
            riskLabel.setText("Risk Level: ");

            // Reset progress bar
            riskBar.setValue(0);
            riskBar.setString("Risk");
            riskBar.setForeground(
                java.awt.Color.GRAY
            );

            // Clear detection results
            resultArea.setText("");

            // Put cursor back in URL field
            urlField.requestFocus();

        });

        // ADD PANELS TO FRAME

        frame.add(
            topPanel,
            BorderLayout.NORTH
        );

        frame.add(
            centerPanel,
            BorderLayout.CENTER
        );

        // SHOW WINDOW

        frame.setDefaultCloseOperation(
            JFrame.EXIT_ON_CLOSE
        );

        frame.setVisible(true);
    }
}