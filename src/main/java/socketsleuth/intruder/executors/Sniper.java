package socketsleuth.intruder.executors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.ProxyWebSocket;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.TextMessage;
import socketsleuth.intruder.JSONRPCMessageTableModel;
import socketsleuth.intruder.payloads.models.IPayloadModel;
import socketsleuth.intruder.payloads.payloads.Utils;
import websocket.MessageProvider;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class WebSocketMessage {
    private String data;
    private Direction direction;

    public WebSocketMessage(String data, Direction direction) {
        this.data = data;
        this.direction = direction;
    }
}

public class Sniper {
    private final MessageProvider socketProvider;
    private MontoyaApi api;
    private JSONRPCMessageTableModel tableModel;
    private Thread workerThread;
    private volatile boolean cancelled = false;
    private int minDelay = 100;
    private int maxDelay = 200;
    private List<WebSocketMessage> sentMessages;
    private Consumer<Integer> progressCallback;
    private Runnable completionCallback;

    public Sniper(MontoyaApi api, MessageProvider socketProvider) {
        this.api = api;
        this.socketProvider = socketProvider;
        this.sentMessages = new ArrayList<WebSocketMessage>();
    }
    
    /**
     * Set the table model to use for displaying messages.
     * This should be called before starting the attack.
     */
    public void setTableModel(JSONRPCMessageTableModel tableModel) {
        this.tableModel = tableModel;
    }

    public int getMinDelay() {
        return minDelay;
    }

    public void setMinDelay(int minDelay) {
        this.minDelay = minDelay;
    }

    public int getMaxDelay() {
        return maxDelay;
    }

    public void setMaxDelay(int maxDelay) {
        this.maxDelay = maxDelay;
    }

    public void setProgressCallback(Consumer<Integer> callback) {
        this.progressCallback = callback;
    }

    public void setCompletionCallback(Runnable callback) {
        this.completionCallback = callback;
    }

    public boolean isRunning() {
        if (workerThread == null) {
            return false;
        }
        return workerThread.isAlive();
    }

    public void cancel() {
        cancelled = true;
        if (workerThread != null) {
            workerThread.interrupt();
        }
    }

    public void start(ProxyWebSocket proxyWebSocket,
                      int socketId, IPayloadModel<String> payloadModel,
                      String baseInput,
                      Direction selectedDirection) {
        if (workerThread != null && workerThread.isAlive()) {
            api.logging().logToOutput("Intruder action is already running. Wait before new action.");
            return;
        }

        List<String> payloadPositions = Utils.extractPayloadPositions(baseInput);
        if (payloadPositions.size() == 0) {
            JOptionPane.showMessageDialog(
                    api.userInterface().swingUtils().suiteFrame(),
                    "Please ensure at least one payload position is defined.",
                    "Invalid configuration", JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        if (tableModel == null) {
            api.logging().logToOutput("Error: No table model set for Sniper executor");
            return;
        }
        
        api.logging().logToOutput(
                "Starting sniper payload insertion with Min Delay: "
                        + minDelay
                        + " Max Delay: "
                        + maxDelay
        );

        // Track the current payload for response association
        final String[] currentPayload = {null};
        
        Consumer<TextMessage> responseSubscriber = textMessage -> {
            SwingUtilities.invokeLater(() -> {
                // Responses don't have a payload, but we can associate with the last sent payload
                tableModel.addMessage(textMessage.payload(), textMessage.direction(), currentPayload[0]);
            });
        };
        this.socketProvider.subscribeTextMessage(socketId, responseSubscriber);

        cancelled = false;
        Random rand = new Random();
        final int totalPayloads = payloadModel.size();
        
        workerThread = new Thread(() -> {
            api.logging().logToOutput("Sniper execution started");
            int current = 0;
            for (String payload : payloadModel) {
                if (cancelled) {
                    api.logging().logToOutput("Sniper attack cancelled by user");
                    break;
                }
                
                // Track current payload for response association
                currentPayload[0] = payload;
                
                String newInput = replacePlaceholders(baseInput, payload);
                proxyWebSocket.sendTextMessage(newInput, selectedDirection);
                
                final int progress = current;
                final String payloadForTable = payload;
                SwingUtilities.invokeLater(() -> {
                    tableModel.addMessage(newInput, selectedDirection, payloadForTable);
                    if (progressCallback != null) {
                        int percent = totalPayloads > 0 ? (progress * 100) / totalPayloads : 0;
                        progressCallback.accept(percent);
                    }
                });
                
                sentMessages.add(new WebSocketMessage(newInput, selectedDirection));
                current++;
                
                int delay = rand.nextInt(maxDelay - minDelay + 1) + minDelay;
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException ex) {
                    if (cancelled) {
                        break;
                    }
                }
            }

            // Wait a while to catch responses from the final request (unless cancelled)
            if (!cancelled) {
                try {
                    api.logging().logToOutput("finished - cleaning up");
                    Thread.sleep(5000);
                } catch (InterruptedException ex) {
                    // Ignore
                }
            }
            
            this.socketProvider.unsubscribeTextMessage(socketId, responseSubscriber);
            api.logging().logToOutput("clean up complete");
            
            SwingUtilities.invokeLater(() -> {
                if (progressCallback != null) {
                    progressCallback.accept(100);
                }
                if (completionCallback != null) {
                    completionCallback.run();
                }
            });
        });

        workerThread.start();
    }

    private static String replacePlaceholders(String input, String replacement) {
        Pattern pattern = Pattern.compile("§(.*?)§");
        Matcher matcher = pattern.matcher(input);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(result, replacement);
        }
        matcher.appendTail(result);
        return result.toString();
    }
}
