package websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class MessageProvider {

    private MontoyaApi api;
    private Map<Integer, ProxyWebSocketCreation> sockets;
    private Map<Integer, List<Consumer<TextMessage>>> textMessageSubscribers = new HashMap<>();

    public MessageProvider(MontoyaApi api) {
        this.api = api;
        this.sockets = new HashMap<>();
    }

    public void handleTextMessage(int socketId, TextMessage message) {
        if (!this.sockets.containsKey(socketId)) {
            api.logging().logToOutput("[MessageProvider] Received text message for invalid socket ID: " + socketId);
            return;
        }

        List<Consumer<TextMessage>> subscribers = textMessageSubscribers.get(socketId);
        if (subscribers != null) {
            for (Consumer<TextMessage> subscriber : subscribers) {
                subscriber.accept(message);
            }
        }
    }

    public void handleBinaryMessage(int socketId, BinaryMessage message) {

    }

    public void handleSocketClosed(int socketId) {

    }

    public void handleSocketCreated(int socketId, ProxyWebSocketCreation webSocketCreation) {
        api.logging().logToOutput("[MessageProvider] New socket created with ID: " + socketId);
        this.sockets.put(socketId, webSocketCreation);
    }

    public void subscribeTextMessage(int socketId, Consumer<TextMessage> consumer) {
        textMessageSubscribers
                .computeIfAbsent(socketId, k -> new ArrayList<>())
                .add(consumer);
    }

    public void unsubscribeTextMessage(int socketId, Consumer<TextMessage> consumer) {
        List<Consumer<TextMessage>> subscribers = textMessageSubscribers.get(socketId);
        if (subscribers != null) {
            subscribers.remove(consumer);
        }
    }

}
