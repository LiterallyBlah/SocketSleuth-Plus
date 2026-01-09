import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import socketsleuth.WebSocketInterceptionRulesTableModel;
import websocket.MessageProvider;

import javax.swing.*;
import java.util.Map;

class WebSocketCreationHandler implements ProxyWebSocketCreationHandler {

    private final MessageProvider socketProvider;
    Logging logger;
    MontoyaApi api;
    Map<Integer, WebSocketContainer> connections;
    WebSocketConnectionTableModel tableModel;
    JTable connectionTable;
    JTable streamTable;
    WebSocketInterceptionRulesTableModel interceptionRules;
    WebSocketMatchReplaceRulesTableModel matchReplaceRules;
    JSONRPCResponseMonitor responseMonitor;
    WebSocketAutoRepeater webSocketAutoRepeater;

    public WebSocketCreationHandler(
            MontoyaApi api,
            WebSocketConnectionTableModel tableModel,
            Map<Integer, WebSocketContainer> wsConnections,
            JTable connectionTable,
            JTable streamTable,
            WebSocketInterceptionRulesTableModel interceptionRules,
            WebSocketMatchReplaceRulesTableModel matchReplaceRules,
            JSONRPCResponseMonitor responseMonitor,
            WebSocketAutoRepeater webSocketAutoRepeater,
            MessageProvider socketProvider) {
        this.api = api;
        this.logger = api.logging();
        this.connections = wsConnections;
        this.tableModel = tableModel;
        this.connectionTable = connectionTable;
        this.streamTable = streamTable;
        this.interceptionRules = interceptionRules;
        this.matchReplaceRules = matchReplaceRules;
        this.responseMonitor = responseMonitor;
        this.webSocketAutoRepeater = webSocketAutoRepeater;
        this.socketProvider = socketProvider;
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation webSocketCreation) {
        logger.logToOutput("New WS connection received");

        // Store off the WebSocket so we can access it later
        WebSocketContainer container = new WebSocketContainer();
        container.setWebSocketCreation(webSocketCreation);
        container.setTableRow(new WebsocketConnectionTableRow(
                this.connections.size(),
                webSocketCreation.upgradeRequest().url(),
                webSocketCreation.upgradeRequest().httpService().port(),
                true,
                webSocketCreation.upgradeRequest().httpService().secure(),
                "",
                webSocketCreation.upgradeRequest(),
                webSocketCreation.proxyWebSocket()
        ));

        // TODO: Investigate if we can get the socketId form burp instead of making our own
        final int socketId = this.connections.size();
        this.connections.put(socketId, container);
        this.socketProvider.handleSocketCreated(socketId, webSocketCreation);

        // Get the new row from container and add to actual table model (on EDT)
        SwingUtilities.invokeLater(() -> {
            this.tableModel.addConnection(container.getTableRow());
        });

        // Setup handler for messages within WS stream
        webSocketCreation.proxyWebSocket().registerProxyMessageHandler(
                new WebSocketMessageHandler(
                        this.api,
                        socketId,
                        container.getTableRow().getStreamModel(),
                        this.streamTable,
                        this.interceptionRules,
                        this.matchReplaceRules,
                        new SocketCloseCallback() {
                            @Override
                            public void handleConnectionClosed() {
                                container.getTableRow().setActive(false);
                                tableModel.updateConnection(socketId);
                            }
                        },
                        this.responseMonitor,
                        this.webSocketAutoRepeater,
                        this.socketProvider
                )
        );
    }
}