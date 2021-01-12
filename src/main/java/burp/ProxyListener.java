package burp;

import javax.swing.*;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class ProxyListener implements IProxyListener {
    public enum RequestColor {
        RED("red"),
        ORANGE("orange"),
        YELLOW("yellow"),
        GREEN("green"),
        CYAN("cyan"),
        BLUE("blue"),
        PINK("pink"),
        MAGENTA("magenta"),
        GRAY("gray"),
        CLEAR(null);

        private final String color;
        RequestColor(String color) {
            this.color = color;
        }

        public String toString() {
            return this.color;
        }
    }

    private final IBurpExtenderCallbacks callbacks;
    private RequestColor color = RequestColor.GREEN;
    private boolean enableHighlightProxy = false;
    private final List<String> keywords = new ArrayList<>();
    private RequestTableModel tableModel;
    private List<String> uniqColumns = new ArrayList<>();
    private Logger logger = Logger.getLogger(BurpExtender.EXTENSION_NAME);

    public ProxyListener(IBurpExtenderCallbacks callbacks, RequestTableModel tableModel) {
        this.tableModel = tableModel;
        this.callbacks = callbacks;
    }

    public void setTableModel(RequestTableModel model) {
        this.tableModel = model;
    }

    private void setRequestColor(IHttpRequestResponse message) {
        message.setHighlight(this.color.toString());
    }

    private void highlightProxyHistory() {
        for (IHttpRequestResponse message: this.callbacks.getProxyHistory()) {
            highlightRequest(message);
        }
    }

    public void highlightRequest(IHttpRequestResponse message) {
        try {
            IExtensionHelpers helpers = callbacks.getHelpers();
            Map<String, String> row = tableModel.newRow(message, helpers);
            if (tableModel.containRow(row, uniqColumns)) {
                setRequestColor(message);
            }
        }
        catch (Exception ex) {
            logger.severe("Highlight failed: "
                    + message.getHttpService().toString()
                    + "\nMessage: " + ex.getMessage());
        }
    }

    public void startHighlight(RequestColor color, String condition) {
        this.color = color;
        for (String name: condition.split(",")) {
            uniqColumns.add(name.trim());
        }
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                highlightProxyHistory();
                return null;
            }
        };
        worker.execute();
        this.enableHighlightProxy = true;
    }

    public void stopHighLight() {
        this.enableHighlightProxy = false;
        this.color = RequestColor.CLEAR;
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                highlightProxyHistory();
                uniqColumns.clear();
                return null;
            }
        };
        worker.execute();
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (this.enableHighlightProxy && messageIsRequest) {
            if (tableModel.containRow(tableModel.newRow(message.getMessageInfo(), callbacks.getHelpers()), uniqColumns)) {
                setRequestColor(message.getMessageInfo());
            }
        }
    }
}
