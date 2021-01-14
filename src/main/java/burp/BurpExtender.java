package burp;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.logging.*;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public static final String EXTENSION_NAME = "API Reporter";
    private final Logger logger = Logger.getLogger(EXTENSION_NAME);
    private RequestTableModel tableModel = null;
    private final JTable table = new JTable();
    private ProxyListener highlighter = null;
    private boolean isUseMakeHttpRequest = true;
    private String highlightCondition;
    private boolean isHighlightRequest = false;
    private JTabbedPane extensionPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerContextMenuFactory(this);
        initLogger();

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                highlighter = new ProxyListener(BurpExtender.this.callbacks, tableModel);
                BurpExtender.this.callbacks.registerProxyListener(highlighter);

                if (!loadNewTable(null)) {
                    return;
                }

                table.setAutoCreateRowSorter(true);
                table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

                JScrollPane scrollPanel = new JScrollPane(table);
                scrollPanel.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                scrollPanel.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
                extensionPanel = new JTabbedPane();
                JSplitPane apiPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                apiPanel.setLeftComponent(scrollPanel);

                JPanel optionsPanelRoot = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JPanel optionsPanel = new JPanel();
                JCheckBox cbHighlight = new JCheckBox("Highlight requests in Proxy history by color");
                JCheckBox cbUseMakeHttpRequest = new JCheckBox("Force to send HTTP request to get response in Repeater if there is no response in the editor");
                JCheckBox cbPrimaryColumns = new JCheckBox("Add requests to the table if their values equal to values of columns");
                JTextField tfHighlight = new JTextField(15);
                JTextField tfUniqueColumns = new JTextField(15);
                JPanel buttonsPanel = new JPanel();
                JPanel highlightPanel = new JPanel();
                JPanel uniqueColumnPanel = new JPanel();
                FlowLayout cbLayout = new FlowLayout();
                GridLayout buttonsLayout = new GridLayout(0, 5);
                GridBagLayout optionsLayout = new GridBagLayout();
                GridBagConstraints constraints = new GridBagConstraints();
                JComboBox<ProxyListener.RequestColor> cbbColors = new JComboBox<>();
                JButton exportButton = new JButton("Export to Xlsx");
                JButton saveButton = new JButton("Save table");
                JButton importButton = new JButton("Import table");

                cbUseMakeHttpRequest.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (e.getStateChange() == ItemEvent.SELECTED) {
                            isUseMakeHttpRequest = true;
                        }
                        else if (e.getStateChange() == ItemEvent.DESELECTED) {
                            isUseMakeHttpRequest = false;
                        }
                    }
                });
                cbHighlight.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (e.getStateChange() == ItemEvent.SELECTED) {
                            isHighlightRequest = true;
                            highlightCondition = tfHighlight.getText();
                            tfHighlight.setEnabled(false);
                            highlighter.startHighlight((ProxyListener.RequestColor)cbbColors.getSelectedItem(), highlightCondition);
                            cbbColors.setEnabled(false);
                        }
                        else if (e.getStateChange() == ItemEvent.DESELECTED) {
                            isHighlightRequest = false;
                            cbbColors.setEnabled(true);
                            tfHighlight.setEnabled(true);
                            highlighter.stopHighLight();
                        }
                    }
                });
                cbPrimaryColumns.addItemListener(new ItemListener() {
                    @Override
                    public void itemStateChanged(ItemEvent e) {
                        if (e.getStateChange() == ItemEvent.SELECTED) {
                            BurpExtender.this.tableModel.setPrimaryColumns(tfUniqueColumns.getText());
                            BurpExtender.this.tableModel.enablePrimaryColumn();
                            tfUniqueColumns.setEnabled(false);
                        }
                        else if (e.getStateChange() == ItemEvent.DESELECTED) {
                            BurpExtender.this.tableModel.disablePrimaryColumn();
                            tfUniqueColumns.setEnabled(true);
                        }
                    }
                });

                importButton.addMouseListener(new MouseListener() {
                    @Override
                    public void mouseClicked(MouseEvent e) { }

                    @Override
                    public void mousePressed(MouseEvent e) { }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        final JFileChooser fc = new JFileChooser();
                        fc.setFileFilter(new FileNameExtensionFilter("json file", "json"));
                        int retval = fc.showOpenDialog(BurpExtender.this.extensionPanel);

                        if (retval == JFileChooser.APPROVE_OPTION) {
                            String filePath = fc.getSelectedFile().getAbsolutePath();

                            // Remove highlight if it is enable
                            if (cbHighlight.isSelected()) {
//                                highlighter.stopHighLight(highlightCondition);
                                cbHighlight.setSelected(false);
                            }
                            if (loadNewTable(filePath)) {
                                JOptionPane.showMessageDialog(BurpExtender.this.extensionPanel, "Import success");
                            }
                            else {
                                JOptionPane.showMessageDialog(BurpExtender.this.extensionPanel,
                                                       "Import failed",
                                                          "Error",
                                                               JOptionPane.ERROR_MESSAGE);
                            }

                        }
                    }

                    @Override
                    public void mouseEntered(MouseEvent e) { }

                    @Override
                    public void mouseExited(MouseEvent e) { }
                });
                saveButton.addMouseListener(new MouseListener() {
                    @Override
                    public void mouseClicked(MouseEvent e) { }

                    @Override
                    public void mousePressed(MouseEvent e) { }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        JFileChooser fc = new JFileChooser();
                        fc.setFileFilter(new FileNameExtensionFilter("json file", "json"));
                        int retval = fc.showSaveDialog(BurpExtender.this.extensionPanel);
                        if (retval == JFileChooser.APPROVE_OPTION) {
                            try {
                                String filepath = fc.getSelectedFile().getAbsolutePath();
                                if (!filepath.toLowerCase(Locale.ROOT).endsWith(".json")) {
                                    filepath += ".json";
                                }
                                OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(filepath), StandardCharsets.UTF_8);
                                String jsonContent = BurpExtender.this.tableModel.toJson();
                                writer.write(jsonContent);
                                writer.close();
                            }
                            catch (Exception ex) {
                                logger.severe(ex.getMessage());
                                JOptionPane.showMessageDialog(BurpExtender.this.extensionPanel,
                                                        "Save failed",
                                                        "Error",
                                                        JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    }

                    @Override
                    public void mouseEntered(MouseEvent e) { }

                    @Override
                    public void mouseExited(MouseEvent e) { }
                });
                exportButton.addMouseListener(new MouseListener() {
                    @Override
                    public void mouseClicked(MouseEvent e) { }

                    @Override
                    public void mousePressed(MouseEvent e) { }

                    @Override
                    public void mouseReleased(MouseEvent e) {
                        JFileChooser fc = new JFileChooser();
                        fc.setFileFilter(new FileNameExtensionFilter("xlsx file", "xlsx"));
                        int retval = fc.showSaveDialog(BurpExtender.this.extensionPanel);
                        if (retval == JFileChooser.APPROVE_OPTION) {
                            try {
                                XSSFWorkbook workbook = new XSSFWorkbook();
                                XSSFSheet sheet = workbook.createSheet();
                                RequestTableModel tableModel = BurpExtender.this.tableModel;
                                // Create header
                                Row header = sheet.createRow(0);
                                for (int i = 0; i < tableModel.getColumnCount(); i++) {
                                    if (!tableModel.isColumnVisitable(i)) continue;
                                    Cell cell = header.createCell(i);
                                    cell.setCellValue(tableModel.getColumnName(i));
                                }
                                // Create row
                                for (int i = 0; i < tableModel.getRowCount(); i++) {
                                    Row row = sheet.createRow(1 + i);
                                    for (int col = 0; col < tableModel.getColumnCount(); col++) {
                                        if (!tableModel.isColumnVisitable(i)) continue;
                                        Cell cell = row.createCell(col);
                                        String value = tableModel.getValueAt(i, col).toString();
                                        if (value.length() > 32767) {
                                            value = value.substring(0, 32766);
                                        }
                                        cell.setCellValue(value);
                                    }
                                }

                                String filepath = fc.getSelectedFile().getAbsolutePath();
                                if (!filepath.endsWith(".xlsx")) {
                                    filepath += ".xlsx";
                                }
                                FileOutputStream fileStream = new FileOutputStream(filepath);
                                workbook.write(fileStream);
                                workbook.close();
                                fileStream.close();
                            }
                            catch (Exception ex) {
                                logger.severe(ex.getMessage());
                                JOptionPane.showMessageDialog(BurpExtender.this.extensionPanel, "Failed to export", "Error", JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    }

                    @Override
                    public void mouseEntered(MouseEvent e) { }

                    @Override
                    public void mouseExited(MouseEvent e) {

                    }
                });

                optionsPanelRoot.add(optionsPanel);
                optionsPanel.setBorder(new EmptyBorder(0,20,0,0));
                optionsPanel.setLayout(optionsLayout);

                buttonsLayout.setHgap(10);
                buttonsPanel.setLayout(buttonsLayout);
                buttonsPanel.add(saveButton);
                buttonsPanel.add(importButton);
                buttonsPanel.add(exportButton);

                cbLayout.setHgap(3);
                highlightPanel.setLayout(cbLayout);
                highlightPanel.add(cbHighlight);
                cbbColors.addItem(ProxyListener.RequestColor.GREEN);
                cbbColors.addItem(ProxyListener.RequestColor.CYAN);
                cbbColors.addItem(ProxyListener.RequestColor.RED);
                cbbColors.addItem(ProxyListener.RequestColor.GRAY);
                cbbColors.addItem(ProxyListener.RequestColor.BLUE);
                cbbColors.addItem(ProxyListener.RequestColor.MAGENTA);
                cbbColors.addItem(ProxyListener.RequestColor.PINK);
                cbbColors.addItem(ProxyListener.RequestColor.ORANGE);
                cbbColors.addItem(ProxyListener.RequestColor.YELLOW);
                cbbColors.addItem(ProxyListener.RequestColor.CLEAR);
                highlightPanel.add(cbbColors);
                highlightPanel.add(new JLabel("if its values equal to values of columns:"));
                tfHighlight.setText("URL");
                highlightPanel.add(tfHighlight);
                uniqueColumnPanel.add(cbPrimaryColumns);
                tfUniqueColumns.setText("URL");
                uniqueColumnPanel.add(tfUniqueColumns);

                constraints.fill = GridBagConstraints.VERTICAL;
                constraints.anchor = GridBagConstraints.NORTHWEST;
                constraints.weighty = 1;
                constraints.gridy = 0;
                constraints.gridx = 0;
                optionsPanel.add(buttonsPanel, constraints);
                constraints.gridy = 1;
                optionsPanel.add(highlightPanel, constraints);
                constraints.gridy = 2;
                cbUseMakeHttpRequest.setMargin(new Insets(0, 5, 0, 0));
                optionsPanel.add(cbUseMakeHttpRequest, constraints);
                constraints.gridy = 3;
                optionsPanel.add(uniqueColumnPanel, constraints);

                extensionPanel.addTab("Table", apiPanel);
                extensionPanel.addTab("Options", optionsPanelRoot);

                Action deleteAction = new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        List<Map<String, String>> rows = new ArrayList<>();
                        for (int i: table.getSelectedRows()) {
                            rows.add(tableModel.getRow(table.convertRowIndexToModel(i)));
                        }
                        for (Map<String, String> row: rows) {
                            // TODO: remove highlight deleted row
                            tableModel.removeRow(row);
                        }
                    }
                };
                Action sendRepeaterAction = new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (int i : table.getSelectedRows()) {
                            int index = table.convertRowIndexToModel(i);
                            String host = tableModel.getRow(index).get("Host");
                            String port = tableModel.getRow(index).get("Port");
                            String protocol = tableModel.getRow(index).get("Protocol");
                            String requestString = tableModel.getRow(index).get("Request bytes");

                            if (host != null && port != null && protocol != null && requestString != null) {
                                boolean isHttps = protocol.equals("https");
                                byte[] requestBytes = Base64.getDecoder().decode(requestString);
                                logger.info("Send to repeater: " + host + " " + port + " " + String.valueOf(isHttps));
                                callbacks.sendToRepeater(host, Integer.parseInt(port), isHttps, requestBytes, null);
                            }
                        }
                    }
                };

                JPopupMenu popupMenu = new JPopupMenu();
                JMenuItem deleteItem = new JMenuItem("Delete");
                JMenuItem sendRepeaterItem = new JMenuItem("Send request to Repeater");
                popupMenu.add(deleteItem);
                popupMenu.add(sendRepeaterItem);
                KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);
                deleteItem.setAccelerator(keyStroke);
                deleteItem.addActionListener(deleteAction);
                sendRepeaterItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_R, KeyEvent.CTRL_DOWN_MASK));
                sendRepeaterItem.addActionListener(sendRepeaterAction);
                table.setComponentPopupMenu(popupMenu);
                table.getInputMap().put(keyStroke, "delete");
                table.getActionMap().put("delete", deleteAction);
                table.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_R, KeyEvent.CTRL_DOWN_MASK), "sendRepeater");
                table.getActionMap().put("sendRepeater", sendRepeaterAction);

                callbacks.customizeUiComponent(table);
                callbacks.customizeUiComponent(scrollPanel);
                callbacks.customizeUiComponent(extensionPanel);
                callbacks.customizeUiComponent(apiPanel);

                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        byte context = invocation.getInvocationContext();

        if (context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
            || context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
            || context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            JMenuItem item = new JMenuItem("Send to " + EXTENSION_NAME);
            KeyStroke key = KeyStroke.getKeyStroke(KeyEvent.VK_W, KeyEvent.CTRL_DOWN_MASK);
            ActionListener action = e -> {
                SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() throws Exception {
                        for (IHttpRequestResponse message : invocation.getSelectedMessages()) {
                            IHttpRequestResponse tmpMessage = message;
                            if (message.getResponse() == null && BurpExtender.this.isUseMakeHttpRequest &&
                                    (context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                                            || context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)) {
                                try {
                                    // Extensions should not make HTTP requests in the Swing event dispatch thread
                                    // So I have to create a new thread to run makeHttpRequest
                                    logger.info("Using makeHttpRequest");
                                    tmpMessage = callbacks.makeHttpRequest(message.getHttpService(), message.getRequest());
                                } catch (Exception ex) {
                                    // WARNING: Connection errors, request timeout,...
                                    logger.severe("makeHttpRequest failed " + ex.getMessage());
                                    continue;
                                }
                            }
                            try {
                                if (!tableModel.addRow(tmpMessage, helpers)) {
                                    // TODO: add more selections
                                    logger.info("Row has been existed already!");
                                }
                                // TODO: highlight the request if highlighting is enable
                            }
                            catch (Exception ex) {
                                logger.severe("Add row failed: " + ex.getMessage()
                                        + "\nUrl: " + helpers.analyzeRequest(message).getUrl().toString());
                            }
                        }
                        tableModel.fireTableDataChanged();
                        logger.info("Inserted " + invocation.getSelectedMessages().length
                                + " row, total row is " + tableModel.getRowCount());
                        return null;
                    }
                };
                worker.execute();
            };

            // Set shortcut key for the item
            item.setAccelerator(key);
            item.addActionListener(action);
            menu.add(item);
        }

        return menu;
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return extensionPanel;
    }

    @Override
    public void extensionUnloaded() {
        highlighter.stopHighLight();
    }

    static JFrame getBurpFrame() {
        for (Frame f: Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith("Burp Suite")) {
                return (JFrame)f;
            }
        }
        return null;
    }

    private boolean loadNewTable(String filepath) {
        try {
            tableModel = new RequestTableModel(filepath);
        }
        catch (JsonProcessingException ex) {
            logger.severe("Can not parse template file!\n" + ex.getMessage());
            return false;
        }
        catch (IOException ex) {
            logger.severe("Can not open template file!\n" + ex.getMessage());
            return false;
        }
        table.setModel(tableModel);
        highlighter.setTableModel(tableModel);
        // Set width for each column from TableModel
        for (int column = 0; column < tableModel.getColumnCount(); column++) {
            int width = tableModel.getPreferredColumnWidth(column);
            if (width != 0) {
                table.getColumnModel().getColumn(column).setPreferredWidth(width);
            }
            if (!tableModel.isColumnVisitable(column)) {
                table.getColumnModel().getColumn(column).setWidth(0);
                table.getColumnModel().getColumn(column).setMinWidth(0);
                table.getColumnModel().getColumn(column).setMaxWidth(0);
            }
        }
        return true;
    }

    private void initLogger() {
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.INFO);

        // Remove all existed handlers, avoid to duplicate log
        for (Handler handler: logger.getHandlers()) {
            logger.removeHandler(handler);
        }

        // Redirect all normal logs to Burp
        StreamHandler stdoutStream = new StreamHandler(callbacks.getStdout(), new SimpleFormatter()) {
            @Override
            public synchronized void publish(final LogRecord record) {
                if (record.getLevel() != Level.SEVERE) {
                    super.publish(record);
                    flush();
                }
            }
        };
        logger.addHandler(stdoutStream);

        // Redirect all error logs to Burp
        StreamHandler stderrStream = new StreamHandler(callbacks.getStderr(), new SimpleFormatter()) {
            @Override
            public synchronized void publish(final LogRecord record) {
                if (record.getLevel() == Level.SEVERE) {
                    super.publish(record);
                    flush();
                }
            }
        };
        logger.addHandler(stderrStream);
    }
}

