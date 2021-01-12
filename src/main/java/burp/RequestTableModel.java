package burp;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;

import javax.swing.table.AbstractTableModel;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.logging.Logger;

public class RequestTableModel extends AbstractTableModel {
    private final List<HeaderEntry> headers = new ArrayList<>();
    private final List<Map<String, String>> values = Collections.synchronizedList(new ArrayList<>());
    private final Logger logger = Logger.getLogger(BurpExtender.EXTENSION_NAME);
    private final List<String> primaryColumns = new ArrayList<>();
    private boolean primaryColumnMode = false;
    private static final String ORDER_SYMBOL = "#";

    public RequestTableModel(String jsonPath) throws JsonParseException, IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root;
        if (jsonPath == null) {
            root = mapper.readTree(getClass().getClassLoader().getResourceAsStream("template.json"));
        }
        else {
            root = mapper.readTree(new File(jsonPath));
        }
        JsonNode valuesNode = root.get("values");
        JsonNode headersNode = root.get("headers");


        boolean haveOrder = false;
        headers.addAll(mapper.readValue(headersNode.toString(), new TypeReference<List<HeaderEntry>>() {}));
        for (HeaderEntry entry: headers) {
            if (entry.getName().equals(ORDER_SYMBOL)) {
                haveOrder = true;
            }
        }
        if (!haveOrder) {
            HeaderEntry orderEntry = new HeaderEntry();
            orderEntry.setName(ORDER_SYMBOL);
            orderEntry.setEditable(false);
            orderEntry.setPreferredWidth(50);
            headers.add(0, orderEntry);
        }
        // there is no value node so json file is only a template
        if (valuesNode != null) {
            values.addAll(mapper.readValue(valuesNode.toString(), new TypeReference<List<Map<String, String>>>() {}));
        }
    }

    public void setPrimaryColumns(String names) {
        String[] columnNames = names.split(",");
        primaryColumns.clear();
        for (String name: columnNames) {
            primaryColumns.add(name.trim());
        }
    }

    public void enablePrimaryColumn() {
        this.primaryColumnMode = true;
    }

    public void disablePrimaryColumn() {
        this.primaryColumnMode = false;
    }

    public boolean containRow(Map<String, String> newRow) {
        return containRow(newRow, this.primaryColumns);
    }

    public boolean containRow(Map<String, String> newRow, List<String> columnNames) {
        for (Map<String, String> row: values) {
            for (String name: columnNames) {
                String value = row.get(name);
                if (value != null && value.equals(newRow.get(name))) {
                    return true;
                }
            }
        }
        return false;
    }

    public void removeRow(int row) {
        values.remove(row);
        updateRowsOrderNo();
        fireTableDataChanged();
    }

    public void removeRow(Map<String, String> row) {
        values.remove(row);
        updateRowsOrderNo();
        fireTableDataChanged();
    }

    public Map<String, String> getRow(int row) {
        return values.get(row);
    }

    private void updateRowsOrderNo() {
        int count = 1;
        for (Map<String, String> row: values) {
            row.put(ORDER_SYMBOL, String.valueOf(count));
            count++;
        }
    }

    public boolean addRow(Map<String, String> value) {
        boolean result = true;
        if (!this.primaryColumnMode) {
            value.put(ORDER_SYMBOL, String.valueOf(values.size() + 1));
            values.add(value);
        }
        else {
            if (containRow(value)) {
                result = false;
            }
            else {
                value.put(ORDER_SYMBOL, String.valueOf(values.size() + 1));
                values.add(value);
            }
        }
        return result;
    }

    public boolean addRow(IHttpRequestResponse message, IExtensionHelpers helpers) {
        Map<String, String> row = newRow(message, helpers);
        return addRow(row);
    }

    public Map<String, String> newRow(IHttpRequestResponse message, IExtensionHelpers helpers) {
        Map<String, String> row = new HashMap<>();
        TypeInformation info = new TypeInformation(message, helpers);
        String value;

        for (HeaderEntry entry : this.headers) {
            if (entry.getName().equals(ORDER_SYMBOL)) {
                continue;
            }
            value = info.getValue(entry.getType());
            row.put(entry.getName(), value);
        }

        return row;
    }

    @Override
    public int getRowCount() {
        return values.size();
    }

    @Override
    public int getColumnCount() {
        return headers.size();
    }

    @Override
    public Object getValueAt(int row, int column) {
        return values.get(row).get(headers.get(column).getName());
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return headers.get(columnIndex).getEditable();
    }

    @Override
    public String getColumnName(int column) {
        return headers.get(column).getName();
    }

    @Override
    public void setValueAt(Object newVal, int row, int col) {
        values.get(row).put(headers.get(col).getName(), newVal.toString());
    }

    public int getPreferredColumnWidth(int column) {
        return headers.get(column).getPreferredWidth();
    }

    public boolean isColumnVisitable(int column) {
        return headers.get(column).getVisitable();
    }

    public String toJson() throws JsonProcessingException {
        String result = "";
        ObjectMapper mapper = new ObjectMapper();

        String headers = mapper.writeValueAsString(this.headers);
        String values = mapper.writeValueAsString(this.values);
        result += "{";
        result += "\"headers\": " + headers;
        result += ",\n\"values\": " + values;
        result += "}\n";

        return result;
    }

    public String toCsv() throws JsonProcessingException {
        String jsonContent = toJson();
        JsonNode jsonTree = new ObjectMapper().readTree(jsonContent).get("values");
        CsvSchema.Builder csvSchemaBuilder = new CsvSchema.Builder();
        for (HeaderEntry entry: headers) {
            csvSchemaBuilder.addColumn(entry.getName());
        }
        CsvSchema csvSchema = csvSchemaBuilder.build().withHeader();
        CsvMapper csvMapper = new CsvMapper();
        return csvMapper.writerFor(JsonNode.class).with(csvSchema.withEscapeChar(',')).writeValueAsString(jsonTree);
    }
}

class HeaderEntry {
    private String name = "";
    private boolean editable = true;
    private boolean visitable = true;
    private String type = "";
    private int preferredWidth = 0;
    @JsonIgnore
    private static List<String> validTypes = null;
    @JsonIgnore
    private static final Logger logger = Logger.getLogger(BurpExtender.EXTENSION_NAME);

    @JsonSetter("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonGetter("name")
    public String getName() {
        return this.name;
    }

    @JsonSetter("visitable")
    public void setVisitable(boolean ok) {
        this.visitable = ok;
    }

    @JsonGetter("visitable")
    public boolean getVisitable() {
        return this.visitable;
    }

    @JsonSetter("editable")
    public void setEditable(boolean editable) {
        this.editable = editable;
    }

    @JsonGetter("editable")
    public boolean getEditable() {
        return this.editable;
    }

    @JsonSetter("preferredWidth")
    public void setPreferredWidth(int width) {
        this.preferredWidth = width;
    }

    @JsonSetter("type")
    public void setType(String type) {
        boolean ok = false;
        // Cache all defined types
        if (validTypes == null) {
            validTypes = new ArrayList<>();
            // Use reflection to get all defined types
            for (Field field: TypeInformation.class.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())
                    && Modifier.isFinal(field.getModifiers())
                    && Modifier.isPublic(field.getModifiers())) {
                   validTypes.add(field.getName());
                }
            }
        }

        for (String name: validTypes) {
            if (name.equals(type)) {
                this.type = type;
                ok = true;
                break;
            }
        }

        // Set this.type to empty if it can not map
        if (!ok) {
            this.type = "";
        }
    }

    @JsonGetter("type")
    public String getType() {
        return this.type;
    }

    @JsonGetter("preferredWidth")
    public int getPreferredWidth() {
        return this.preferredWidth;
    }
}
