# API Reporter

A Burp Suite's extension to monitor, save and report tested APIs.

This extension will help you remember APIs you tested in a long time ago, now you have to test them again and export to report.

## Features

- Custom column in table by predefined json file. The column is used to display request information (URL, method, parameters,...)
- Save/import result
- Export to Xlsx (excel) format
- Send request to Repeater
- Send request to API Reporter in Repeater/Proxy history tab
- Auto highlight all requests in Proxy history if they match defined "conditions"

## How to create your own table and columns
- The table can be custom by predefined json. By default, the extension uses the json file in src/main/java/resources/template.json. You can load another json by clicking at Import button in Options tab.
```json
{
  "headers": [
    {"name": "URL", "preferredWidth": 300, "type": "REQUEST_PATH"},
    {"name": "Method", "editable": false, "type": "REQUEST_METHOD"},
    {"name": "Parameters", "preferredWidth": 200, "type": "REQUEST_PARAMS"},
    {"name": "Description", "preferredWidth": 300},
    {"name": "Recommend", "preferredWidth": 300},
    {"name": "Date found", "type": "DATE_NOW"},
    {"name": "Rank", "preferredWidth": 75},
    {"name": "Response body", "preferredWidth": 401, "type": "RESPONSE_BODY"},
    {"name": "Host", "visitable":  false, "type": "REQUEST_HOST"},
    {"name": "Port", "visitable": false, "type": "REQUEST_PORT"},
    {"name": "Protocol", "visitable": false, "type": "REQUEST_PROTOCOL"},
    {"name": "Request bytes", "visitable": false, "type": "REQUEST_BYTES"}
  ]
}
```

- The `headers` is an array contains definitions of columns.
- Each column has its properties:
  - `name`: the name of the column header
  - `preferredWidth`: the width of the column
  - `editable`: make each cell in the column can be edited or not
  - `visitable`: make the column can be visited or not. In the example, the `Host`, `Port`, `Protocol` and `Request bytes` are invisible. Because they are used in Send to Repeater feature, but I don't want them are displayed in the table.
  - `type`: extension will automatically fill value into the cell of column if the column defined `type` value. For example, the column `URL` will be filled the request path. All values of `type` are defined in src/main/java/burp/TypeInformation.java. You can create new type by doing a pull request :D 
  
 ## Report bug, contribution

I always welcome that. Feel free to report bug or pull request to this Github repository.
