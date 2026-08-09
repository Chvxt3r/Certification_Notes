# Architecture

![splunk architecture](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/218/101.png)

![splunk architecture2](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/218/102.png)

# SPL (Splunk Processing Languarge)
## Basic Searching
* `search` commmand is implicit in the commands, but can be included.
* Supports Boolean operators (`AND`, `OR`, and `NOT`)

```spl
# Search the main index for all events containing the word "Unknown"
index="main" "UNKNOWN"

# Adding a wildcard to get all events containing "uknown" anywhere in the event data
index="main" "UNKNOWN*"
```
## Fields and Comparison Operators
* Splunk automatically identifies certain data as fields (`source`, `sourcetype`, `host`, etc)
* Users can manually define additional fields
* Fields can be used with comparison operators (`=`, `!=`, `<`, `>`, `<=`, `>=`) to increase precision
```spl
# Search the main index for all events that do not have the EventCode value 1
index="main" EventCode!=1
```
## The `fields` command
* Specifies which fields should be included or excluded from the search results.
```spl
# Retrieve all process creation events (EventCode=1) from the main index from the Windows event log (sourcetype="WinEventLog:Sysmon") and hide the "User" field.
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```
## The `table` command
* Presents results in tabular format
```spl
# Returns Process creations events (EventCode=1) from the main index sourced from Sysmon and display in a table with the time, host, and Image (program executable)
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```
