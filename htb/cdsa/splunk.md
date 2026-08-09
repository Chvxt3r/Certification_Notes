# Architecture

![splunk architecture](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/218/101.png)

![splunk architecture2](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/218/102.png)

# SPL (Splunk Processing Language)
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
## `fields`
* Specifies which fields should be included or excluded from the search results.
```spl
# Retrieve all process creation events (EventCode=1) from the main index from the Windows event log (sourcetype="WinEventLog:Sysmon") and hide the "User" field.

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```
## `table` 
* Presents results in tabular format
```spl
# Returns Process creations events (EventCode=1) from the main index sourced from Sysmon and display in a table with the time, host, and Image (program executable)

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | table _time, host, Image
```
## `rename`
* Renames a field in the search results
```spl
# Renames image field to Process. Affects all subsequent references

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | rename Image as Process
```
## `dedup`
* removes duplicate events
```spl
# Removes duplicate entries based on the Image field. If the same process (image) is created multiple times, it will appear only once in the results

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | dedup Image
```
## `sort`
* sorts the results
```spl
# Sorts all process creation results in decending order of their timestamps.

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | sort - _time
```
## `stats`
* performs statistical operations
```spl
# returns a table where each row is a unqie comboof timestamp and process

index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | stats count by _time, Image
```
## `chart`
* creates a data visualization based on statistical operations
```spl
# Returns a table where each represents a unique timestamp and each column a unique process.
# Cell values indicate the number of network connection events that occured for each process at that specific time.

index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | chart count by _time, Image
```
## `eval`
* creates or redefines fields
```spl
# Creates a new field (Process_Path) which contains the lowercase version of the Image field.

index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval Process_Path=lower(Image)
```
## `rex`
* extracts new fields from existing ones using regex
```spl
index="main" EventCode=4662 | rex max_match=0 "[^%](?<guid>{.*})" | table guid
```
* `index="main" EventCode=4662` filters the events to those in the main index with the event code equal to 4662
* `rex max_match=0 "[^%](?<guid>{.*})"` uses rex to extract values matchin the patter from the events fields.  
** `{.*}` looks for substrings that begin with `{` and end with `}`  
** `[^%]` ensures that the match does not begin with a `%`  
**  The captured value within the curly braces `{.*}` is assigned to the name capture group `guid`  
** `table guid` displays the extracted GUIDs in the output.  
** `max_match=0` option ensures all occurences are extracted from each event.  
* By default, `rex` only extracts the first occurence. see `max_match=0` above.
