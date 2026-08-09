# Architecture

![splunk architecture](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/218/101.png)

![splunk architecture2](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/218/102.png)

# SPL (Splunk Processing Language) Commands and Searches
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

## `lookup`
* Lookup table (csv) has to be added in the splunk settings for this to work. (Settings -> Lookups -> Lookup Table Files -> New Look Table File)
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | eval filename=mvdedup(split(Image, "\\")) | eval filename=mvindex(filename, -1) | eval filename=lower(filename) | lookup malware_lookup.csv filename OUTPUTNEW is_malware | table filename, is_malware | dedup filename, is_malware
```
** `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1`: This command is the search criteria. It is pulling from the `main` index where the sourcetype is `WinEventLog:Sysmon` and the `EventCode` is `1`. The Sysmon `EventCode` of `1` indicates a process creation event.  
** `| eval filename=mvdedup(split(Image, "\\"))`: This command is splitting the `Image` field, which contains the file path, into multiple elements at each backslash and making it a multivalue field. The `mvdedup` function is used to eliminate any duplicates in this multivalue field.  
** `| eval filename=mvindex(filename, -1)`: Here, the `mvindex` function is being used to select the last element of the multivalue field generated in the previous step. In the context of a file path, this would typically be the actual file name.  
** `| eval filename=lower(filename)`: This command is taking the `filename` field and converting it into lowercase using the lower function. This is done to ensure the search is not case-sensitive and to standardize the data.  
** `| lookup malware_lookup.csv filename OUTPUTNEW is_malware`: This command is performing a lookup operation. The `lookup` command is taking the `filename` field, and checking if it matches any entries in the `malware_lookup.csv` lookup table. If there is a match, it appends a new field, `is_malware`, to the event, indicating whether the process is flagged as malicious.  
** `| table filename, is_malware`: The `table` command is used to format the output, in this case showing only the `filename` and `is_malware` fields in a tabular format.  
** `| dedup filename, is_malware`: This command eliminates any duplicate events based on the `filename` and `is_malware` fields. In other words, if there are multiple identical entries for the `filename` and `is_malware` fields in the search results, the `dedup` command will retain only the first occurrence and remove all subsequent duplicates.  

## `inputlookup`
* Retrieves data froma lookup file without joining it to a search. Basically just displays the contents of a lookup file.
```spl
| inputlookup malware_lookup.csv
```

## `Time Range`
* used to select a time range. (You can also use the time range picker in the web interface)
```spl
# Selecting from index "main" earliest entry should be negative 7 days from now, all events not EventCode 1

index="main" earliest=-7d EventCode !=1
```

## `Transaction`
* Used to group event that share common characteristics into transactions.
* Often used to track sessions or activies that span across multiple events.
```spl
index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) | transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m | table Image |  dedup Image 
```
** `| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m`: `transaction` command is used to group events based on the `Image` field. The grouping is subject to the conditions that it starts with an event where the EventCode is 1, and ends with an event where the EventCode is 3, and the maximum time between them is 1 minute.  
** Basically, this query identies a sequence of activies (process creation followed by a network connection) associated with the same executable or script within a 1 minute window. Presents the results in a table, and ensures the executables/scripts present are unique.   
** ***Valuable in Threat Hunting***  

## Subsearches
* Search nested inside another search
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ] | table _time, Image, CommandLine, User, ComputerName
```
** `NOT`: the main search will exclude the results of the subsearch from it's results.  
** `[ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | top limit=100 Image | fields Image ]`: The subsearch. Fetches the Process Creation events, then uses `top` to return the 100 most common process names.  
** This query can be used to highlight unusal or rare process.  

# How to identify the available data (or, how do I know what to search for?)
## Using SPL
* `eventcount`
    ```spl
    | eventcount summarize=false index=* | table index
    ```
    ** Counts events in all indexes, `summarize=false` display counts for each index separately, `table` displays the table.   
    ** Basically, How do I find the available indexes?  

* `metadata`
    ```spl
    | metadata type=sourcetypes
    ```
    ** `metadata` provides statistics surrounding specified index fields, in this example, sourcetypes.  
    ** basically, How do I find all of the different sourcetypes?  

    ```spl
    # Returns metadata about the sourcetypes
    | metadata type=sourcetypes index=* | table sourcetype
    ```
    ```spl
    # Returns a list of all data sources in the environment
    | metadate type=sourcetypes index=* | table source
    ```
* Finding Fields
```spl
# Returns the raw data in table form for the specifice sourcetype

sourcetype="WinEventLog:Security" | table _raw

# See all fields in a source type, including the non-default fields.
# Generates a table with all fields available in the source type.

sourcetype="WinEventLog:Security" | table *
```
:warning: The above commands can generate a very large table. Better way is below

* Better approach is using the `fields` command
```spl
sourcetype="WinEventLog:Security" | fields Account_Name, EventCode | table Account_Name, EventCode
```

* To see a list of field names only
```spl
# Returns a table that includes every field found in the events returned by the search
# in this case, WinEventLog:Security

sourcetype="WinEventLog:Security" | fieldsummary
```
:warning: Values provided by `fieldsummary` are based on events returned by our search. If you need to see all of them, you're going to have to make sure you have a long enough time range to capture them all.

* How events are distributed over time
```spl
index=* sourcetype=* | bucket _time span=1d | stats count by _time, index, sourcetype | sort - _time
```  
** Sometimes, we might want to know how events are distributed over time. This query retrieves all data `(index=* sourcetype=*)`, then `bucket` command is used to group the events based on the `_time` field into 1-day buckets. The `stats` command then counts the number of events for each day (`_time`), `index`, and `sourcetype`. Lastly, the `sort` command sorts the result in descending order of `_time`.  

* `rare`
```spl
# This command finds the 10 rarest combinations of indexes and sourcetypes

index=* sourcetype=* | rare limit=10, index, sourcetype

# This command finds the 20 least common values of the ParentImage field

index="main" | rare limit=2- useother=f ParentImage
```
* Detailed Summary of fields
```spl
# This search shows a summary of all fields (fieldsummary), filters out fields that appear in less than 100 events (where count < 100), and then displays a table (table) showing the field name, total count, and distinct count.

index=* sourcetype=* | fieldsummary | where count < 100 | table field, count, distinct_count
```
* Using `sistats to explore event diversity
```spl
# This command counts the number of events per index, sourcetype, source, and host, which can provide us a clear picture of the diversity and distribution of our data.

index=* | sistats count by index, sourcetype, source, host
```
```spl
# The rare command can also be used to find uncommon combinations of field values

index=* sourcetype=* | rare limit=10 field1, field2, field3
```
## Leveraging Splunks User interface








# References
[Splunk Command quick reference](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.4/quick-reference/command-quick-reference)
