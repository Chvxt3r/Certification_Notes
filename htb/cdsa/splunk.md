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

