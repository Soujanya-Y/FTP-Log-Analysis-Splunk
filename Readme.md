# Analyzing FTP Log Files Using Splunk SIEM

## Introduction
FTP (File Transfer Protocol) log files contain valuable information about file transfers within a network. Analyzing FTP logs using Splunk SIEM enables security professionals to monitor file transfer activities, detect anomalies, and identify potential security threats.

## Project Overview
In this project, we will upload sample FTP log files to Splunk SIEM and perform various analyses to gain insights into FTP activity within the network.

## Prerequisites
Before starting the project, ensure the following:
- Splunk instance is installed and configured.
- FTP log data sources are configured to forward logs to Splunk.

## Steps to Upload Sample FTP Log Files to Splunk SIEM

### 1. Prepare Sample FTP Log Files
- Obtain sample [FTP log files](https://www.secrepo.com/maccdc2012/ftp.log.gz) in a suitable format (e.g., text files).
- Ensure the log files contain relevant FTP events, including timestamps, source IP, username, commands, filenames, etc.
- Save the sample log files in a directory accessible by the Splunk instance.

### 2. Upload Log Files to Splunk
- Log in to the Splunk web interface.
- Navigate to **Settings** > **Add Data**.
- Select **Upload** as the data input method.

### 3. Choose File
- Click on **Select File** and choose the sample FTP log file you prepared earlier.

### 4. Set Source Type
- In the **Set Source Type** section, specify the source type for the uploaded log file.
- Choose the appropriate source type for FTP logs (e.g., `ftp` or a custom source type if applicable).

### 5. Review Settings
- Review other settings such as index, host, and sourcetype.
- Ensure the settings are configured correctly to match the sample FTP log file.

### 6. Click Upload
- Once all settings are configured, click on the **Review** button.
- Review the settings one final time to ensure accuracy.
- Click **Submit** to upload the sample FTP log file to Splunk.

### 7. Verify Upload
- After uploading, navigate to the search bar in the Splunk interface.
- Run a search query to verify that the uploaded FTP events are visible.


## Steps to Analyze FTP Log Files in Splunk SIEM

### 1. Search for FTP Events   
- Open Splunk interface and navigate to the search bar.
- Enter the following search query to retrieve FTP events
```
source="ftp.log" host="SoujanyaPC" sourcetype="ftplog"
```
[Raw_ftp_splunk_log](Raw_ftp_splunk_log.png)
- Here is the breakdown of the fileds in the ftplogs
-  [1] Timestamp
-  [2] Session ID
-  [3] Source IP
-  [4] Source Port
-  [5] Destination IP
-  [6] Destination Port
-  [7] FTP Username
-  [8] FTP Password / Client string
-  [9] FTP Command
-  [10] FTP Command Argument
-  [11-13] File Details (filename, MIME type, size)
-  [14] FTP Response Code
-  [15] FTP Response Message
-  [16] Direction Flag (T or F)
-  [17] Data Transfer Source IP
-  [18] Data Transfer Destination IP
-  [19] Data Transfer Port
-  [20] File hash or identifier

### 2.  Extract Relevant Fields
- Use Splunk's field extraction capabilities or regular expressions to extract these fields for better analysis.
```
| rex field=_raw "^(?<timestamp>\d+\.\d+)\t(?<session_id>\S+)\t(?<src_ip>\d+\.\d+\.\d+\.\d+)\t(?<src_port>\d+)\t(?<dst_ip>\d+\.\d+\.\d+\.\d+)\t(?<dst_port>\d+)\t(?<username>[^\t]+)\t(?<password>[^\t]*)\t(?<ftp_command>[^\t]+)\t(?<command_arg>[^\t]*)\t(?<file_type>[^\t]*)\t(?<file_size>[^\t]*)\t(?<response_code>\d+)\t(?<response_msg>[^\t]*)\t(?<direction>[TF\-]*)\t(?<data_src_ip>[^\t]*)\t(?<data_dst_ip>[^\t]*)\t(?<data_port>[^\t]*)\t(?<file_hash>.*)$"
"
```

Explanation:
- `^`: Start of the line.
-  timestamp	\d+\.\d+
-  session_id	\S+
-  src_ip / dst_ip	\d+\.\d+\.\d+\.\d+
-  src_port / dst_port / data_port	\d+
-  username / ftp_command /password / command_arg	[^\t]+
-  response_code	\d+
-  response_msg	[^\t]+
-  direction	[TF\-]
-  file_hash	.* (can be - or a real hash)

[Field_extraction_ftp_splunk_log.png](field_extraction_ftp_splunk_log.png)


### 3. Analyze File Transfer Activity
- Determine the frequency and volume of file transfers.
```
source="ftp.log" host="SoujanyaPC" sourcetype="ftplog"
| rex field=_raw "^(?<timestamp>\d+\.\d+)\t(?<session_id>\S+)\t(?<src_ip>\S+)\t(?<src_port>\d+)\t(?<dst_ip>\S+)\t(?<dst_port>\d+)\t(?<username>[^\t]+)\t(?<password>[^\t]*)\t(?<ftp_command>[^\t]+)\t(?<command_arg>[^\t]*)\t(?<file_type>[^\t]*)\t(?<file_size>[^\t]*)\t(?<response_code>\d+)\t(?<response_msg>[^\t]*)\t(?<direction>[TF\-]*)\t(?<data_src_ip>[^\t]*)\t(?<data_dst_ip>[^\t]*)\t(?<data_port>[^\t]*)\t(?<file_hash>.*)$"
| where ftp_command="RETR" OR ftp_command="STOR"
| eval file_size=if(file_size=="-", 0, tonumber(file_size))
| eval _time=strptime(timestamp, "%s.%6N")
| timechart span=1h count as "Transfer Count", sum(file_size) as "Total Bytes Transferred"

```
[Frequency_vs_Volume.png](Frequency_vs_Volume.png)
- Identify top users or IP addresses involved in file transfers.
```
source="ftp.log" host="SoujanyaPC" sourcetype="ftplog"
| rex field=_raw "^(?<timestamp>\d+\.\d+)\t(?<session_id>\S+)\t(?<src_ip>\S+)\t(?<src_port>\d+)\t(?<dst_ip>\S+)\t(?<dst_port>\d+)\t(?<username>[^\t]+)\t(?<password>[^\t]*)\t(?<ftp_command>[^\t]+)\t(?<command_arg>[^\t]*)\t(?<file_type>[^\t]*)\t(?<file_size>[^\t]*)\t(?<response_code>\d+)\t(?<response_msg>[^\t]*)\t(?<direction>[TF\-]*)\t(?<data_src_ip>[^\t]*)\t(?<data_dst_ip>[^\t]*)\t(?<data_port>[^\t]*)\t(?<file_hash>.*)$"
| where ftp_command="RETR" OR ftp_command="STOR"
| eval file_size=if(file_size=="-", 0, tonumber(file_size))
| stats count as transfer_count sum(file_size) as total_bytes by username
| sort - transfer_count
| head 10

```
[Topusers.png](Topusers.png)
- Analyze the types of files being transferred (e.g., documents, executables, archives).
```
source="ftp.log" host="SoujanyaPC" sourcetype="ftplog"
| rex field=_raw "^(?<timestamp>\d+\.\d+)\t(?<session_id>\S+)\t(?<src_ip>\S+)\t(?<src_port>\d+)\t(?<dst_ip>\S+)\t(?<dst_port>\d+)\t(?<username>[^\t]+)\t(?<password>[^\t]*)\t(?<ftp_command>[^\t]+)\t(?<command_arg>[^\t]*)\t(?<file_type>[^\t]*)\t(?<file_size>[^\t]*)\t(?<response_code>\d+)\t(?<response_msg>[^\t]*)\t(?<direction>[TF\-]*)\t(?<data_src_ip>[^\t]*)\t(?<data_dst_ip>[^\t]*)\t(?<data_port>[^\t]*)\t(?<file_hash>.*)$"
| where ftp_command="RETR" OR ftp_command="STOR"
| eval file_type=if(file_type=="-" OR isnull(file_type), "unknown", file_type)
| stats count as transfer_count sum(eval(if(file_size=="-", 0, tonumber(file_size)))) as total_bytes by file_type
| sort - transfer_count
```
[FileTypes.png](FileTypes.png)

### 4. Detect Anomalies
- Look for unusual patterns in file transfer activity.
```
source="ftp.log" host="SoujanyaPC" sourcetype="ftplog"
| rex field=_raw "^(?<timestamp>\d+\.\d+)\t(?<session_id>\S+)\t(?<src_ip>\S+)\t(?<src_port>\d+)\t(?<dst_ip>\S+)\t(?<dst_port>\d+)\t(?<username>[^\t]+)\t(?<password>[^\t]*)\t(?<ftp_command>[^\t]+)\t(?<command_arg>[^\t]*)\t(?<file_type>[^\t]*)\t(?<file_size>[^\t]*)\t(?<response_code>\d+)\t(?<response_msg>[^\t]*)\t(?<direction>[TF\-]*)\t(?<data_src_ip>[^\t]*)\t(?<data_dst_ip>[^\t]*)\t(?<data_port>[^\t]*)\t(?<file_hash>.*)$"
| where ftp_command="RETR" OR ftp_command="STOR"
| eval file_size=if(file_size=="-", 0, tonumber(file_size))
| eval _time=strptime(timestamp, "%s.%6N")
| timechart span=1h sum(file_size) as total_bytes
| anomalydetection total_bytes

```
[AnomalyDetection.png](AnomalyDetection.png)

- Analyze sudden spikes or drops in file transfer volume.
```
source="ftp.log" host="SoujanyaPC" sourcetype="ftplog"
| rex field=_raw ...
| where ftp_command="RETR" OR ftp_command="STOR"
| eval file_size=if(file_size=="-", 0, tonumber(file_size))
| timechart span=1h sum(file_size) as volume by username
| anomalydetection *
```  
- Investigate file transfers to or from suspicious IP addresses.
- Use statistical analysis or machine learning models to detect anomalies.

### 5. Monitor User Behavior
- Monitor user behavior during file transfers.
- Identify users with multiple failed login attempts or unauthorized access attempts.
- Analyze user activity patterns and deviations from normal behavior.

## Conclusion
Analyzing FTP log files using Splunk SIEM provides valuable insights into file transfer activities within a network. By monitoring FTP events, detecting anomalies, and correlating with other logs, organizations can enhance their security posture and protect against various cyber threats.


