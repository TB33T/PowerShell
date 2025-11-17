#TrevorB - 3/27/2025
#script that uses robocopy to copy data from the \\$server\$drive drive to E:\Archive
#reference https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
#/MIR - mirrors the directory tree
#/COPY:DAT - copies Data, Attributes, & Timestamps
#/R:1 - retries 1 time on failed copies
#/MT - multi-threaded copies
#/ipg:<n> - Specifies the inter-packet gap to free bandwidth on slow lines, 1000 milliseconds = 1 second
#/xx - Excludes extra files and directories present in the destination but not the source. Excluding extra files doesn't delete files from the destination
#/LOG+: - writes the status output to the log file as unicode text(appends output to the existing log file)
#/NP - progress of copying will not be displayed
robocopy '\\$server\$drive' 'E:\Archive' /MIR /COPY:DAT /R:1 /MT /xx /LOG+:C:\Users\trevor.brunner\Documents\robolog_$server-$Archive.log
