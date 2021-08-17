# Mail_to_TheHive
Fill TheHive cases from mail messages

These are a set of scripts to transform mail message in TheHive cases, other scripts available don't manage template based on regexp so we decide to write our own connector.

# IMPORTANT
This is only a POC, just some code to make things works. Maybe the best language was Python but we're more skilled in PHP so we choose it.

There're two operating mode:
IMAP: using crontab we check an inbox, retrieve mail, detect template, extract observable and create case to TheHive
POST: case data come from POST request *

* we're no more able to use IMAP for certain customer as policy deny it. We create with Google script a simple connector that send us by POST the content of mail message of Gmail Inbox.

# TEMPLATE SELECTOR
