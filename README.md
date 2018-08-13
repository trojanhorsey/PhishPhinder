

I developed PhishPhinder in response to our migration to O365 at the organization in which I work. It was quite the process to identify phishing messages that had slipped through the permiter, find them in O365, purge them, block the IOCs in the proxy, repeat the same steps for our on-prem 2007 exchange server, and then notify users. Thus, I created a PowerShell tool that does all of this for you.

Be sure to modify the variables at the top of the script so that it will function properly within your environment.

IMPORTANT: Exchange 2007 management shell must be installed on your machine before proceeding! If not, PhishPhinder will not be able to search the on-prem environment. Please download and install the shell before proceeding. If your organization does not use Exchange 2007 (hopefully not), feel free to delete the function from PhishPhinder as needed.

Review the message to ensure it is in fact a phishing campaign

Now, retrieve the following details from the message:
    The URL of the phishing site (Do this by hovering over the link and making a note of the domain. Be very careful not 
    to click the message on accident!)
    The subject line
    The sender address
    The date it was sent

Using PhishPhinder

After the script is launched you will be presented with the main menu. Press '1' and hit Enter to continue.


Follow the instructions presented in each step and ensure that you format your input exactly as shown in each example so 
that the search works correctly.
NOTE: When entering the earliest and latest dates, be sure to provide a buffer of a day or so to catch any stragglers 
that may have been delivered from the same campaign.


After you hit enter the root domain at the last step and hit Enter, the script will block the website and then prompt you 
for your credentials. Enter them in the prompt and proceed
NOTE: Your credentials must be entered as <user>@domain.com so that O365 knows to look at our instance of Exchange Online


The script will begin running and look for hits in our O365 environment. Once the search is complete, you will be prompted
to verify whether or not the results appear correct. Please review the results carefully as proceeding will purge the 
messages from users' inboxes!


After verifying the results, select 'Y' to continue and purge the messages from the targeted inboxes.


After the O365 results are purged, PhishPhinder will then search for hits in our legacy, on-prem environment. If results 
are returned they will be outputted to the terminal as well for verification. If not, you will receive the following prompt 
to continue.

After you hit enter to continue, PhishPhinder will send out a Threat Alert to the affected users and an investigative 
summary will be compiled and delivered to the address you have defined.

