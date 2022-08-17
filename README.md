# Usage instructions 
These instructions assume you have access to the following resources, and general knowledge of cloud services and infrastructure and Google Workspace.

# Requirements
- AWS account
- AWS SES approved for production sending (sandbox-only is fine for testing)
- GCP access that allows project creation, API access, domain-wide delegation, and service account key creation
- Google Admin access to add a domain-wide delegated app, and administer Rules
- Serverless Framework 2
- Python 3.9

1. In Google Workspace, create at least one [Data Protection Rule](https://admin.google.com/ac/dp/rules/). 
	- Create a rule name
	- Define the scope of the rule. NOTE: Since the Drive DLP Tool policies can be scoped more narrowly than the Google Data Protection Rule, we generally apply the Data Protection Rule to the entire organization and then create more granular response rules or audit-only rules based on Organizational Unit.
	- Select data protection for Google Drive: File created, modified, uploaded or shared.
	- Define the detector types and likelihood thresholds for your desired detection, and where you want to look for that data (i.e. All Content). Note that if you choose multiple detectors in one rule, the rule defaults to AND. Switch this to OR if you are analyzing files with any of the listed detectors.
	- Choose a response action. By default, no action is taken and the activity is simply logged. You can also choose to use Google’s native actions such as Block or Warn on External Share to add additional in-line preventative controls.
	- Save your rule.
2. Define your DLP policies.
	- Define your DLP policies in policy-engine/dlp-policies.json based on the selected detectors. These policies will fire on any rule activity containing a matched detector. 
	- See Writing Policies for in-depth policy writing and fields.
	- Populate config.ini files with your parameters.
3. Install the Serverless framework. Consider following the installation [guide](https://www.serverless.com/framework/docs/getting-started). Google Drive DLP currently uses Serverless Framework version 2. Compatibility with version 3 has not been tested.
	- Install serverless: npm install serverless@2
	- Install the required plugins: serverless plugin install -n serverless-python-requirements
4. Perform your initial [Serverless application setup](https://www.serverless.com/blog/stages-and-environments) by defining providers, stages, and parameters. If your organization already has a CICD pipeline, you may choose to use that for deployment rather than the native Serverless web application. Instructions will vary based on your deployment pipeline.
5. Create a [Google Cloud Project](http://console.cloud.google.com).
	- Enable the Google Drive API and Google Admin SDK APIs.
	- Create service account credentials in JSON format. These credentials must be added to AWS Secrets Manager. 
		- Store a new secret named google-drive-dlp in AWS Secrets Manager
		- Select “Other type of secret”
		- Paste the JSON data from the credentials file into the “plaintext” tab under Key/Value pairs.
		- Save the secret and take note of the ARN.
	- In Google Workspace, enable [domain-wide delegation](https://admin.google.com/ac/owl/domainwidedelegation) for the clientId associated with the service account credentials created in the previous step. The following scopes are required:
		- https://www.googleapis.com/auth/admin.reports.audit.readonly
		- https://www.googleapis.com/auth/admin.directory.user.readonly
		- https://www.googleapis.com/auth/drive
6. In your AWS account
	- Ensure that SES is enabled for production sending (or test in the sandbox)
	- Create DynamoDb table with partition key ​uniqueId (string). By default the table should be named google_dlp_events but this can be updated in config.ini.
	- In your DynamoDb table, enable a stream with View type: New image. Note the ARN of this stream. 
7. Create your Serverless parameters. If you do not want to use the Serverless parameter functionality, you can update the serverless.yml files to reference your ARNs and variables directly.
	- Collector
		- DynamoARN - ARN of the table created
		- SecretValueARN - ARN of the secret created
		- DelegatedUser - Email address of the Google Administrator account that will be used for querying file event history. This account must have access to admin reports and admin directory permissions.
	- Policy engine
		- DynamoARN - See above
		- SecretValueARN - See above
		- DelegatedUser - See above
		- StreamARN - ARN of the event stream. 
	- Response actions
		- DynamoARN - See above
		- SecretValueARN - See above
		- SESARN - ARN of SES
		- StreamARN - See above
		- DelegatedUser - See above
8. Deploy the 3 DLP application services using Serverless Framework. Deployment steps will vary based on your organization’s CICD processes, as well as if and how you choose to configure Serverless’ providers, stages, and parameters.
	- Navigate to the service’s directory (collector, policy-engine, and response-actions)
serverless deploy –stage <stagename>
9. Verify that the collector service is inserting data into the DynamoDB table.
10. Once the Lambda functions are created, go to your DynamoDb table and create two triggers: one associated with each the policy and response-actions Lambda functions.


# Writing Policies

Policies are in JSON formatted and should be ordered by priority, with highest priority at the top for first evaluation. Ex: files should be analyzed for public access with file discovery prior to internal sharing with the domain.

## Examples
Notify administrators when a document containing an SSN is shared publicly by anyone

		{
			"policyName": "Identify public sharing of SSN",
			"policyDescription": "Alert admins when file containing ssn",
			"matchedDetectors": ["US_SOCIAL_SECURITY_NUMBER"],
			"ous": ["*"],
			"type": "anyone",
			"responseActions": ["Send admin notification"]
		}


Send user notification and revoke access when users in the Staff OU share documents containing SSN, credit card numbers with the entire domain

		{
			"policyName": "Identify domain sharing of confidential data",
			"policyDescription": "Revoke access to SSN and CC shared domain-wide",
			"matchedDetectors": ["US_SOCIAL_SECURITY_NUMBER", "CREDIT_CARD_NUMBER"],
			"ous": ["Staff, "Contractors"],
			"type": "domain",
			"responseActions": ["Revoke access", "Send admin notification", "Send user notification"]
		}

 
Additional policy examples can be found in policy-engine/dlp-policies.json. 
 
**Supported Fields**


| Field  | Description | Required | Type | Supported Values |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| policyName  | Name of your policy  | True | string | Any string (ex: Identify public sharing of PII)|
| policyDescription  | Description of your policy  | True | string | Any string |
| matchedDetectors | Name of infoType associated with desired detector(s) | True | list | Any valid Google [DLP infotype](https://cloud.google.com/dlp/docs/infotypes-reference) ex: ["US_SOCIAL_SECURITY_NUMBER", "US_BANK_ROUTING_MICR"]|
| ous | Google Organizational Unit (OU) | True | list | “*” or a Google Workspace OU path.|
| allowFileDiscovery | Only trigger violation if file discovery (search for file publicly or in domain) is enabled | False | bool | True, False |
| type | User object type to trigger violation | False | string | domain, group, user, anyone|
| role | Document role to trigger violation | False | string | reader, viewer, writer, commenter, owner, organizer, fileOrganizer |
| displayName | Display name to trigger violation | False | string | any
