import json 
import json
import requests

banner = """
Sentinel2ATT&CK v2- Microsoft Sentinel TTPs Coverage
"""
print(banner)

# Configuration Parameters
Azure_AD_Tenant = "TENANTID_HERE"
Client_ID = "CLIENTID_HERE"
Client_Secret = "CLIENTSECRET_HERE"
ResourceGroup = "RG_NAME_HERE"
WorkspaceID = "WORKSPACEID_HERE"
Subscription = "SUBSCRIPTIONID_HERE"


# Get the Access Token
LAW_Access_Url = "https://login.microsoftonline.com/"+Azure_AD_Tenant+"/oauth2/token"
LAW_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
LAW_payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https://api.loganalytics.io&client_secret='+Client_Secret
LAW_Access_response = requests.get(LAW_Access_Url, headers=LAW_headers, data=LAW_payload).json()
LAW_Access_Token = LAW_Access_response["access_token"]
print("[+] Access Token Received Successfully")

LAW_Auth = 'Bearer '+LAW_Access_Token
LAW_headersAD = {
    'Authorization': LAW_Auth}

LAW_Url= "https://api.loganalytics.io/v1/workspaces/"+WorkspaceID+"/query"

# Get the MITRE ATT&CK Techniques from Microsoft Sentinel Alerts
LAW_Payload = {"query": "SecurityAlert| where TimeGenerated > ago(90d)| where isnotempty(Techniques)| summarize count() by Techniques| project Techniques"}
LAW_response = requests.post(LAW_Url, headers=LAW_headersAD, json=LAW_Payload).json()

Sentinel_Techniques = []

for technique in LAW_response["tables"][0]["rows"]:
    Technique = json.loads(technique[0])
    for t in Technique:
        Sentinel_Techniques.append(t)

# Remove Duplicates
Sentinel_Techniques =  list(dict.fromkeys(Sentinel_Techniques))
print("[+] MITRE ATT&CK Techniques were extracted from your Microsoft Sentinel Alerts Successfully")


# Generate MITRE Layer

Layer_Template = {
    "description": "Techniques Covered by Microsoft Sentinel",
    "name": "Techniques Covered by Microsoft Sentinel",
    "domain": "mitre-enterprise",
    "version": "4.5",
    "techniques": 
        [{  "techniqueID": technique, "color": "#5df542"  } for technique in Sentinel_Techniques] 
    ,
    "gradient": {
        "colors": [
            "#ffffff",
            "#5df542"
        ],
        "minValue": 0,
        "maxValue": 1
    },
    "legendItems": [
        {
            "label": "Techniques Covered by Microsoft Sentinel",
            "color": "#ff0000"
        }
    ]
}

json_data = json.dumps(Layer_Template)

with open("Sentinel_Coverage.json", "w") as file:
    json.dump(Layer_Template, file)

print("[+] The MITRE matrix json file 'Sentinel_Coverage.json' was created successfully")
