# Okta Device Trust Rules
#
# Additional Terraform resources for device trust integration
# with Kandji/Iru MDM and CrowdStrike EDR.

# Network Zones - Define trusted networks
resource "okta_network_zone" "corporate_vpn" {
  name = "Corporate VPN"
  type = "IP"
  
  gateways = [
    "10.0.0.0/8",
    "192.168.0.0/16",
  ]
  
  usage = "POLICY"
}

resource "okta_network_zone" "office_network" {
  name = "Office Networks"
  type = "IP"
  
  gateways = [
    "203.0.113.0/24",  # Example office IP range
  ]
  
  usage = "POLICY"
}

# Behavior Detection - Detect anomalous access patterns
resource "okta_behavior" "new_device" {
  name          = "New Device Access"
  type          = "ANOMALOUS_DEVICE"
  number_of_authentications = 0
  
  # Trigger when user accesses from a device they haven't used before
}

resource "okta_behavior" "new_location" {
  name          = "New Geographic Location"
  type          = "ANOMALOUS_LOCATION"
  number_of_authentications = 0
  
  # Trigger when user accesses from unusual location
}

resource "okta_behavior" "velocity_anomaly" {
  name          = "Impossible Travel"
  type          = "VELOCITY"
  velocity      = 805  # km/h - impossible to travel faster
  
  # Detect impossible travel scenarios
}

# Device Trust Integration Points
# These would be configured in Okta Admin Console but documented here for GitOps

# Kandji/Iru Integration
# - Endpoint: https://company.api.kandji.io/api/v1
# - Sync device compliance status every 15 minutes
# - Map Kandji Blueprint compliance to Okta device trust

# CrowdStrike Integration  
# - Endpoint: Configured via Okta device trust partner
# - Real-time threat status sync
# - Block access on active threat detection

# Custom device trust attributes (set via API from our Trust Broker)
# okta_user_schema_property for custom device attributes would go here

# Application Assignments - Which apps use which policy
# This maps applications to their authentication policies

locals {
  # Standard apps - use standard policy
  standard_apps = [
    "slack",
    "google_workspace",
    "github",
    "notion",
    "1password",
  ]
  
  # Sensitive apps - use high security policy
  sensitive_apps = [
    "aws_console",
    "okta_admin",
    "pagerduty",
    "terraform_cloud",
  ]
}

# Note: In production, you would use okta_app_signon_policy_assignment
# to assign policies to applications. Example:
#
# resource "okta_app_signon_policy_assignment" "slack" {
#   app_id    = data.okta_app.slack.id
#   policy_id = okta_app_signon_policy.standard_apps.id
# }
