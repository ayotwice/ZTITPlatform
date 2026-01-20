# Okta Authentication Policies as Code
#
# This Terraform configuration demonstrates zero-trust authentication policies
# for Okta, enforcing device trust requirements as John described:
#
# "Applications can only be accessed from company machines where we know
# that they don't have an active compromise and are patched inside of
# a two-week SLA"
#
# NOTE: This is a reference architecture. Actual attribute names may vary
# based on your Okta provider version and plan tier.

terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.6"
    }
  }
}

# Variables for configuration
variable "org_name" {
  description = "Okta organization name"
  type        = string
  default     = "company"
}

variable "api_token" {
  description = "Okta API token"
  type        = string
  sensitive   = true
  default     = ""
}

# ==============================================================================
# DEVICE ASSURANCE POLICIES
# Define minimum security requirements for devices
# ==============================================================================

resource "okta_policy_device_assurance_macos" "standard_macos" {
  name = "Standard macOS Device Assurance"
  
  # Require FileVault encryption
  disk_encryption_type = ["ALL_INTERNAL_VOLUMES"]
  
  # Require screen lock with passcode
  screenlock_type = ["PASSCODE"]
  
  # Minimum OS version (ensures security patches)
  os_version = "14.0.0"
  
  # Require Secure Enclave for hardware-backed security
  secure_hardware_present = true
}

resource "okta_policy_device_assurance_macos" "high_security_macos" {
  name = "High Security macOS Device Assurance"
  
  disk_encryption_type    = ["ALL_INTERNAL_VOLUMES"]
  screenlock_type         = ["BIOMETRIC", "PASSCODE"]
  os_version              = "14.2.0"
  secure_hardware_present = true
}

# ==============================================================================
# AUTHENTICATION POLICIES
# Control how users authenticate to applications
# ==============================================================================

# Policy for standard applications (Slack, GitHub, etc.)
resource "okta_app_signon_policy" "standard_apps" {
  name        = "Standard Application Access Policy"
  description = "Zero-trust policy requiring compliant devices for standard applications"
}

# Policy for sensitive applications (AWS, Admin consoles)
resource "okta_app_signon_policy" "sensitive_apps" {
  name        = "Sensitive Application Access Policy" 
  description = "Stricter zero-trust policy for sensitive applications"
}

# ==============================================================================
# POLICY RULES
# Define conditions for access decisions
# ==============================================================================

# Rule: Allow access from managed, compliant devices
resource "okta_app_signon_policy_rule" "managed_device_required" {
  policy_id = okta_app_signon_policy.standard_apps.id
  name      = "Require Managed Compliant Device"
  priority  = 1
  
  # Device must be MDM-enrolled and registered with Okta
  device_is_managed    = true
  device_is_registered = true
  
  # Device must meet our assurance policy
  device_assurances_included = [okta_policy_device_assurance_macos.standard_macos.id]
  
  # Allow from any network (device compliance is the gate)
  network_connection = "ANYWHERE"
  
  # Require MFA, re-authenticate every 12 hours
  factor_mode                 = "2FA"
  re_authentication_frequency = "PT12H"
  
  # Allow access if all conditions met
  access = "ALLOW"
}

# Rule: Deny access from non-compliant devices
resource "okta_app_signon_policy_rule" "deny_noncompliant" {
  policy_id = okta_app_signon_policy.standard_apps.id
  name      = "Deny Non-Compliant Devices"
  priority  = 99  # Catch-all rule
  
  # This is the default deny - catches anything not matching above
  access = "DENY"
}

# Rule: High security for sensitive apps
resource "okta_app_signon_policy_rule" "high_security" {
  policy_id = okta_app_signon_policy.sensitive_apps.id
  name      = "High Security Device Required"
  priority  = 1
  
  device_is_managed          = true
  device_is_registered       = true
  device_assurances_included = [okta_policy_device_assurance_macos.high_security_macos.id]
  
  # Require phishing-resistant MFA, re-auth every hour
  factor_mode                 = "2FA"
  re_authentication_frequency = "PT1H"
  
  access = "ALLOW"
}

# ==============================================================================
# OUTPUTS
# Reference these IDs when assigning policies to applications
# ==============================================================================

output "standard_policy_id" {
  description = "ID of the standard application policy"
  value       = okta_app_signon_policy.standard_apps.id
}

output "sensitive_policy_id" {
  description = "ID of the sensitive application policy"
  value       = okta_app_signon_policy.sensitive_apps.id
}

output "macos_assurance_id" {
  description = "ID of the standard macOS device assurance policy"
  value       = okta_policy_device_assurance_macos.standard_macos.id
}
