<#
.SYNOPSIS
    Generates a STIG Viewer 3.x (.cklb) file for VMware Cloud Foundation vSphere ESX 9.x
    based on the STIG Readiness Guide Version 1 Release 1 rule set.

.DESCRIPTION
    Since no official DISA STIG exists for ESXi 9.x, this script constructs a .cklb
    using the VCFE-9X rule IDs and titles extracted from the VCF 9.x SRG PowerCLI
    remediation content. Severity (CAT) assignments are best-effort based on control type.
    All findings default to Not_Reviewed.

    Fields per rule:
      - CheckText    : Manual UI verification steps followed by PowerCLI equivalent
      - FixText      : Manual UI remediation steps followed by PowerCLI equivalent
      - Vuln_Discuss : Detailed vulnerability discussion matching STIG verbosity

.NOTES
    File Name  : New-ESXi9xCKLB.ps1
    Version    : 1.2.0
    Output     : VMware_vSphere_ESX_9x_SRG_V1R1_<hostname>.cklb

.PARAMETER Hostname
    Target hostname to embed in the CKLB asset info.

.PARAMETER HostIP
    Target host IP address to embed in the CKLB asset info.

.PARAMETER OutputPath
    Directory to write the .cklb file to. Defaults to current directory.

.EXAMPLE
    .\New-ESXi9xCKLB.ps1 -Hostname "esxi01.lab.local" -HostIP "10.0.0.10" -OutputPath "C:\STIGs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Hostname = "HOSTNAME",

    [Parameter(Mandatory = $false)]
    [string]$HostIP = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "."
)

$rules = @(
    @{
        RuleID       = "VCFE-9X-000005"
        Title        = "The ESX host must enforce the limit of three consecutive invalid logon attempts by a user."
        Severity     = "medium"
        GroupTitle   = "Account Lockout"
        Vuln_Discuss = "By limiting the number of failed logon attempts, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account. Once the configured number of attempts is reached, the account is locked by the ESXi host for a defined period of time. Setting this value to 3 aligns with DoD policy and common industry best practices for account lockout. Without an account lockout threshold, an attacker has unlimited attempts to guess a password, significantly increasing the risk of unauthorized access to the system. This control supports the requirements of NIST SP 800-53 AC-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Security.AccountLockFailures and verify the value is set to 3.

If the value is not 3, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.AccountLockFailures

If the value returned is not 3, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Security.AccountLockFailures, and set the value to 3.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000006"
        Title        = "The ESX host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via the Direct Console User Interface (DCUI)."
        Severity     = "medium"
        GroupTitle   = "Consent Banner DCUI"
        Vuln_Discuss = "Failure to display the DOD logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources. The DOD Notice and Consent Banner serves multiple legal purposes: it informs the user that the system is owned by the U.S. Government and that all activity may be monitored and recorded; it notifies users that by accessing the system they consent to such monitoring; and it warns that unauthorized use of the system is subject to criminal and civil penalties. The banner must be displayed on all access methods including the DCUI to ensure consistent enforcement of legal and policy requirements. This control supports the requirements of NIST SP 800-53 AC-8."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Annotations.WelcomeMessage and verify the value contains the Standard Mandatory DOD Notice and Consent Banner text.

If the banner is not configured or does not contain the required DOD text, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Select-Object -ExpandProperty Value

If the value is empty or does not contain the DOD Notice and Consent Banner text, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Annotations.WelcomeMessage, and set the value to the Standard Mandatory DOD Notice and Consent Banner text as defined in DoD policy.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value '<DOD_banner_text>' -Confirm:`$false

Note: Replace <DOD_banner_text> with the organizationally approved DOD Notice and Consent Banner."
    },
    @{
        RuleID       = "VCFE-9X-000008"
        Title        = "The ESX host must enable lockdown mode."
        Severity     = "high"
        GroupTitle   = "Lockdown Mode"
        Vuln_Discuss = "Enabling lockdown mode disables direct access to an ESXi host and requires that the host be managed through vCenter Server. This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging on to a host directly. Lockdown mode significantly reduces the attack surface of the ESXi host by preventing direct root and user access to the host via DCUI, SSH, or ESXi Shell unless the account is on the exception users list. Without lockdown mode, an attacker with physical or network access to the management interface could potentially bypass vCenter-enforced access controls. Normal lockdown mode restricts direct access while still allowing DCUI access for emergency recovery. Strict lockdown mode provides the highest level of restriction. This control supports the requirements of NIST SP 800-53 AC-3 and CM-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Lockdown Mode, verify the mode is set to Normal or Strict.

If Lockdown Mode is set to Disabled, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter>
(Get-VMHost -Name <hostname>).ExtensionData.Config.LockdownMode

If the value returned is 'lockdownDisabled', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Lockdown Mode, click Edit and set lockdown mode to Normal or Strict as required by the environment.

PowerCLI:
Connect-VIServer -Server <vcenter>
`$vmhostv = Get-VMHost -Name <hostname> | Get-View
`$lockdown = Get-View `$vmhostv.ConfigManager.HostAccessManager
`$lockdown.ChangeLockdownMode('lockdownNormal')"
    },
    @{
        RuleID       = "VCFE-9X-000010"
        Title        = "The ESX host client must be configured with an idle session timeout."
        Severity     = "medium"
        GroupTitle   = "Host Client Timeout"
        Vuln_Discuss = "An attacker who is able to physically access a workstation with an authenticated ESXi Host Client session can take advantage of that access to perform malicious actions. Configuring an idle session timeout ensures that unattended sessions are automatically terminated after a period of inactivity, reducing the window of opportunity for unauthorized access. Without a session timeout, a session left open on an unattended workstation could be exploited by an unauthorized user who gains physical access. This applies to the web-based ESXi Host Client used for direct host management. This control supports the requirements of NIST SP 800-53 AC-11 and AC-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting UserVars.HostClientSessionTimeout and verify the value is 900 or less but not 0.

If the value is 0 or greater than 900, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout

If the value returned is 0 or greater than 900, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate UserVars.HostClientSessionTimeout, and set the value to 900.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value 900 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000014"
        Title        = "The ESX host must use DOD-approved encryption to protect the confidentiality of network sessions."
        Severity     = "high"
        GroupTitle   = "TLS Profile"
        Vuln_Discuss = "The ESXi host provides several network services including the vSphere API, the ESXi Host Client, and other management interfaces that use TLS to protect the confidentiality and integrity of communications. Using weak or outdated TLS configurations exposes these communications to interception and tampering. The NIST_2024 TLS server profile enforces the use of strong, FIPS 140-2 validated cryptographic algorithms and disables deprecated protocols such as TLS 1.0 and 1.1 and weak cipher suites. Without enforcing a compliant TLS profile, management communications between vSphere components may be susceptible to protocol downgrade attacks and the use of weak ciphers that have known vulnerabilities. This control supports the requirements of NIST SP 800-53 SC-8 and IA-7."
        CheckText    = "From an ESXi shell, run the following command:
esxcli system tls server get --show-profile-defaults --show-current-boot-profile

Verify the Profile value is NIST_2024. If the TLS profile is not NIST_2024, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$tlsargs = `$esxcli.system.tls.server.get.CreateArgs()
`$tlsargs.showprofiledefaults = `$true
`$tlsargs.showcurrentbootprofile = `$true
`$esxcli.system.tls.server.get.invoke(`$tlsargs) | Select-Object -ExpandProperty Profile

If the value returned is not NIST_2024, this is a finding."
        FixText      = "Place the host in maintenance mode before applying this change. From an ESXi shell, run:
esxcli system tls server set --profile=NIST_2024

Reboot the host for the change to take effect.

PowerCLI (host must be in maintenance mode):
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$tlsargs = `$esxcli.system.tls.server.set.CreateArgs()
`$tlsargs.profile = 'NIST_2024'
`$esxcli.system.tls.server.set.invoke(`$tlsargs)

Reboot the host after applying the change."
    },
    @{
        RuleID       = "VCFE-9X-000015"
        Title        = "The ESX host must produce audit records containing information to establish what type of events occurred."
        Severity     = "medium"
        GroupTitle   = "Log Level"
        Vuln_Discuss = "Audit records are essential for reconstructing security events and detecting malicious or anomalous activity on a system. Without sufficient logging detail, it may be impossible to determine what actions were taken by users or processes on the ESXi host. The log level setting controls the verbosity of the host agent log, which records management plane activity. Setting the log level to 'info' ensures that informational, warning, and error events are all captured without generating excessive log volume. Setting the log level too low, such as 'warning' or 'error', may result in important operational and security events being omitted from the audit record. Setting it too high, such as 'verbose' or 'trivia', may generate excessive log data that could mask relevant events and consume storage capacity. This control supports the requirements of NIST SP 800-53 AU-2 and AU-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.HostAgent.log.level and verify the value is set to info.

If the value is not info, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.log.level

If the value returned is not 'info', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.HostAgent.log.level, and set the value to info.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value 'info' -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000035"
        Title        = "The ESX host must enforce password complexity by configuring a password quality policy."
        Severity     = "medium"
        GroupTitle   = "Password Complexity"
        Vuln_Discuss = "Password complexity requirements reduce the ability of attackers to successfully obtain valid passwords using dictionary or brute-force attacks. The ESXi password quality control setting uses the Linux PAM pam_passwdqc module to enforce minimum password complexity requirements. The required configuration enforces a minimum length of 15 characters for passwords consisting of a single character class, disables weaker shorter passwords, requires a retry limit of 3, and rejects passwords similar to the previous password. Without enforcing password complexity requirements, users may choose simple or easily guessable passwords that can be compromised through common attack methods, potentially resulting in unauthorized access to the ESXi management plane. This control supports the requirements of NIST SP 800-53 IA-5."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Security.PasswordQualityControl and verify the value is:
random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15

If the value does not match the required string exactly, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.PasswordQualityControl

If the value returned does not match 'random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Security.PasswordQualityControl, and set the value to:
random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value 'random=0 similar=deny retry=3 min=disabled,disabled,disabled,disabled,15' -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000042"
        Title        = "The ESX host must enforce a 90-day maximum password lifetime restriction."
        Severity     = "medium"
        GroupTitle   = "Password Max Days"
        Vuln_Discuss = "Any password, no matter how complex, can eventually be cracked or stolen. Enforcing a maximum password lifetime limits the window of opportunity for an attacker who has obtained a valid credential through theft, interception, or brute-force methods. Requiring regular password changes also reduces the risk associated with long-term credential exposure resulting from previously undetected breaches. Without a maximum password age, credentials could remain valid indefinitely, extending the potential damage from a compromised account. A 90-day maximum aligns with DoD policy and common federal security standards. This control supports the requirements of NIST SP 800-53 IA-5."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Security.PasswordMaxDays and verify the value is 90 or less.

If the value is greater than 90, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.PasswordMaxDays

If the value returned is greater than 90, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Security.PasswordMaxDays, and set the value to 90.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000046"
        Title        = "The ESX host must be configured to disable nonessential capabilities by disabling the Managed Object Browser (MOB)."
        Severity     = "medium"
        GroupTitle   = "Disable MOB"
        Vuln_Discuss = "The Managed Object Browser (MOB) is a web-based interface that provides low-level access to the ESXi object model and can be used to browse and make changes to the host configuration. The MOB was historically useful for debugging and development but poses a security risk in production environments because it provides direct access to the vSphere API without the access controls enforced by vCenter Server. An attacker with access to the management network who authenticates to the MOB could browse sensitive configuration data and potentially make unauthorized changes to the host. Because the MOB serves no operational purpose in a production deployment and provides an additional attack surface, it should be disabled. This control supports the requirements of NIST SP 800-53 CM-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.HostAgent.plugins.solo.enableMob and verify the value is set to false.

If the value is true, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

If the value returned is True, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.HostAgent.plugins.solo.enableMob, and set the value to false.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value `$false -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000048"
        Title        = "The ESX host must uniquely identify and must authenticate organizational users by using Active Directory."
        Severity     = "medium"
        GroupTitle   = "Active Directory"
        Vuln_Discuss = "Joining an ESXi host to an Active Directory domain allows organizational user accounts to be used for authentication rather than local accounts, enabling centralized identity management, enforcement of organizational password policies, and integration with enterprise access control systems. Using local accounts exclusively on ESXi hosts makes it difficult to enforce consistent password policies, audit user activity across multiple hosts, and quickly revoke access when personnel leave the organization. Active Directory integration ensures that individual accountability is maintained and that authentication is tied to centrally managed identities rather than host-local accounts that may not be subject to the same governance controls. This control supports the requirements of NIST SP 800-53 IA-2 and IA-8."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Authentication Services. Verify the host is joined to an Active Directory domain and the Domain Status shows as 'OK'.

If the host is not joined to an Active Directory domain and no equivalent centralized authentication mechanism is in use, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostAuthentication | Select-Object Domain, DomainMembershipStatus

If Domain is empty or DomainMembershipStatus is not 'Ok', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Authentication Services. Click Join Domain, provide the domain name and credentials of an account authorized to join systems to the domain, and click OK.

Note: This rule requires environment-specific domain credentials and must be remediated manually. Ensure the correct Active Directory domain and organizational unit are targeted per site policy."
    },
    @{
        RuleID       = "VCFE-9X-000064"
        Title        = "The ESX host must disable Inter-Virtual Machine (VM) Transparent Page Sharing."
        Severity     = "medium"
        GroupTitle   = "Memory Salting"
        Vuln_Discuss = "Transparent Page Sharing (TPS) is a memory management feature that allows the ESXi hypervisor to share memory pages that have identical content across multiple virtual machines, reducing overall memory consumption. However, research has demonstrated that TPS can be exploited as a side-channel attack vector that allows information to leak between virtual machines. By observing memory deduplication patterns, a malicious VM may be able to infer information about the memory contents of neighboring VMs, potentially compromising the confidentiality of data belonging to other tenants. Setting Mem.ShareForceSalting to 2 disables inter-VM TPS by requiring all shared pages to be salted with a unique VM identifier, preventing cross-VM page sharing while still allowing intra-VM TPS. This control supports the requirements of NIST SP 800-53 SC-39 and SI-16."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Mem.ShareForceSalting and verify the value is set to 2.

If the value is not 2, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Mem.ShareForceSalting

If the value returned is not 2, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Mem.ShareForceSalting, and set the value to 2.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000066"
        Title        = "The ESX host must set a timeout to automatically terminate idle shell sessions."
        Severity     = "medium"
        GroupTitle   = "Shell Interactive Timeout"
        Vuln_Discuss = "If a user is logged in to the ESXi Shell or SSH session and the session is left unattended, an unauthorized user could gain access to the session and perform malicious actions with the privileges of the authenticated user. Setting an interactive session timeout ensures that idle shell sessions are automatically terminated after a period of inactivity, reducing the risk of unauthorized use of an unattended session. The ESXiShellInteractiveTimeOut setting controls the timeout for interactive shell sessions specifically, as opposed to scripted or automated sessions. This timeout applies to direct shell access and is separate from the SSH daemon timeout settings. This control supports the requirements of NIST SP 800-53 AC-11 and AC-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting UserVars.ESXiShellInteractiveTimeOut and verify the value is 900 or less but not 0.

If the value is 0 or greater than 900, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

If the value returned is 0 or greater than 900, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate UserVars.ESXiShellInteractiveTimeOut, and set the value to 900.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000082"
        Title        = "The ESX host must enable Secure Boot enforcement for configuration encryption."
        Severity     = "high"
        GroupTitle   = "Secure Boot Enforcement"
        Vuln_Discuss = "ESXi configuration encryption protects the host configuration data at rest using encryption keys that are sealed to the host's TPM. Requiring Secure Boot as part of configuration encryption ensures that the encryption keys cannot be accessed on a host that has not successfully validated its boot chain. Without this enforcement, an attacker who physically moves an ESXi boot drive to a host that does not have Secure Boot enabled could potentially access or modify the encrypted configuration data. By requiring Secure Boot for configuration encryption, the integrity of the boot chain is tied to the protection of the configuration data, significantly raising the bar for offline attacks against ESXi configuration. This control works in conjunction with VCFE-9X-000091 (enable Secure Boot) and VCFE-9X-000193 (TPM-based configuration encryption). This control supports the requirements of NIST SP 800-53 SI-7 and SC-28."
        CheckText    = "From an ESXi shell, run the following command:
esxcli system settings encryption get

Verify the RequireSecureBoot field is True. If RequireSecureBoot is not True, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.settings.encryption.get.invoke() | Select-Object RequireSecureBoot, Mode

If RequireSecureBoot is not True, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system settings encryption set --require-secure-boot=TRUE --mode=TPM

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sbarg = `$esxcli.system.settings.encryption.set.CreateArgs()
`$sbarg.mode = 'TPM'
`$sbarg.requiresecureboot = `$true
`$esxcli.system.settings.encryption.set.Invoke(`$sbarg)"
    },
    @{
        RuleID       = "VCFE-9X-000091"
        Title        = "The ESX host must enable Secure Boot."
        Severity     = "high"
        GroupTitle   = "UEFI Secure Boot"
        Vuln_Discuss = "Secure Boot is part of the UEFI firmware standard. With UEFI Secure Boot enabled, a host refuses to load any UEFI driver or application unless the operating system bootloader has a valid digital signature. Secure Boot for ESXi requires support from the firmware and requires that all ESXi kernel modules, drivers, and VIBs be signed by VMware or a partner subordinate. Secure Boot is enabled in the BIOS of the ESXi physical server and supported by the hypervisor boot loader. This control ensures that the boot chain is validated, preventing the loading of unsigned or tampered boot components. Without Secure Boot, an attacker with physical access to the server could potentially boot a modified or malicious version of the hypervisor. This control is a prerequisite for effective configuration encryption. This control supports the requirements of NIST SP 800-53 SI-7 and CM-5."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Summary. Review the hardware summary section and verify Secure Boot is shown as enabled.

If Secure Boot is not enabled, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
(Get-VMHost -Name <hostname>).ExtensionData.Capability.UefiSecureBoot

If the value returned is not True, this is a finding."
        FixText      = "Secure Boot must be enabled in the server firmware. Reboot the server and enter the firmware setup utility (BIOS/UEFI). Navigate to the Secure Boot settings and enable UEFI Secure Boot. Save the settings and boot normally.

Note: This setting cannot be configured via vSphere Client or PowerCLI as it is a firmware-level control. Refer to the server vendor documentation for specific steps to enable Secure Boot in the firmware."
    },
    @{
        RuleID       = "VCFE-9X-000096"
        Title        = "The ESX host must disable remote access to the information system by disabling Secure Shell (SSH)."
        Severity     = "high"
        GroupTitle   = "SSH Disabled"
        Vuln_Discuss = "Secure Shell (SSH) provides encrypted remote command-line access to the ESXi host shell. While SSH uses strong encryption for its communications, enabling SSH increases the attack surface of the ESXi host by providing an additional network-accessible entry point. SSH on ESXi provides access to the ESXi shell, which has capabilities not available through the vSphere API and vCenter. An attacker who gains SSH access, either through credential compromise or an SSH vulnerability, could make changes to host configuration that bypass vCenter-enforced access controls, extract sensitive data, or pivot to other systems on the management network. SSH should only be enabled temporarily for troubleshooting or maintenance purposes and disabled immediately afterward. In a properly managed environment, all routine administration should be performed through vCenter. This control supports the requirements of NIST SP 800-53 CM-7 and AC-17."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Services, locate SSH. Verify that the Status is Stopped and the Startup Policy is Manual or Disabled.

If SSH is Running or the Startup Policy is set to start automatically, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostService | Where-Object {`$_.Label -eq 'SSH'} | Select-Object Label, Running, Policy

If Running is True or Policy is not 'off', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Services, select SSH and click Stop. Then click Edit Startup Policy and set the startup policy to Manual.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$svc = Get-VMHost -Name <hostname> | Get-VMHostService | Where-Object {`$_.Label -eq 'SSH'}
`$svc | Set-VMHostService -Policy 'off' -Confirm:`$false
`$svc | Stop-VMHostService -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000108"
        Title        = "The ESX host must enforce an unlock timeout of 15 minutes after a user account is locked out."
        Severity     = "medium"
        GroupTitle   = "Account Unlock Time"
        Vuln_Discuss = "Setting a lockout duration (unlock timeout) prevents an attacker from repeatedly triggering the account lockout mechanism as a denial-of-service tactic while also ensuring that legitimate users can regain access to their accounts after a reasonable waiting period without requiring administrator intervention for every lockout event. Without a configured unlock timeout, a locked account might remain locked indefinitely, requiring manual administrator action to unlock it, or conversely the timeout might be set to zero which could allow rapid retry attempts after the lockout counter resets. A 15-minute unlock timeout balances security by slowing brute-force attempts while minimizing operational impact to authorized users. This control supports the requirements of NIST SP 800-53 AC-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Security.AccountUnlockTime and verify the value is set to 900.

If the value is not 900, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.AccountUnlockTime

If the value returned is not 900, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Security.AccountUnlockTime, and set the value to 900.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000110"
        Title        = "The ESX host must allocate audit record storage capacity to store at least one week's worth of audit records."
        Severity     = "medium"
        GroupTitle   = "Audit Storage Capacity"
        Vuln_Discuss = "Audit records are critical for forensic investigation and security incident response. If audit record storage capacity is insufficient, older records may be overwritten before they can be reviewed or exported to a remote logging system, potentially destroying evidence of security incidents or policy violations. The ESXi host stores audit records locally before forwarding them to remote syslog destinations. Ensuring sufficient local storage capacity provides a buffer that maintains audit record availability even in the event of temporary disruptions to remote log forwarding. The required capacity of 100MB provides sufficient space to store at least one week's worth of typical audit activity on an ESXi host. This control supports the requirements of NIST SP 800-53 AU-4 and AU-9."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Syslog.global.auditRecord.storageCapacity and verify the value is 100 or greater.

If the value is less than 100, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity

If the value returned is less than 100, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Syslog.global.auditRecord.storageCapacity, and set the value to 100.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Set-AdvancedSetting -Value 100 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000111"
        Title        = "The ESX host must off-load audit records onto a different system or media than the system being audited."
        Severity     = "medium"
        GroupTitle   = "Audit Record Remote"
        Vuln_Discuss = "Storing audit records only on the system being audited creates a single point of failure for audit data integrity. An attacker who compromises the ESXi host could modify, delete, or truncate locally stored audit records to conceal their activities. Additionally, in the event of a host failure or corruption, locally stored audit records may be lost entirely. Off-loading audit records to a remote, dedicated logging system ensures that audit data is preserved and protected independently of the system being audited. Remote audit record storage also enables centralized review and correlation of audit data across multiple systems. ESXi supports forwarding audit records to remote syslog servers using the Syslog.global.auditRecord.remoteEnable setting. This control supports the requirements of NIST SP 800-53 AU-4 and AU-9."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Syslog.global.auditRecord.remoteEnable and verify the value is set to true.

If the value is false, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable

If the value returned is not True, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Syslog.global.auditRecord.remoteEnable, and set the value to true. Ensure a remote syslog server is also configured under Syslog.global.logHost.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Set-AdvancedSetting -Value `$true -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000121"
        Title        = "The ESX host must synchronize internal information system clocks to an authoritative time source."
        Severity     = "medium"
        GroupTitle   = "NTP"
        Vuln_Discuss = "Accurate and synchronized system time is fundamental to the integrity of audit records and security operations. If system clocks are not synchronized, audit records from different systems will have inconsistent timestamps, making it difficult or impossible to correlate events across systems during incident investigation. Inaccurate time also affects the validity of certificates and can interfere with Kerberos authentication, which has a strict tolerance for clock skew between systems. ESXi hosts must be configured to synchronize their clocks with authoritative NTP servers approved by the organization. Without NTP synchronization, the host clock may drift significantly over time, particularly after maintenance events or reboots. This control supports the requirements of NIST SP 800-53 AU-8 and SC-45."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Time Configuration. Verify NTP is enabled, at least one authorized NTP server is configured, and the NTP daemon startup policy is set to 'Start and Stop with Host'.

If NTP is not configured, no authorized NTP servers are listed, or the NTP service is not running, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostService | Where-Object {`$_.Label -eq 'NTP Daemon'} | Select-Object Label, Running, Policy
(Get-VMHost -Name <hostname>).ExtensionData.Config.DateTimeInfo.NtpConfig.Server

If Running is not True, Policy is not 'on', or no authorized NTP servers are listed, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Time Configuration. Click Edit, add the organizationally approved NTP server addresses, set the startup policy to 'Start and Stop with Host', and click Start to start the NTP daemon.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Add-VMHostNtpServer -VMHost (Get-VMHost -Name <hostname>) -NtpServer '<ntp_server_ip>'
`$svc = Get-VMHost -Name <hostname> | Get-VMHostService | Where-Object {`$_.Label -eq 'NTP Daemon'}
`$svc | Set-VMHostService -Policy 'on' -Confirm:`$false
`$svc | Start-VMHostService -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000130"
        Title        = "The ESX Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified."
        Severity     = "high"
        GroupTitle   = "VIB Acceptance Level"
        Vuln_Discuss = "The ESXi software acceptance level determines what category of VIBs can be installed on a host. VIBs are software packages that extend ESXi functionality. The acceptance levels from most to least restrictive are: VMwareCertified, VMwareAccepted, PartnerSupported, and CommunitySupported. Community-supported VIBs have not been reviewed, tested, or signed by VMware and carry the highest risk of containing malicious code, causing system instability, or introducing security vulnerabilities. Installing a CommunitySupported VIB on a production system violates the principle of using only approved and trusted software and could allow an attacker to introduce malicious kernel-level code that operates with full hypervisor privileges. The minimum acceptable acceptance level for DoD systems is PartnerSupported, which ensures VIBs have at minimum been signed and accepted by a VMware partner. This control supports the requirements of NIST SP 800-53 CM-5 and SI-7."
        CheckText    = "From an ESXi shell, run:
esxcli software acceptance get

If the acceptance level is CommunitySupported, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.software.acceptance.get.Invoke()

If the value returned is 'CommunitySupported', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli software acceptance set --level=PartnerSupported

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$vibargs = `$esxcli.software.acceptance.set.CreateArgs()
`$vibargs.level = 'PartnerSupported'
`$esxcli.software.acceptance.set.Invoke(`$vibargs)"
    },
    @{
        RuleID       = "VCFE-9X-000138"
        Title        = "The ESX host must enable bidirectional Challenge-Handshake Authentication Protocol (CHAP) authentication for Internet Small Computer Systems Interface (iSCSI) traffic."
        Severity     = "medium"
        GroupTitle   = "iSCSI CHAP"
        Vuln_Discuss = "iSCSI is a protocol that allows SCSI commands to be transmitted over IP networks, providing network-based storage access. Without authentication, any host on the network that can reach the iSCSI target could potentially access the storage. CHAP provides a mechanism for iSCSI initiators and targets to mutually authenticate each other, ensuring that only authorized hosts can access storage resources and that the iSCSI target the initiator is connecting to is legitimate. Unidirectional CHAP only authenticates the initiator to the target, leaving the target unauthenticated. Bidirectional CHAP requires both parties to authenticate, preventing man-in-the-middle attacks where a rogue iSCSI target could be substituted for a legitimate one. This control supports the requirements of NIST SP 800-53 IA-3 and SC-8."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Storage >> Storage Adapters. Select the iSCSI software adapter and review the Authentication section. Verify that CHAP is set to Required and Mutual CHAP is also set to Required, indicating bidirectional authentication.

If CHAP is not configured, is set to Prohibited, or is configured for unidirectional authentication only, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostHba | Where-Object {`$_.Type -eq 'iSCSI'} | Select-Object Device, ChapType, MutualChapEnabled

If ChapType is not 'Required' or MutualChapEnabled is not True, this is a finding.

Note: If iSCSI is not in use on the host, this finding is not applicable."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Storage >> Storage Adapters. Select the iSCSI adapter, click the Authentication tab, click Edit, and set CHAP to Required with bidirectional CHAP configured with appropriate credentials.

Note: This rule requires environment-specific CHAP secret configuration and must be remediated manually. Coordinate with the storage administrator to obtain appropriate CHAP credentials."
    },
    @{
        RuleID       = "VCFE-9X-000152"
        Title        = "The ESX host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
        Severity     = "medium"
        GroupTitle   = "vMotion Isolation"
        Vuln_Discuss = "vMotion is the VMware technology that allows live migration of running virtual machines between ESXi hosts. During a vMotion migration, the entire memory contents of a running virtual machine are transmitted across the network in a relatively short time period. If vMotion traffic is not isolated on a dedicated network segment, this memory data could potentially be captured and analyzed by other systems that share the same network. The memory of a running virtual machine may contain sensitive data such as encryption keys, passwords, session tokens, and other confidential information. vMotion traffic is not encrypted by default in all configurations, making network-level isolation critical. Dedicating a VMkernel adapter and a separate VLAN or physical network to vMotion traffic ensures this sensitive data cannot be accessed by unauthorized systems. This control supports the requirements of NIST SP 800-53 SC-8 and SC-5."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> VMkernel adapters. For each VMkernel adapter with vMotion enabled, verify no other traffic types such as Management, Fault Tolerance Logging, vSAN, or vSphere Replication are also enabled on the same adapter.

If any VMkernel adapter has vMotion enabled simultaneously with any other traffic type, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostNetworkAdapter -VMKernel | Where-Object {`$_.VMotionEnabled} | Select-Object Name, VMotionEnabled, ManagementTrafficEnabled, FaultToleranceLoggingEnabled, VsanTrafficEnabled, VSphereReplicationEnabled

If any adapter shows VMotionEnabled as True alongside any other traffic type set to True, this is a finding."
        FixText      = "From the vSphere Client, configure a dedicated VMkernel adapter for vMotion traffic only. Remove vMotion from any VMkernel adapter that carries other traffic types. Create a new VMkernel adapter on a dedicated VLAN and configure it for vMotion only.

Note: This rule requires network architecture changes that are environment-specific and must be remediated manually. Coordinate with the network administrator to configure appropriate VLAN isolation."
    },
    @{
        RuleID       = "VCFE-9X-000181"
        Title        = "The ESX host must restrict access to the DCUI."
        Severity     = "medium"
        GroupTitle   = "DCUI Access"
        Vuln_Discuss = "The Direct Console User Interface (DCUI) provides low-level access to the ESXi host for configuration and troubleshooting. The DCUI.Access setting controls which local accounts can access the DCUI when the host is in lockdown mode. By default, only root is listed, which is appropriate. If additional accounts are added to DCUI.Access, those accounts bypass certain lockdown mode restrictions and can access the DCUI even when the host is in lockdown mode. Unauthorized accounts in the DCUI.Access list represent an excessive privilege assignment that could allow unauthorized individuals to modify host configuration through the DCUI and bypass vCenter-enforced access controls. The DCUI access list should contain only accounts that are specifically authorized to perform emergency recovery operations. This control supports the requirements of NIST SP 800-53 AC-3 and AC-6."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting DCUI.Access and verify the value contains only 'root'.

If any accounts other than root are listed in DCUI.Access without documented authorization, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name DCUI.Access

If the value returned contains any account names other than 'root', this is a finding unless those accounts are specifically documented and authorized."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate DCUI.Access, and set the value to root.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value 'root' -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000193"
        Title        = "The ESX host must require TPM-based configuration encryption."
        Severity     = "high"
        GroupTitle   = "TPM Config Encryption"
        Vuln_Discuss = "ESXi configuration data contains sensitive information including account credentials, certificate private keys, and other security-relevant configuration parameters. Without encryption, this configuration data stored on the ESXi boot device is accessible to anyone with physical access to the boot media. TPM-based configuration encryption uses the host's Trusted Platform Module to seal the encryption keys to the specific hardware configuration of the host, ensuring that the encrypted configuration can only be decrypted on the original host with its current firmware and software configuration. This prevents offline attacks where an attacker copies the boot device to another system and attempts to extract the configuration data. TPM-based encryption provides stronger protection than software-only encryption because the keys are bound to the physical hardware. This control supports the requirements of NIST SP 800-53 SC-28 and SI-7."
        CheckText    = "From an ESXi shell, run:
esxcli system settings encryption get

Verify the Mode field is set to TPM. If Mode is not TPM, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.settings.encryption.get.invoke() | Select-Object Mode, RequireSecureBoot

If Mode is not 'TPM', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system settings encryption set --mode=TPM

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$tpmencarg = `$esxcli.system.settings.encryption.set.CreateArgs()
`$tpmencarg.mode = 'TPM'
`$esxcli.system.settings.encryption.set.Invoke(`$tpmencarg)

Note: The host must have a functional TPM 2.0 module and Secure Boot must be enabled for this setting to take effect."
    },
    @{
        RuleID       = "VCFE-9X-000196"
        Title        = "The ESX host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via Secure Shell (SSH)."
        Severity     = "medium"
        GroupTitle   = "SSH /etc/issue Banner"
        Vuln_Discuss = "Failure to display the DOD logon banner prior to an SSH logon attempt will negate legal proceedings resulting from unauthorized access to system resources. The content of the /etc/issue file on ESXi is controlled through the Config.Etc.issue advanced setting and is displayed to users before they authenticate via SSH. The banner must inform users that the system is owned by the U.S. Government, that all activity is subject to monitoring, and that unauthorized use is prohibited. This banner serves both as a legal notice and as a deterrent to unauthorized users. Without the proper banner, the legal basis for prosecuting unauthorized access may be compromised, and users may not be aware of monitoring activities. This control is complementary to VCFE-9X-000197 which configures the SSH daemon to display the banner file. This control supports the requirements of NIST SP 800-53 AC-8."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.Etc.issue and verify the value contains the Standard Mandatory DOD Notice and Consent Banner text.

If the value is empty or does not contain the required DOD banner text, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.Etc.issue | Select-Object -ExpandProperty Value

If the value is empty or does not contain the DOD Notice and Consent Banner text, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.Etc.issue, and set the value to the Standard Mandatory DOD Notice and Consent Banner text as defined in DoD policy.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.Etc.issue | Set-AdvancedSetting -Value '<DOD_banner_text>' -Confirm:`$false

Note: Replace <DOD_banner_text> with the organizationally approved DOD Notice and Consent Banner."
    },
    @{
        RuleID       = "VCFE-9X-000197"
        Title        = "The ESX host Secure Shell (SSH) daemon must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system."
        Severity     = "medium"
        GroupTitle   = "SSH Banner"
        Vuln_Discuss = "The SSH daemon must be configured to present the DOD Notice and Consent Banner to users attempting to authenticate. This is accomplished by configuring the SSH banner option to point to the /etc/issue file, which contains the required banner text. Without this configuration, users connecting via SSH will not be presented with the legal notice and consent information prior to authentication, which could undermine the legal basis for monitoring and prosecution of unauthorized access. The banner setting in the SSH daemon configuration must reference the /etc/issue file so that any updates to the banner text through the Config.Etc.issue advanced setting are automatically reflected in SSH banner presentation. This control works in conjunction with VCFE-9X-000196 which configures the actual banner content. This control supports the requirements of NIST SP 800-53 AC-8."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep banner

Verify the Value field shows /etc/issue. If the banner is not configured to /etc/issue, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'banner'} | Select-Object Key, Value

If the Value returned is not '/etc/issue', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k banner -v /etc/issue

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'banner'
`$sshsargs.value = '/etc/issue'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000198"
        Title        = "The ESX host must enable audit logging."
        Severity     = "medium"
        GroupTitle   = "Enable Audit Records"
        Vuln_Discuss = "Audit logging is fundamental to security monitoring, incident detection, and forensic investigation. Without audit logging enabled, the ESXi host will not generate audit records for security-relevant events such as authentication attempts, privilege escalation, configuration changes, and system access. The absence of audit records makes it impossible to reconstruct the sequence of events surrounding a security incident, detect ongoing attacks, or demonstrate compliance with security policy requirements. ESXi maintains a separate audit record subsystem distinct from the general syslog facility. The Syslog.global.auditRecord.storageEnable setting must be enabled to activate local storage of audit records. Audit records complement the general log data and provide a structured record specifically designed for security auditing purposes. This control supports the requirements of NIST SP 800-53 AU-2 and AU-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Syslog.global.auditRecord.storageEnable and verify the value is set to true.

If the value is false, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable

If the value returned is not True, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Syslog.global.auditRecord.storageEnable, and set the value to true.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable | Set-AdvancedSetting -Value `$true -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000199"
        Title        = "The ESX host must be configured to disable nonessential capabilities by disabling the ESXi shell."
        Severity     = "high"
        GroupTitle   = "ESXi Shell Disabled"
        Vuln_Discuss = "The ESXi shell provides command-line access to the ESXi host operating system with capabilities that go beyond what is available through the vSphere API. While useful for troubleshooting and advanced configuration tasks, the ESXi shell represents a significant attack surface if left enabled. An attacker who gains access to the ESXi shell, whether through compromised credentials or an exploitation of a service that provides access to it, can perform operations that bypass vCenter access controls, modify host configuration, access VM data, and potentially escape the hypervisor to affect virtual machines. The ESXi shell should only be enabled temporarily for specific maintenance tasks under controlled conditions and disabled immediately afterward. In normal operations, all management should be performed through vCenter. This control supports the requirements of NIST SP 800-53 CM-7 and AC-17."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Services, locate ESXi Shell. Verify the Status is Stopped and the Startup Policy is Manual or Disabled.

If ESXi Shell is Running or the Startup Policy allows it to start automatically, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostService | Where-Object {`$_.Label -eq 'ESXi Shell'} | Select-Object Label, Running, Policy

If Running is True or Policy is not 'off', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Services, select ESXi Shell, click Stop, and set the startup policy to Manual.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$svc = Get-VMHost -Name <hostname> | Get-VMHostService | Where-Object {`$_.Label -eq 'ESXi Shell'}
`$svc | Set-VMHostService -Policy 'off' -Confirm:`$false
`$svc | Stop-VMHostService -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000200"
        Title        = "The ESX host must automatically stop shell services after ten minutes."
        Severity     = "medium"
        GroupTitle   = "Shell Timeout"
        Vuln_Discuss = "The ESXiShellTimeOut setting controls how long the ESXi Shell or SSH service will continue to run after it has been enabled, regardless of whether any sessions are active. This setting provides an additional safety net to ensure that shell services that were temporarily enabled for maintenance purposes are automatically disabled after a set period, even if the administrator forgets to manually disable them. Without this timeout, shell services enabled for a specific task could remain active indefinitely, creating an ongoing security risk. A 10-minute timeout ensures that shell access is limited to the maintenance window and that the host automatically returns to a more secure state after the timeout expires. This control is complementary to VCFE-9X-000066 which controls interactive session timeout and VCFE-9X-000096 and VCFE-9X-000199 which disable the services entirely. This control supports the requirements of NIST SP 800-53 CM-7 and AC-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting UserVars.ESXiShellTimeOut and verify the value is 600 or less but not 0.

If the value is 0 or greater than 600, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the value returned is 0 or greater than 600, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate UserVars.ESXiShellTimeOut, and set the value to 600.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000201"
        Title        = "The ESX host must set a timeout to automatically end idle DCUI sessions after 10 minutes."
        Severity     = "medium"
        GroupTitle   = "DCUI Timeout"
        Vuln_Discuss = "The Direct Console User Interface (DCUI) provides local console access to the ESXi host and is accessible via physical connection to the server console or via out-of-band management interfaces such as IPMI or iDRAC. An idle DCUI session left authenticated at the console represents a risk of unauthorized access by anyone who gains physical or out-of-band access to the console. Setting a DCUI timeout of 600 seconds (10 minutes) ensures that unattended DCUI sessions are automatically terminated, requiring reauthentication. Without this timeout, an authenticated DCUI session could remain open indefinitely, allowing anyone who accesses the physical or virtual console to interact with the host as the authenticated user. This control supports the requirements of NIST SP 800-53 AC-11 and AC-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting UserVars.DcuiTimeOut and verify the value is 600 or less but not 0.

If the value is 0 or greater than 600, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the value returned is 0 or greater than 600, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate UserVars.DcuiTimeOut, and set the value to 600.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000202"
        Title        = "The ESX host must configure a persistent log location for all locally stored logs and audit records."
        Severity     = "medium"
        GroupTitle   = "Syslog Log Directory"
        Vuln_Discuss = "If the ESXi host does not have persistent local storage for logs, all log data is stored in a temporary RAM-based filesystem that is cleared on every reboot. This means that after any reboot, including those caused by unexpected failures or attacks, all local log data from before the reboot is permanently lost. Persistent log storage ensures that log data survives host reboots and is available for forensic investigation following an incident. This is particularly important because a host reboot is often one of the first indicators that a security event has occurred. Without persistent logging, critical evidence of the events leading up to a reboot may be permanently lost. Persistent storage also ensures that log data is available for analysis even when connectivity to remote syslog servers is temporarily disrupted. This control supports the requirements of NIST SP 800-53 AU-9 and AU-4."
        CheckText    = "From an ESXi shell, run:
esxcli system syslog config get

Verify the LocalLogOutputIsPersistent field is true. If LocalLogOutputIsPersistent is false, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.syslog.config.get.Invoke() | Select-Object LocalLogOutput, LocalLogOutputIsPersistent

If LocalLogOutputIsPersistent is not True, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate Syslog.global.logDir and set the value to a persistent datastore location such as [datastore_name]/scratch/logs.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value '[datastore_name] /scratch/logs' -Confirm:`$false

Note: Replace 'datastore_name' with the actual name of a persistent datastore. After setting, run esxcli system syslog reload on the host to apply the change."
    },
    @{
        RuleID       = "VCFE-9X-000203"
        Title        = "The ESX host must protect the confidentiality and integrity of transmitted information by isolating ESX management traffic."
        Severity     = "medium"
        GroupTitle   = "Management Isolation"
        Vuln_Discuss = "ESXi management traffic includes communications between the host and vCenter Server, access to the ESXi Host Client, and other management plane communications. If management traffic is not isolated on a dedicated network segment, these communications may be accessible to unauthorized systems or users on shared network segments. An attacker who gains access to a network segment shared with ESXi management traffic could potentially capture management credentials, perform man-in-the-middle attacks against management sessions, or exploit vulnerabilities in management services. Network isolation ensures that only authorized management systems on dedicated management networks can communicate with the ESXi management interface. This isolation should be implemented through dedicated VLANs, physically separate network interfaces, or equivalent network segmentation controls. This control supports the requirements of NIST SP 800-53 SC-7 and SC-8."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> VMkernel adapters. Identify the VMkernel adapter with management traffic enabled. Verify the associated port group and VLAN are dedicated to management traffic and not shared with VM network traffic or other services.

If management traffic is not isolated on a dedicated network segment, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostNetworkAdapter -VMKernel | Where-Object {`$_.ManagementTrafficEnabled} | Select-Object Name, IP, PortGroupName, ManagementTrafficEnabled, VMotionEnabled, FaultToleranceLoggingEnabled, VsanTrafficEnabled

Review the PortGroupName and verify it is on a dedicated management VLAN. If any other traffic type is enabled on the same adapter or the port group VLAN is shared with non-management traffic, this is a finding."
        FixText      = "Configure a dedicated VMkernel adapter on a dedicated management VLAN for ESXi management traffic. Ensure no VM traffic or other service traffic is on the same VLAN or port group. Remove management traffic from any adapter that also carries other traffic types.

Note: This rule requires network architecture planning and must be remediated manually. Coordinate with the network administrator to configure the appropriate VLAN and switch configuration."
    },
    @{
        RuleID       = "VCFE-9X-000204"
        Title        = "The ESX host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic."
        Severity     = "medium"
        GroupTitle   = "IP Storage Isolation"
        Vuln_Discuss = "IP-based storage protocols such as iSCSI and NFS transmit storage data over the IP network. If this storage traffic is not isolated on a dedicated network segment, unauthorized systems may be able to observe storage data in transit, attempt unauthorized access to storage resources, or interfere with storage traffic in ways that cause data corruption or availability issues. Storage traffic often contains sensitive data from virtual machine workloads, and the loss of storage connectivity can immediately impact the availability of all VMs running on the host. Isolating storage traffic to a dedicated network ensures that only authorized storage systems and the ESXi hosts are on the storage network, reduces the risk of unauthorized access to storage resources, and prevents other network traffic from competing with storage traffic for bandwidth and potentially causing performance issues or timeouts. This control supports the requirements of NIST SP 800-53 SC-7 and SC-8."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> VMkernel adapters. Identify any VMkernel adapters used for iSCSI or NFS storage. Verify that these adapters are on dedicated network segments (VLANs) that are not shared with management, vMotion, or VM traffic.

If IP storage traffic shares a network segment with any other traffic type, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-VMHostNetworkAdapter -VMKernel | Select-Object Name, IP, PortGroupName, ManagementTrafficEnabled, VMotionEnabled, VsanTrafficEnabled

Review the PortGroupName for storage-related adapters and verify they are on isolated VLANs dedicated to storage traffic."
        FixText      = "Configure dedicated VMkernel adapters on dedicated VLANs for iSCSI and NFS storage traffic. Ensure no management, vMotion, VM, or other traffic types are on the same VLANs as storage adapters.

Note: This rule requires network architecture changes that are environment-specific and must be remediated manually. Coordinate with the network and storage administrators."
    },
    @{
        RuleID       = "VCFE-9X-000205"
        Title        = "The ESX host lockdown mode exception users list must be verified."
        Severity     = "medium"
        GroupTitle   = "Lockdown Exception Users"
        Vuln_Discuss = "Lockdown mode is designed to prevent direct access to the ESXi host, requiring that all management be performed through vCenter. The exception users list allows specific accounts to be exempted from lockdown mode restrictions, enabling them to directly access the host through SSH or the DCUI even when the host is in lockdown mode. Exception users retain their access privileges to the host, effectively bypassing the protections that lockdown mode is designed to provide. If the exception users list contains unauthorized accounts, these accounts can access the host directly, potentially circumventing vCenter access controls and audit trails. The exception users list must be reviewed regularly to ensure it contains only accounts that are specifically required and authorized for direct host access, such as service accounts required by infrastructure components like NSX. This control supports the requirements of NIST SP 800-53 AC-3 and AC-6."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Lockdown Mode, click Edit and review the Exception Users list. Verify that only authorized accounts are listed and that the list matches the organizationally approved exception users.

If any unauthorized accounts are present in the exception users list, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter>
`$vmhostv = Get-VMHost -Name <hostname> | Get-View
`$lockdown = Get-View `$vmhostv.ConfigManager.HostAccessManager
`$lockdown.QueryLockdownExceptions()

Compare the returned list against the organizationally approved exception user list. If any accounts are present that are not authorized, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Security Profile. Under Lockdown Mode, click Edit. In the Exception Users section, remove any accounts that are not authorized. Click OK to save.

PowerCLI:
Connect-VIServer -Server <vcenter>
`$vmhostv = Get-VMHost -Name <hostname> | Get-View
`$lockdown = Get-View `$vmhostv.ConfigManager.HostAccessManager
`$authorizedUsers = @('authorized_user1','authorized_user2')
`$lockdown.UpdateLockdownExceptions(`$authorizedUsers)"
    },
    @{
        RuleID       = "VCFE-9X-000206"
        Title        = "The ESX host Secure Shell (SSH) daemon must be configured to only use FIPS 140-2 validated ciphers."
        Severity     = "high"
        GroupTitle   = "SSH Ciphers"
        Vuln_Discuss = "SSH cipher configuration determines the encryption algorithms that will be negotiated during the establishment of SSH sessions. Permitting the use of weak or non-FIPS-validated ciphers creates vulnerabilities that could allow an attacker to decrypt SSH session traffic through cryptanalysis. The use of deprecated algorithms such as DES, 3DES, RC4, and others with known weaknesses should be explicitly prohibited. By configuring only FIPS 140-2 validated AES-based ciphers, the confidentiality of SSH management sessions is ensured using cryptographic algorithms that have been vetted through the NIST FIPS validation program. This is particularly important because SSH sessions may carry sensitive administrative commands and credentials between administrators and ESXi hosts. This control supports the requirements of NIST SP 800-53 SC-8, SC-12, and IA-7."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep ciphers

Verify the Value field contains only FIPS-validated ciphers:
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

If any non-FIPS ciphers are present or the cipher list is not configured, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'ciphers'} | Select-Object Key, Value

If the Value does not match the required cipher list exactly, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k ciphers -v 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'ciphers'
`$sshsargs.value = 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000207"
        Title        = "The ESX host Secure Shell (SSH) daemon must be configured to not allow gateway ports."
        Severity     = "low"
        GroupTitle   = "SSH GatewayPorts"
        Vuln_Discuss = "SSH port forwarding allows users to tunnel network connections through an SSH session. The GatewayPorts option, when enabled, allows remote hosts to connect to forwarded ports on the SSH server, effectively making the ESXi host act as a network gateway or proxy for remote connections. This capability can be exploited by an attacker who has established an SSH session to bypass network access controls by creating tunnels that allow external systems to reach internal network resources through the compromised ESXi host. Disabling GatewayPorts ensures that any port forwarding through SSH can only be accessed locally on the ESXi host itself, limiting the potential for SSH tunneling to be used as a network pivot point. This control supports the requirements of NIST SP 800-53 CM-7 and SC-7."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep gatewayports

Verify the Value field is 'no'. If the value is 'yes', this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'gatewayports'} | Select-Object Key, Value

If the Value returned is not 'no', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k gatewayports -v no

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'gatewayports'
`$sshsargs.value = 'no'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000208"
        Title        = "The ESX host Secure Shell (SSH) daemon must not permit user environment settings."
        Severity     = "medium"
        GroupTitle   = "SSH PermitUserEnvironment"
        Vuln_Discuss = "SSH PermitUserEnvironment allows users to pass environment variables to the SSH session through the ~/.ssh/environment file. If enabled, this capability allows users to set environment variables that may be used by shell scripts or system programs running in the SSH session, potentially enabling privilege escalation or bypassing security controls. For example, environment variables such as LD_PRELOAD, PATH, or IFS could be manipulated to alter the behavior of commands executed during the SSH session. Disabling this option prevents SSH users from setting environment variables that could be used to subvert security mechanisms or elevate privileges. This control supports the requirements of NIST SP 800-53 CM-7 and AC-3."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep permituserenvironment

Verify the Value field is 'no'. If the value is 'yes', this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'permituserenvironment'} | Select-Object Key, Value

If the Value returned is not 'no', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k permituserenvironment -v no

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'permituserenvironment'
`$sshsargs.value = 'no'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000209"
        Title        = "The ESX host Secure Shell (SSH) daemon must not permit tunnels."
        Severity     = "medium"
        GroupTitle   = "SSH PermitTunnel"
        Vuln_Discuss = "SSH tunneling allows network traffic to be encapsulated and transmitted through an SSH connection, effectively bypassing network access controls and firewalls. The PermitTunnel option enables tun(4) device forwarding, which can be used to create VPN-like tunnels through SSH. If enabled, an attacker who gains SSH access to an ESXi host could use the tunneling capability to establish persistent covert communication channels that bypass network security controls, route unauthorized traffic through the management network, or access network resources that should not be reachable from the attacker's location. Disabling SSH tunneling prevents the ESXi SSH daemon from being used as a covert communication channel or network bypass mechanism. This control supports the requirements of NIST SP 800-53 CM-7 and SC-7."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep permittunnel

Verify the Value field is 'no'. If the value is 'yes', this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'permittunnel'} | Select-Object Key, Value

If the Value returned is not 'no', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k permittunnel -v no

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'permittunnel'
`$sshsargs.value = 'no'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000210"
        Title        = "The ESX host Secure Shell (SSH) daemon must set a timeout count on idle sessions."
        Severity     = "low"
        GroupTitle   = "SSH ClientAliveCountMax"
        Vuln_Discuss = "The ClientAliveCountMax setting specifies the number of client alive messages that may be sent without the SSH daemon receiving a response from the client before the connection is dropped. Combined with ClientAliveInterval, this setting determines how long an unresponsive SSH session is allowed to persist before being terminated. Setting ClientAliveCountMax to 3 means that after 3 consecutive missed client alive checks (at the configured interval), the session will be terminated. Without a limit on unresponsive sessions, idle or disconnected SSH sessions could remain open indefinitely, consuming resources and potentially providing an opportunity for session hijacking. This control works in conjunction with VCFE-9X-000211 (ClientAliveInterval) to enforce SSH session timeout. This control supports the requirements of NIST SP 800-53 AC-11 and AC-12."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep clientalivecountmax

Verify the Value field is 3. If the value is not 3, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'clientalivecountmax'} | Select-Object Key, Value

If the Value returned is not '3', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k clientalivecountmax -v 3

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'clientalivecountmax'
`$sshsargs.value = '3'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000211"
        Title        = "The ESX host Secure Shell (SSH) daemon must set a timeout interval on idle sessions."
        Severity     = "medium"
        GroupTitle   = "SSH ClientAliveInterval"
        Vuln_Discuss = "The ClientAliveInterval setting specifies the number of seconds the SSH daemon waits before sending a keepalive message to the client to check whether the client is still connected and responsive. This mechanism is used to detect and terminate idle or unresponsive SSH sessions. Without a ClientAliveInterval configured, the SSH daemon may not detect disconnected or idle sessions in a timely manner, allowing these sessions to persist indefinitely. An idle authenticated SSH session represents a security risk because anyone who gains access to the terminal where the session originated could use the session to interact with the ESXi host. Combined with ClientAliveCountMax, this setting determines the effective session timeout for unresponsive SSH connections. This control supports the requirements of NIST SP 800-53 AC-11 and AC-12."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep clientaliveinterval

Verify the Value field is 200 or less but not 0. If the value is 0 or greater than 200, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'clientaliveinterval'} | Select-Object Key, Value

If the Value returned is 0 or greater than 200, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k clientaliveinterval -v 200

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'clientaliveinterval'
`$sshsargs.value = '200'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000212"
        Title        = "The ESX host Secure Shell (SSH) daemon must disable port forwarding."
        Severity     = "medium"
        GroupTitle   = "SSH AllowTCPForwarding"
        Vuln_Discuss = "SSH TCP port forwarding allows users to tunnel arbitrary TCP connections through an SSH session. This capability is often used legitimately for secure access to services, but in a hardened ESXi environment it can be exploited to bypass network access controls. An attacker who gains SSH access to an ESXi host could use TCP forwarding to establish tunnels that allow communication with systems that would otherwise be unreachable due to firewall rules, route traffic through the ESXi management network to reach internal systems, or create persistent covert communication channels that evade network monitoring. Disabling TCP forwarding prevents SSH from being used as a network bypass mechanism while still allowing its use for management command-line access. This is distinct from gateway ports (VCFE-9X-000207) in that it applies to local and remote forwarding regardless of whether remote hosts can connect to forwarded ports. This control supports the requirements of NIST SP 800-53 CM-7 and SC-7."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep allowtcpforwarding

Verify the Value field is 'no'. If the value is 'yes', this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'allowtcpforwarding'} | Select-Object Key, Value

If the Value returned is not 'no', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k allowtcpforwarding -v no

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'allowtcpforwarding'
`$sshsargs.value = 'no'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000213"
        Title        = "The ESX host Secure Shell (SSH) daemon must ignore .rhosts files."
        Severity     = "medium"
        GroupTitle   = "SSH IgnoreRhosts"
        Vuln_Discuss = "The .rhosts file is a legacy Unix authentication mechanism that allows users to specify trusted remote hosts and users who can authenticate without a password. This mechanism is fundamentally insecure because it relies solely on the source IP address for authentication, which can be spoofed, and because any user who can write to the .rhosts file in a user's home directory can grant themselves passwordless access. SSH IgnoreRhosts instructs the SSH daemon to disregard .rhosts and .shosts files for authentication decisions. Even though ESXi does not use traditional home directories in the same way as a general-purpose Unix system, explicitly disabling rhosts-based authentication ensures that this legacy authentication bypass cannot be exploited if any configuration or files are present. This control supports the requirements of NIST SP 800-53 IA-2 and CM-7."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep ignorerhosts

Verify the Value field is 'yes'. If the value is 'no', this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'ignorerhosts'} | Select-Object Key, Value

If the Value returned is not 'yes', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k ignorerhosts -v yes

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'ignorerhosts'
`$sshsargs.value = 'yes'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000214"
        Title        = "The ESX host Secure Shell (SSH) daemon must not allow host-based authentication."
        Severity     = "medium"
        GroupTitle   = "SSH HostbasedAuthentication"
        Vuln_Discuss = "Host-based authentication is a method in which authentication is based on the identity of the source host rather than the individual user. When host-based authentication is enabled, a user from a trusted host can authenticate to the SSH daemon without providing a password, relying solely on the trusted status of the source host. This is fundamentally insecure because it means that compromise of a trusted host provides automatic access to all accounts on the ESXi host that trust it. Host-based authentication also bypasses individual accountability since the user is authenticated based on host identity rather than individual credentials. This legacy authentication method should not be used on production systems where individual accountability and strong authentication are required. All authentication to ESXi SSH must use individual credentials. This control supports the requirements of NIST SP 800-53 IA-2 and CM-7."
        CheckText    = "From an ESXi shell, run:
esxcli system ssh server config list | grep hostbasedauthentication

Verify the Value field is 'no'. If the value is 'yes', this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.ssh.server.config.list.invoke() | Where-Object {`$_.Key -eq 'hostbasedauthentication'} | Select-Object Key, Value

If the Value returned is not 'no', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system ssh server config set -k hostbasedauthentication -v no

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sshsargs = `$esxcli.system.ssh.server.config.set.CreateArgs()
`$sshsargs.keyword = 'hostbasedauthentication'
`$sshsargs.value = 'no'
`$esxcli.system.ssh.server.config.set.Invoke(`$sshsargs)"
    },
    @{
        RuleID       = "VCFE-9X-000215"
        Title        = "The ESX host must disable Simple Network Management Protocol (SNMP) v1 and v2c."
        Severity     = "high"
        GroupTitle   = "Disable SNMP v1/v2c"
        Vuln_Discuss = "SNMP versions 1 and 2c use community strings for authentication, which are transmitted in cleartext across the network. These community strings function as shared passwords and provide access to the SNMP management information base (MIB) of the device. An attacker who can capture network traffic on a segment where SNMP v1 or v2c traffic is present can trivially obtain the community string and use it to read potentially sensitive configuration and status information from the ESXi host, and if write access is configured, could potentially modify SNMP-configurable parameters. SNMP v3 provides significantly stronger security through support for encryption and message authentication. If SNMP is required for monitoring, only SNMP v3 with authentication and privacy (authPriv) mode should be configured. SNMP v1 and v2c community strings must be removed or SNMP must be disabled entirely. This control supports the requirements of NIST SP 800-53 CM-7 and IA-3."
        CheckText    = "Note: The Get-VMHostSnmp cmdlet only functions when connected directly to an ESXi host, not through vCenter.

From a PowerCLI session connected directly to the ESXi host (not via vCenter):
Connect-VIServer -Server <esxi_host_ip> -User root
Get-VMHostSnmp | Select-Object Enabled, Communities, V3Targets

If Enabled is True and any Communities are listed (indicating v1/v2c is in use), this is a finding.

Alternatively, from an ESXi shell:
esxcli system snmp get

If Enabled is true and communities are configured, this is a finding."
        FixText      = "From a PowerCLI session connected directly to the ESXi host:
Connect-VIServer -Server <esxi_host_ip> -User root
Set-VMHostSnmp -Enabled `$false

Or to remove only v1/v2c community strings while keeping SNMPv3:
Get-VMHostSnmp | Set-VMHostSnmp -RemoveCommunity '<community_string>'

Alternatively, from an ESXi shell:
esxcli system snmp set --enable false

Note: This rule must be remediated manually with direct host connection. If SNMP monitoring is required, configure only SNMPv3 with authentication and privacy."
    },
    @{
        RuleID       = "VCFE-9X-000216"
        Title        = "The ESX host must configure the firewall to block network traffic by default."
        Severity     = "medium"
        GroupTitle   = "Default Firewall Policy"
        Vuln_Discuss = "The ESXi firewall provides host-based network access control for the management interfaces of the ESXi host. Without a default deny firewall policy, any network service that is running on the ESXi host is potentially reachable from any system that has network connectivity to the host's management interface. A default deny policy means that all inbound and outbound traffic is blocked unless explicitly permitted by a firewall rule. This significantly reduces the attack surface of the ESXi host by ensuring that only traffic to explicitly authorized services is allowed. Without a default deny policy, newly started services or services whose firewall rules are misconfigured may be inadvertently exposed to unauthorized network access. The ESXi firewall must be both enabled and configured with a default drop action. This control supports the requirements of NIST SP 800-53 SC-7 and CM-7."
        CheckText    = "From an ESXi shell, run:
esxcli network firewall get

Verify the Enabled field is true and the DefaultAction field is DROP. If the firewall is disabled or DefaultAction is PASS, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.network.firewall.get.invoke() | Select-Object DefaultAction, Enabled, Loaded

If Enabled is not true or DefaultAction is not 'DROP', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli network firewall set --enabled true --default-action false

Note: '--default-action false' sets the default action to DROP.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$fwargs = `$esxcli.network.firewall.set.CreateArgs()
`$fwargs.enabled = `$true
`$fwargs.defaultaction = `$false
`$esxcli.network.firewall.set.Invoke(`$fwargs)"
    },
    @{
        RuleID       = "VCFE-9X-000217"
        Title        = "The ESX host must configure the firewall to restrict access to services running on the host."
        Severity     = "medium"
        GroupTitle   = "Firewall Rules"
        Vuln_Discuss = "The ESXi firewall supports per-service IP-based access restrictions that allow administrators to configure which IP addresses or subnets are permitted to connect to each service running on the host. When user-configurable firewall rules are set to allow all IP addresses, any system that can reach the ESXi management network can attempt to connect to those services. Restricting firewall rules to only authorized IP ranges ensures that even if an unauthorized system gains access to the management network, it cannot connect to ESXi services. This defense-in-depth measure complements network-level access controls such as VLAN segmentation and reduces the impact of a management network breach. Service-level IP restrictions also limit the attack surface available to any system that has been compromised on the management network. This control supports the requirements of NIST SP 800-53 SC-7 and AC-3."
        CheckText    = "From an ESXi shell, run:
esxcli network firewall ruleset list

Review all enabled, user-configurable rulesets and verify AllowedIPAddresses does not show 'All' unless there is a documented and approved exception.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$fwsys = Get-View (Get-VMHost -Name <hostname>).ExtensionData.ConfigManager.FirewallSystem
`$fwsys.FirewallInfo.Ruleset | Where-Object {`$_.IpListUserConfigurable -and `$_.Enabled -and `$_.AllowedHosts.AllIp} | Select-Object Key, Label

If any enabled user-configurable ruleset has AllowedHosts.AllIp set to True without a documented exception, this is a finding."
        FixText      = "From an ESXi shell, for each service that should be restricted:
esxcli network firewall ruleset allowedip add --ruleset-id=<service_id> --ip-address=<authorized_cidr>
esxcli network firewall ruleset set --ruleset-id=<service_id> --allowed-all=false

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$fwsys = Get-View (Get-VMHost -Name <hostname>).ExtensionData.ConfigManager.FirewallSystem
`$rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
`$rulesetIpListSpec.allIp = `$false
`$network = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
`$network.network = '<network_address>'
`$network.prefixLength = <prefix_length>
`$rulesetIpListSpec.ipNetwork = @(`$network)
`$rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
`$rulesetSpec.allowedHosts = `$rulesetIpListSpec
`$fwsys.UpdateRuleset('<ruleset_id>', `$rulesetSpec)"
    },
    @{
        RuleID       = "VCFE-9X-000218"
        Title        = "The ESX host must enable Bridge Protocol Data Units (BPDU) filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
        Severity     = "medium"
        GroupTitle   = "BlockGuestBPDU"
        Vuln_Discuss = "Bridge Protocol Data Units (BPDUs) are used by the Spanning Tree Protocol (STP) to prevent network loops. Physical network switches with PortFast and BPDU Guard enabled will shut down switch ports if they receive BPDU frames. A virtual machine on an ESXi host could generate BPDU frames, either intentionally as part of a denial-of-service attack or unintentionally through misconfiguration, causing the physical switch port connected to the ESXi host to be disabled by BPDU Guard. This would result in the ESXi host losing network connectivity, making it unreachable for management and potentially causing the VMs running on it to lose network access. Enabling Net.BlockGuestBPDU prevents VMs from sending BPDU frames out of the virtual switch, protecting the physical switching infrastructure from this class of attack. This control supports the requirements of NIST SP 800-53 SC-5 and SI-17."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Net.BlockGuestBPDU and verify the value is set to 1.

If the value is 0, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Net.BlockGuestBPDU

If the value returned is not 1, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Net.BlockGuestBPDU, and set the value to 1.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000219"
        Title        = "The ESX host must configure virtual switch security policies to reject forged transmits."
        Severity     = "medium"
        GroupTitle   = "Forged Transmits"
        Vuln_Discuss = "The Forged Transmits policy on a virtual switch controls whether a virtual machine is allowed to send network frames with a source MAC address different from the MAC address configured in the VM's network adapter settings. When forged transmits are allowed, a VM can send traffic appearing to originate from any MAC address. This can be used to impersonate other VMs or network devices, launch man-in-the-middle attacks, or bypass MAC address-based network access controls. Rejecting forged transmits ensures that VMs can only send traffic with their assigned MAC addresses, maintaining the integrity of the virtual network and preventing MAC address spoofing within the virtual switching infrastructure. This control should be applied at both the virtual switch and port group levels. This control supports the requirements of NIST SP 800-53 SC-7 and SI-3."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each standard virtual switch, click Edit and review the Security tab. Verify Forged Transmits is set to Reject.

Also review each port group by selecting the port group and clicking Edit >> Security. Verify Forged Transmits is set to Reject or is set to inherit the switch-level setting of Reject.

If Forged Transmits is set to Accept on any virtual switch or port group, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualSwitch -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Select-Object VirtualSwitch, ForgedTransmits
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Select-Object VirtualPortGroup, ForgedTransmits, ForgedTransmitsInherited

If ForgedTransmits is True on any switch, or ForgedTransmits is True and ForgedTransmitsInherited is False on any port group, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each virtual switch, click Edit >> Security and set Forged Transmits to Reject. Repeat for each port group as needed.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualSwitch -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits `$false -Confirm:`$false
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited `$true -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000220"
        Title        = "The ESX host must configure virtual switch security policies to reject Media Access Control (MAC) address changes."
        Severity     = "medium"
        GroupTitle   = "MAC Address Changes"
        Vuln_Discuss = "The MAC Address Changes policy on a virtual switch controls whether a virtual machine guest operating system is allowed to change the effective MAC address of a virtual network adapter to a value different from the initial MAC address configured at the vSphere layer. If MAC address changes are allowed, the guest OS can change its MAC address to impersonate another network device or VM, potentially intercepting traffic intended for another system or bypassing MAC address-based access controls. Rejecting MAC address changes ensures that the guest OS cannot change the effective MAC address of the virtual adapter, maintaining the integrity of MAC-based network policies and preventing MAC spoofing from within guest operating systems. This control complements the Forged Transmits policy and should be applied at both the virtual switch and port group levels. This control supports the requirements of NIST SP 800-53 SC-7 and SI-3."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each standard virtual switch, click Edit and review the Security tab. Verify MAC Address Changes is set to Reject.

Also review each port group by selecting the port group and clicking Edit >> Security. Verify MAC Address Changes is set to Reject or is set to inherit the switch-level setting of Reject.

If MAC Address Changes is set to Accept on any virtual switch or port group, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualSwitch -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Select-Object VirtualSwitch, MacChanges
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Select-Object VirtualPortGroup, MacChanges, MacChangesInherited

If MacChanges is True on any switch, or MacChanges is True and MacChangesInherited is False on any port group, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each virtual switch, click Edit >> Security and set MAC Address Changes to Reject. Repeat for each port group as needed.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualSwitch -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges `$false -Confirm:`$false
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited `$true -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000221"
        Title        = "The ESX host must configure virtual switch security policies to reject promiscuous mode requests."
        Severity     = "medium"
        GroupTitle   = "Promiscuous Mode"
        Vuln_Discuss = "When a virtual network adapter is placed in promiscuous mode, it can receive all network traffic on the virtual switch segment, including traffic not addressed to that adapter. In a physical network, promiscuous mode is used for legitimate purposes such as network monitoring and packet capture, but it can also be used maliciously to capture credentials and sensitive data from other systems on the network segment. On a virtual switch, enabling promiscuous mode for a VM allows that VM to see all traffic on the virtual switch, including traffic between other VMs on the same host. This is particularly concerning because the virtual switch traffic does not leave the host and therefore cannot be monitored by external network security devices. Rejecting promiscuous mode requests ensures that VMs cannot be placed into promiscuous mode to capture traffic from neighboring VMs. This control supports the requirements of NIST SP 800-53 SC-7 and AU-9."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each standard virtual switch, click Edit and review the Security tab. Verify Promiscuous Mode is set to Reject.

Also review each port group by selecting the port group and clicking Edit >> Security. Verify Promiscuous Mode is set to Reject or is set to inherit the switch-level setting of Reject.

If Promiscuous Mode is set to Accept on any virtual switch or port group, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualSwitch -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Select-Object VirtualSwitch, AllowPromiscuous
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Select-Object VirtualPortGroup, AllowPromiscuous, AllowPromiscuousInherited

If AllowPromiscuous is True on any switch, or AllowPromiscuous is True and AllowPromiscuousInherited is False on any port group, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each virtual switch, click Edit >> Security and set Promiscuous Mode to Reject. Repeat for each port group as needed.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualSwitch -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous `$false -Confirm:`$false
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited `$true -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000222"
        Title        = "The ESX host must restrict use of the dvFilter network application programming interface (API)."
        Severity     = "medium"
        GroupTitle   = "dvFilter Bind IP"
        Vuln_Discuss = "The dvFilter API allows third-party network security solutions to attach to virtual machine network adapters and inspect or modify network traffic at the hypervisor level. The Net.DVFilterBindIpAddress advanced setting specifies which IP address the dvFilter framework should bind to for management communications. If this setting is configured with an IP address when dvFilter solutions are not in use, it creates an unnecessary network endpoint that could be targeted by attackers. The dvFilter API provides deep access to VM network communications and any vulnerability in this subsystem could potentially allow an attacker to intercept or modify VM network traffic. The setting should be empty unless dvFilter-based network security products are explicitly deployed and authorized. This control supports the requirements of NIST SP 800-53 CM-7 and SC-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Net.DVFilterBindIpAddress and verify the value is empty.

If the value is not empty and dvFilter network security solutions are not authorized and deployed, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Select-Object Name, Value

If the Value is not empty and no dvFilter products are authorized, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Net.DVFilterBindIpAddress, and set the value to empty.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value '' -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000223"
        Title        = "The ESX host must restrict the use of Virtual Guest Tagging (VGT) on standard switches."
        Severity     = "medium"
        GroupTitle   = "Virtual Guest Tagging"
        Vuln_Discuss = "Virtual Guest Tagging (VGT) mode is configured by setting a port group's VLAN ID to 4095, which causes all VLAN-tagged frames to be passed through to the guest VM with the VLAN tags intact. This allows the guest VM to process the 802.1Q VLAN tags directly. While VGT has legitimate use cases, it also introduces security risks. A VM with VGT access can potentially access VLANs beyond those intended for it if it sends frames with VLAN tags for other VLANs. A compromised or malicious VM could use VGT to reach VLANs that should be inaccessible to it, potentially bypassing network segmentation controls. VGT port groups should only be used where explicitly required and justified, and their use should be documented. This control supports the requirements of NIST SP 800-53 SC-7 and CM-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each standard virtual switch, review the port groups and verify that no port group has a VLAN ID of 4095 unless it is explicitly documented as required.

If any port group has VLAN ID set to 4095 without documented authorization, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard | Where-Object {`$_.VlanId -eq 4095} | Select-Object Name, VlanId

If any results are returned and VGT is not documented as required for those port groups, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> Networking >> Virtual Switches. For each port group with VLAN ID 4095 that is not authorized, click Edit and change the VLAN ID to the appropriate VLAN for that port group.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VirtualPortGroup -VMHost (Get-VMHost -Name <hostname>) -Standard -Name '<portgroup_name>' | Set-VirtualPortGroup -VlanId <appropriate_vlan_id>

Note: Replace <portgroup_name> and <appropriate_vlan_id> with the actual port group name and correct VLAN ID for the environment."
    },
    @{
        RuleID       = "VCFE-9X-000224"
        Title        = "The ESX host must not suppress warnings that the local or remote shell sessions are enabled."
        Severity     = "low"
        GroupTitle   = "Suppress Shell Warning"
        Vuln_Discuss = "ESXi displays warnings in the vSphere Client when the ESXi Shell or SSH service is enabled to alert administrators that these high-risk services are running. These warnings serve as a security awareness mechanism to ensure that administrators are aware when these services are active, particularly if they were enabled for temporary troubleshooting and not subsequently disabled. Suppressing these warnings removes a valuable security signal that could alert administrators to an unauthorized enablement of shell services, whether by a malicious actor or through administrative error. The SuppressShellWarning setting should remain at 0 to ensure that shell service warnings are displayed prominently in the vSphere Client. This control supports the requirements of NIST SP 800-53 SI-5 and AU-6."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting UserVars.SuppressShellWarning and verify the value is set to 0.

If the value is 1, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.SuppressShellWarning

If the value returned is 1, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate UserVars.SuppressShellWarning, and set the value to 0.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 0 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000225"
        Title        = "The ESX host must enable volatile key destruction."
        Severity     = "medium"
        GroupTitle   = "Mem EagerZero"
        Vuln_Discuss = "When a virtual machine is powered off or a memory page is released, that memory may contain sensitive data from the previous VM's workload, including encryption keys, credentials, and other confidential information. Without volatile key destruction, this residual data may persist in physical memory and could potentially be read by another VM that is subsequently allocated those same memory pages, creating a data remanence vulnerability. The Mem.MemEagerZero setting, when set to 1, causes ESXi to zero out memory pages before allocating them to a new VM, ensuring that residual data from previous workloads is destroyed before the memory is reused. This is particularly important in multi-tenant or shared infrastructure environments where different security domains may share the same physical host. This control supports the requirements of NIST SP 800-53 MP-6 and SC-4."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Mem.MemEagerZero and verify the value is set to 1.

If the value is 0, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Mem.MemEagerZero

If the value returned is not 1, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Mem.MemEagerZero, and set the value to 1.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Mem.MemEagerZero | Set-AdvancedSetting -Value 1 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000226"
        Title        = "The ESX host must configure a session timeout for the vSphere API."
        Severity     = "medium"
        GroupTitle   = "SOAP API Timeout"
        Vuln_Discuss = "The vSphere API provides programmatic access to ESXi host management functions through a SOAP-based web service. API sessions that are established but left idle can persist indefinitely unless a session timeout is configured. An idle API session with an authenticated context represents a security risk because any system that can interact with that session could potentially use the authenticated context to perform management operations. Without a session timeout, automation scripts, management tools, or malicious processes could exploit long-lived API sessions to perform unauthorized management operations. Configuring a 30-minute session timeout ensures that idle API sessions are automatically invalidated, requiring reauthentication. This is particularly important given the powerful capabilities available through the vSphere API. This control supports the requirements of NIST SP 800-53 AC-11 and AC-12."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.HostAgent.vmacore.soap.sessionTimeout and verify the value is 30 or less but not 0.

If the value is 0 or greater than 30, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout

If the value returned is 0 or greater than 30, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.HostAgent.vmacore.soap.sessionTimeout, and set the value to 30.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Set-AdvancedSetting -Value 30 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000227"
        Title        = "The ESX host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
        Severity     = "medium"
        GroupTitle   = "Suppress Hyperthreading Warning"
        Vuln_Discuss = "Hyperthreading vulnerabilities such as L1 Terminal Fault (L1TF), MDS (Microarchitectural Data Sampling), and related speculative execution side-channel attacks can allow a malicious VM or process to potentially read data from the memory of co-located workloads sharing the same physical CPU core. ESXi detects when these vulnerabilities are present and displays warnings in the vSphere Client to alert administrators. Suppressing these warnings prevents administrators from being aware of the vulnerability status of the host's hardware and whether appropriate mitigations such as Hyper-Threading disablement or microcode updates are needed. These warnings are an important security awareness mechanism that ensures administrators can make informed decisions about workload placement and hardware mitigation requirements. The SuppressHyperthreadWarning setting must remain at 0 to ensure warnings are displayed. This control supports the requirements of NIST SP 800-53 SI-2 and SI-5."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting UserVars.SuppressHyperthreadWarning and verify the value is set to 0.

If the value is 1, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning

If the value returned is 1, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate UserVars.SuppressHyperthreadWarning, and set the value to 0.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Set-AdvancedSetting -Value 0 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000228"
        Title        = "The ESX host must only run binaries from signed VIBs."
        Severity     = "high"
        GroupTitle   = "execInstalledOnly"
        Vuln_Discuss = "The execInstalledOnly boot option configures the ESXi kernel to only execute binaries that are part of a signed and installed VIB package. Without this restriction, arbitrary executables that may have been placed on the host through exploitation of a vulnerability or through unauthorized access could be executed with kernel-level privileges. This is a critical defense against persistence mechanisms that attackers might use after initially compromising an ESXi host, as any malicious code would need to be installed as a signed VIB to survive and execute. Combined with a restrictive VIB acceptance level (VCFE-9X-000130) and execInstalledOnly enforcement in the encryption settings (VCFE-9X-000229), this setting creates a comprehensive defense against unauthorized code execution at the hypervisor level. This control supports the requirements of NIST SP 800-53 CM-5, SI-7, and CM-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting VMkernel.Boot.execInstalledOnly and verify the value is set to true.

If the value is false, this is a finding.

Note: A reboot is required for changes to this setting to take effect. Verify the current boot value, not just the configured value.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly

If the value returned is not 'true', this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate VMkernel.Boot.execInstalledOnly, and set the value to true.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Set-AdvancedSetting -Value 'true' -Confirm:`$false

Note: A reboot of the ESXi host is required for this setting to take effect."
    },
    @{
        RuleID       = "VCFE-9X-000229"
        Title        = "The ESX host must enable execInstalledOnly enforcement for configuration encryption."
        Severity     = "high"
        GroupTitle   = "execInstalledOnly Enforcement"
        Vuln_Discuss = "The RequireExecutablesOnlyFromInstalledVIBs setting in the configuration encryption subsystem extends the protection of execInstalledOnly to the configuration encryption key handling. When this setting is enabled, the configuration encryption subsystem will not function if the execInstalledOnly boot option is not enforced. This creates a dependency between the execution restriction mechanism and the encryption system, ensuring that if an attacker disables the execInstalledOnly boot option to allow arbitrary code execution, the configuration encryption will also be disabled, preventing the encrypted configuration from being decrypted on that modified host. This interdependency makes it significantly more difficult for an attacker to both disable execution restrictions and maintain access to the encrypted configuration data. This control works together with VCFE-9X-000228 and VCFE-9X-000082 to create a layered security posture. This control supports the requirements of NIST SP 800-53 SI-7, SC-28, and CM-5."
        CheckText    = "From an ESXi shell, run:
esxcli system settings encryption get

Verify the RequireExecutablesOnlyFromInstalledVIBs field is True. If the value is False, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.settings.encryption.get.invoke() | Select-Object RequireExecutablesOnlyFromInstalledVIBs, Mode, RequireSecureBoot

If RequireExecutablesOnlyFromInstalledVIBs is not True, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system settings encryption set --require-exec-installed-only=TRUE

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$sbarg = `$esxcli.system.settings.encryption.set.CreateArgs()
`$sbarg.requireexecinstalledonly = `$true
`$esxcli.system.settings.encryption.set.Invoke(`$sbarg)"
    },
    @{
        RuleID       = "VCFE-9X-000230"
        Title        = "The ESX host must enable strict x509 verification for SSL syslog endpoints."
        Severity     = "medium"
        GroupTitle   = "Syslog x509 Strict"
        Vuln_Discuss = "When ESXi forwards log data to remote syslog servers over an SSL/TLS connection, it must verify the identity of the remote server to prevent man-in-the-middle attacks. Without strict x509 certificate verification, the ESXi host might accept connections to malicious syslog servers that present invalid, self-signed, or otherwise untrusted certificates. An attacker who can intercept or redirect syslog traffic could potentially receive audit records intended for the legitimate syslog server, providing insight into the activity on the ESXi host while also preventing the legitimate syslog server from receiving complete audit data. Strict x509 compliance ensures that the remote syslog server's certificate chain is fully validated against trusted certificate authorities before log data is transmitted, maintaining both the confidentiality of audit data and the authenticity of the destination. This control supports the requirements of NIST SP 800-53 AU-9, SC-8, and IA-5."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Syslog.global.certificate.strictX509Compliance and verify the value is set to true.

If the value is false, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance

If the value returned is not True, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Syslog.global.certificate.strictX509Compliance, and set the value to true.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Syslog.global.certificate.strictX509Compliance | Set-AdvancedSetting -Value `$true -Confirm:`$false

Note: Ensure that the syslog server's certificate is issued by a CA that is trusted by the ESXi host before enabling this setting to avoid disrupting log forwarding."
    },
    @{
        RuleID       = "VCFE-9X-000232"
        Title        = "The ESX host must not be configured to override virtual machine (VM) configurations."
        Severity     = "medium"
        GroupTitle   = "/etc/vmware/settings"
        Vuln_Discuss = "The /etc/vmware/settings file on an ESXi host allows host-level overrides of virtual machine advanced configuration parameters. If this file contains entries that override VM configuration settings, those overrides apply to all virtual machines on the host without the knowledge of the VM administrators. This capability, while available for certain administrative use cases, could be misused to apply unauthorized configuration changes to VMs, potentially weakening security settings that have been deliberately configured at the VM level. Furthermore, host-level overrides of VM settings can create inconsistencies between the documented and actual configuration of VMs, complicating security audits and compliance verification. The settings file should not contain VM configuration overrides unless they are explicitly required and documented. This control supports the requirements of NIST SP 800-53 CM-7 and CM-6."
        CheckText    = "From an ESXi shell, run:
cat /etc/vmware/settings

Verify the file does not contain any override parameters that would modify virtual machine advanced configuration settings. Legitimate entries in this file are limited to specific host-level parameters.

If the file contains any lines in the format 'vmx.<parameter> = <value>' or similar VM configuration override entries, this is a finding.

Note: This check requires direct shell access and cannot be performed via vSphere Client or PowerCLI."
        FixText      = "From an ESXi shell, edit /etc/vmware/settings and remove any unauthorized VM configuration override entries.

Note: This rule requires direct ESXi shell access and must be remediated manually. Exercise caution when editing this file as incorrect modifications can affect host operation. Create a backup before modifying."
    },
    @{
        RuleID       = "VCFE-9X-000233"
        Title        = "The ESX host must not be configured to override virtual machine (VM) logger settings."
        Severity     = "medium"
        GroupTitle   = "/etc/vmware/config"
        Vuln_Discuss = "The /etc/vmware/config file on an ESXi host can contain host-level configuration entries that override virtual machine logging settings. VM logging records actions performed against and within virtual machines, which is essential for forensic investigation and security monitoring. If host-level configuration overrides are used to alter VM logging settings, the logging configuration documented and configured at the VM level may not accurately reflect the actual logging behavior. This could result in insufficient logging, disabled logging, or logging directed to unauthorized destinations. Unauthorized modification of logging settings is a common tactic used by attackers to obscure their activities and evade detection. The /etc/vmware/config file should not contain VM logger configuration overrides. This control supports the requirements of NIST SP 800-53 AU-2, AU-12, and CM-6."
        CheckText    = "From an ESXi shell, run:
cat /etc/vmware/config

Verify the file does not contain any log.* entries or other parameters that would override virtual machine logger settings.

If the file contains log.* entries or other VM logging configuration overrides that are not documented and authorized, this is a finding.

Note: This check requires direct shell access and cannot be performed via vSphere Client or PowerCLI."
        FixText      = "From an ESXi shell, edit /etc/vmware/config and remove any unauthorized VM logger configuration override entries such as log.* parameters.

Note: This rule requires direct ESXi shell access and must be remediated manually. Exercise caution when editing this file. Create a backup before modifying."
    },
    @{
        RuleID       = "VCFE-9X-000234"
        Title        = "The ESX host must use sufficient entropy for cryptographic operations."
        Severity     = "medium"
        GroupTitle   = "Entropy Sources"
        Vuln_Discuss = "Cryptographic operations depend on random number generation for key generation, nonces, and other security-critical values. If the entropy sources available to the ESXi host are insufficient or predictable, the random numbers generated for cryptographic purposes may be predictable, weakening the security of all cryptographic operations performed by the host including TLS session establishment, key generation, and authentication operations. The hardware random number generator (HWRNG) provides a source of true randomness derived from physical processes, significantly improving the quality of random numbers available for cryptographic operations. Disabling the HWRNG (disableHwrng=TRUE) removes this entropy source and forces reliance solely on software-based entropy collection, which may be less robust particularly during early boot or in resource-constrained scenarios. The entropySources setting controls which sources of entropy are used. These settings must be configured to ensure adequate entropy is available for cryptographic operations. This control supports the requirements of NIST SP 800-53 SC-12 and IA-7."
        CheckText    = "From an ESXi shell, run:
esxcli system settings kernel list | grep -E 'disableHwrng|entropySources'

Verify that disableHwrng shows a Configured value of FALSE and entropySources shows a Configured value of 0. If either value is not as expected, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.settings.kernel.list.invoke() | Where-Object {`$_.Name -in 'disableHwrng','entropySources'} | Select-Object Name, Configured, Default

If disableHwrng Configured is not 'FALSE' or entropySources Configured is not '0', this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system settings kernel set --setting=disableHwrng --value=FALSE
esxcli system settings kernel set --setting=entropySources --value=0

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$enthwargs = `$esxcli.system.settings.kernel.set.CreateArgs()
`$enthwargs.setting = 'disableHwrng'
`$enthwargs.value = 'FALSE'
`$esxcli.system.settings.kernel.set.invoke(`$enthwargs)
`$entsrcargs = `$esxcli.system.settings.kernel.set.CreateArgs()
`$entsrcargs.setting = 'entropySources'
`$entsrcargs.value = '0'
`$esxcli.system.settings.kernel.set.invoke(`$entsrcargs)"
    },
    @{
        RuleID       = "VCFE-9X-000235"
        Title        = "The ESX host must not enable log filtering."
        Severity     = "medium"
        GroupTitle   = "Log Filtering"
        Vuln_Discuss = "Log filtering on ESXi allows certain log messages to be suppressed from being written to the syslog. While log filtering might be used to reduce log noise in certain scenarios, it represents a significant risk to audit integrity. If log filtering is enabled, security-relevant events may be filtered out and never written to the audit record, potentially allowing malicious activity to go undetected and unrecorded. An attacker who is aware of the filtering configuration could deliberately trigger events that match the filter criteria to avoid logging their activities. The completeness and integrity of audit records is a fundamental security requirement, and any mechanism that can selectively suppress log entries undermines this requirement. Log filtering must be disabled to ensure all events are recorded. This control supports the requirements of NIST SP 800-53 AU-2, AU-9, and AU-12."
        CheckText    = "From an ESXi shell, run:
esxcli system syslog config logfilter get

Verify the LogFilteringEnabled field is false. If LogFilteringEnabled is true, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object LogFilteringEnabled

If LogFilteringEnabled is not False, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system syslog config logfilter set --log-filtering-enabled=FALSE

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$lfargs = `$esxcli.system.syslog.config.logfilter.set.CreateArgs()
`$lfargs.logfilteringenabled = `$false
`$esxcli.system.syslog.config.logfilter.set.invoke(`$lfargs)"
    },
    @{
        RuleID       = "VCFE-9X-000236"
        Title        = "The ESX host must disable key persistence."
        Severity     = "high"
        GroupTitle   = "Key Persistence"
        Vuln_Discuss = "ESXi key persistence is a feature that allows encryption keys to be stored persistently on the host so that encrypted VMs can be automatically unlocked after a host reboot without requiring manual key retrieval from a key management server. While this feature provides operational convenience, it introduces significant security risks because it means that encryption keys are stored on the same physical media as the encrypted data. If an attacker gains physical access to the host or its storage media, they may be able to access both the encrypted data and the keys needed to decrypt it, defeating the purpose of encryption. Disabling key persistence ensures that encryption keys must be retrieved from a key management server on each boot, maintaining proper separation between encrypted data and the keys needed to decrypt it. This is a critical control for protecting encrypted VM data. This control supports the requirements of NIST SP 800-53 SC-12, SC-28, and IA-5."
        CheckText    = "From an ESXi shell, run:
esxcli system security keypersistence get

Verify the Enabled field is false. If Enabled is true, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.security.keypersistence.get.invoke() | Select-Object Enabled

If Enabled is not False, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system security keypersistence disable --remove-all-stored-keys=TRUE

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$kpargs = `$esxcli.system.security.keypersistence.disable.CreateArgs()
`$kpargs.removeallstoredkeys = `$true
`$esxcli.system.security.keypersistence.disable.invoke(`$kpargs)

Note: Disabling key persistence with --remove-all-stored-keys=TRUE will remove any currently stored keys. Ensure encrypted VMs can obtain their keys from the key management server before applying this change."
    },
    @{
        RuleID       = "VCFE-9X-000237"
        Title        = "The ESX host must deny shell access for the dcui account."
        Severity     = "medium"
        GroupTitle   = "DCUI Shell Access"
        Vuln_Discuss = "The dcui account is a system account used by the Direct Console User Interface (DCUI) process for process isolation purposes. This account is not intended to be used for interactive shell access. If shell access is enabled for the dcui account, it could potentially be exploited to gain a shell on the ESXi host by interacting with the DCUI process in unintended ways. Denying shell access for the dcui account follows the principle of least privilege by restricting the account to only the capabilities it requires for its designed purpose. The dcui account should only have the permissions necessary to run the DCUI process and should not have the ability to spawn an interactive shell. This control supports the requirements of NIST SP 800-53 AC-6 and CM-7."
        CheckText    = "From an ESXi shell, run:
esxcli system account list | grep -A3 dcui

Verify the Shellaccess field for the dcui account is false. If Shellaccess is true, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$esxcli.system.account.list.Invoke() | Where-Object {`$_.UserID -eq 'dcui'} | Select-Object UserID, Shellaccess

If Shellaccess is not False, this is a finding."
        FixText      = "From an ESXi shell, run:
esxcli system account set -i dcui -s false

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
`$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name <hostname>) -V2
`$dcuisaargs = `$esxcli.system.account.set.CreateArgs()
`$dcuisaargs.id = 'dcui'
`$dcuisaargs.shellaccess = 'false'
`$esxcli.system.account.set.invoke(`$dcuisaargs)"
    },
    @{
        RuleID       = "VCFE-9X-000238"
        Title        = "The ESX host must disable virtual hardware management network interfaces."
        Severity     = "medium"
        GroupTitle   = "BMC Network"
        Vuln_Discuss = "Some ESXi hosts have a Baseboard Management Controller (BMC) or equivalent out-of-band management interface that may be accessible through the host's virtual networking stack in addition to its dedicated out-of-band management port. The Net.BMCNetworkEnable setting controls whether the BMC network interface is accessible through the ESXi virtual networking infrastructure. If enabled, this creates an additional network pathway to the BMC that may be accessible from the VM networks or management network without the access controls that are typically applied to dedicated BMC management networks. The BMC provides very powerful out-of-band management capabilities including console access, power management, and firmware updates. Disabling this in-band access to the BMC ensures that it is only accessible through its dedicated out-of-band management interface with the appropriate network access controls applied. This control supports the requirements of NIST SP 800-53 CM-7 and SC-7."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Net.BMCNetworkEnable and verify the value is set to 0.

If the value is 1, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Net.BMCNetworkEnable

If the value returned is 1, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Net.BMCNetworkEnable, and set the value to 0.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Net.BMCNetworkEnable | Set-AdvancedSetting -Value 0 -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000239"
        Title        = "The ESX host must not use the default Active Directory ESX Admin group."
        Severity     = "high"
        GroupTitle   = "AD ESX Admins Group"
        Vuln_Discuss = "When an ESXi host is joined to an Active Directory domain, the Config.HostAgent.plugins.hostsvc.esxAdminsGroup setting specifies which Active Directory group is automatically granted full administrative privileges on the host. The default value of 'ESX Admins' is a well-known group name that an attacker who has compromised the Active Directory environment could potentially create or add members to in order to gain automatic administrative access to all ESXi hosts in the domain. By changing this setting to a non-default, organizationally specific group name, the risk of this attack vector is reduced because the attacker would need to know the specific group name being used and would need to be able to modify that group. If the host is not joined to AD, this setting should be configured with an empty value to prevent the automatic privilege assignment mechanism from being exploitable. This control supports the requirements of NIST SP 800-53 AC-2, AC-3, and IA-2."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.HostAgent.plugins.hostsvc.esxAdminsGroup and verify the value is not set to the default 'ESX Admins'.

If the host is joined to Active Directory and the value is 'ESX Admins', this is a finding.
If the host is not joined to Active Directory and the value is not empty, this may be a finding depending on organizational policy.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup

If the value returned is 'ESX Admins' and the host is AD-joined, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.HostAgent.plugins.hostsvc.esxAdminsGroup, and set the value to the organizationally approved AD group name or empty if AD is not in use.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value '<approved_ad_group_name>' -Confirm:`$false

Note: Replace <approved_ad_group_name> with the organizationally approved Active Directory group name. If AD is not in use, set the value to an empty string."
    },
    @{
        RuleID       = "VCFE-9X-000240"
        Title        = "The ESX host must not automatically grant administrative permissions to Active Directory groups."
        Severity     = "high"
        GroupTitle   = "AD Group Auto Add"
        Vuln_Discuss = "The Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd setting controls whether the ESX Admins Active Directory group (or the group configured in VCFE-9X-000239) is automatically added as an administrator on the ESXi host when the host joins a domain. When this setting is enabled, any group membership changes in Active Directory that add users to the ESX Admins group automatically result in those users gaining administrative access to the ESXi host without requiring explicit permission assignment in vCenter. This automatic privilege escalation through Active Directory group membership could allow unauthorized administrative access if the Active Directory environment is compromised or if group membership is inadvertently modified. Disabling automatic group addition ensures that administrative access to ESXi hosts must be explicitly granted through vCenter's permission model. This control supports the requirements of NIST SP 800-53 AC-2, AC-3, and AC-6."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd and verify the value is set to false.

If the value is true, this is a finding.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd

If the value returned is True, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd, and set the value to false.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroupAutoAdd | Set-AdvancedSetting -Value `$false -Confirm:`$false"
    },
    @{
        RuleID       = "VCFE-9X-000241"
        Title        = "The ESX host must not disable validation of users and groups."
        Severity     = "medium"
        GroupTitle   = "AD Validate Interval"
        Vuln_Discuss = "When an ESXi host is joined to an Active Directory domain, it periodically validates the user and group accounts that have been granted permissions on the host against the Active Directory to ensure they still exist and are active. The Config.HostAgent.plugins.vimsvc.authValidateInterval setting controls how frequently this validation occurs in minutes. If this value is set to 0, validation is disabled, meaning that accounts that have been deleted from or disabled in Active Directory may retain access to the ESXi host indefinitely until the host is rebooted or the permissions are explicitly revoked. Disabling validation defeats a key security mechanism for ensuring that access to ESXi hosts is automatically revoked when accounts are removed from the directory. Setting this to 90 minutes ensures regular validation while not creating excessive load on the domain controller. This control supports the requirements of NIST SP 800-53 AC-2, IA-4, and AC-17."
        CheckText    = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Locate the setting Config.HostAgent.plugins.vimsvc.authValidateInterval and verify the value is not 0.

If the value is 0, this is a finding. The recommended value is 90.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval

If the value returned is 0, this is a finding."
        FixText      = "From the vSphere Client, go to Hosts and Clusters. Select the ESXi host >> Configure >> System >> Advanced System Settings. Click Edit, locate Config.HostAgent.plugins.vimsvc.authValidateInterval, and set the value to 90.

PowerCLI:
Connect-VIServer -Server <vcenter_or_host>
Get-VMHost -Name <hostname> | Get-AdvancedSetting -Name Config.HostAgent.plugins.vimsvc.authValidateInterval | Set-AdvancedSetting -Value 90 -Confirm:`$false"
    }
)

# ---------------------------------------------------------------------------
# Helper: map severity string to CAT label
# ---------------------------------------------------------------------------
function Get-CATLabel {
    param([string]$Severity)
    switch ($Severity) {
        "high"   { return "CAT I" }
        "medium" { return "CAT II" }
        "low"    { return "CAT III" }
        default  { return "CAT II" }
    }
}

# ---------------------------------------------------------------------------
# Build CKLB structure
# ---------------------------------------------------------------------------
$stigId    = [System.Guid]::NewGuid().ToString()
$cklbId    = [System.Guid]::NewGuid().ToString()

$targetData = [ordered]@{
    target_type       = "Computing"
    host_name         = $Hostname
    ip_address        = $HostIP
    mac_address       = ""
    fqdn              = ""
    comments          = "Generated by New-ESXi9xCKLB.ps1 from VCF vSphere ESX 9.x SRG V1R1"
    role              = "None"
    is_web_database   = $false
    technology_area   = "Other Review"
    web_db_site       = ""
    web_db_instance   = ""
}

$stigInfo = [ordered]@{
    version        = "1"
    classification = "UNCLASSIFIED"
    customname     = ""
    stigid         = "VMware_VCF_vSphere_ESX_9x_SRG"
    description    = "VMware Cloud Foundation vSphere ESX 9.x STIG Readiness Guide Version 1 Release 1. NOTE: This is SRG-based content. No official DISA STIG has been published for ESXi 9.x as of the date of generation. Rule IDs use the VCFE-9X-XXXXXX scheme from the Broadcom/VMware DoD compliance and automation repository."
    filename       = "VMware_VCF_vSphere_ESX_9x_SRG_V1R1.xml"
    releaseinfo    = "Release: 1 Benchmark Date: $((Get-Date).ToString('dd MMM yyyy'))"
    title          = "VMware Cloud Foundation vSphere ESX 9.x STIG Readiness Guide"
    uuid           = $stigId
    notice         = "terms-of-use"
    source         = "STIG.DOD.MIL"
}

$vulnArray = @()
$ruleIndex = 1

foreach ($rule in $rules) {
    $vulnId = "V-VCF9X-{0:D6}" -f $ruleIndex
    $ruleId = "SV-VCF9X-{0:D6}r1_rule" -f $ruleIndex

    $stigData = @(
        [ordered]@{ vuln_attribute = "Vuln_Num";                   attribute_data = $vulnId }
        [ordered]@{ vuln_attribute = "Severity";                   attribute_data = $rule.Severity }
        [ordered]@{ vuln_attribute = "Group_Title";                attribute_data = $rule.GroupTitle }
        [ordered]@{ vuln_attribute = "Rule_ID";                    attribute_data = $ruleId }
        [ordered]@{ vuln_attribute = "Rule_Ver";                   attribute_data = $rule.RuleID }
        [ordered]@{ vuln_attribute = "Rule_Title";                 attribute_data = $rule.Title }
        [ordered]@{ vuln_attribute = "Vuln_Discuss";               attribute_data = $rule.Vuln_Discuss }
        [ordered]@{ vuln_attribute = "IA_Controls";                attribute_data = "" }
        [ordered]@{ vuln_attribute = "Check_Content";              attribute_data = $rule.CheckText }
        [ordered]@{ vuln_attribute = "Fix_Text";                   attribute_data = $rule.FixText }
        [ordered]@{ vuln_attribute = "False_Positives";            attribute_data = "" }
        [ordered]@{ vuln_attribute = "False_Negatives";            attribute_data = "" }
        [ordered]@{ vuln_attribute = "Documentable";               attribute_data = "false" }
        [ordered]@{ vuln_attribute = "Mitigations";                attribute_data = "" }
        [ordered]@{ vuln_attribute = "Potential_Impact";           attribute_data = "" }
        [ordered]@{ vuln_attribute = "Third_Party_Tools";          attribute_data = "" }
        [ordered]@{ vuln_attribute = "Mitigation_Control";         attribute_data = "" }
        [ordered]@{ vuln_attribute = "Responsibility";             attribute_data = "" }
        [ordered]@{ vuln_attribute = "Security_Override_Guidance"; attribute_data = "" }
        [ordered]@{ vuln_attribute = "Check_Content_Ref";          attribute_data = "M" }
        [ordered]@{ vuln_attribute = "Weight";                     attribute_data = "10.0" }
        [ordered]@{ vuln_attribute = "Class";                      attribute_data = "Unclass" }
        [ordered]@{ vuln_attribute = "STIGRef";                    attribute_data = "VMware Cloud Foundation vSphere ESX 9.x STIG Readiness Guide :: Version 1, Release 1" }
        [ordered]@{ vuln_attribute = "TargetKey";                  attribute_data = "" }
        [ordered]@{ vuln_attribute = "STIG_UUID";                  attribute_data = $stigId }
        [ordered]@{ vuln_attribute = "LEGACY_ID";                  attribute_data = "" }
        [ordered]@{ vuln_attribute = "CCI_REF";                    attribute_data = "" }
    )

    $vulnArray += [ordered]@{
        status                 = "Not_Reviewed"
        finding_details        = ""
        comments               = ""
        severity_override      = ""
        severity_justification = ""
        stig_data              = $stigData
    }

    $ruleIndex++
}

$stig = [ordered]@{
    stig_info = $stigInfo
    vuln      = $vulnArray
}

$cklb = [ordered]@{
    title       = "VMware Cloud Foundation vSphere ESX 9.x SRG V1R1"
    id          = $cklbId
    active      = $true
    mode        = 1
    has_path    = $true
    target_data = $targetData
    stigs       = @($stig)
}

# ---------------------------------------------------------------------------
# Serialize and write output
# ---------------------------------------------------------------------------
$outputFile = Join-Path $OutputPath "VMware_vSphere_ESX_9x_SRG_V1R1_${Hostname}.cklb"

try {
    $json = $cklb | ConvertTo-Json -Depth 20
    $json | Out-File -FilePath $outputFile -Encoding UTF8 -Force
    Write-Host "SUCCESS: CKLB written to $outputFile" -ForegroundColor Green
    Write-Host "  Rules generated  : $($vulnArray.Count)" -ForegroundColor Cyan
    Write-Host "  CAT I  (high)    : $(($rules | Where-Object {$_.Severity -eq 'high'}).Count)" -ForegroundColor Red
    Write-Host "  CAT II (medium)  : $(($rules | Where-Object {$_.Severity -eq 'medium'}).Count)" -ForegroundColor Yellow
    Write-Host "  CAT III (low)    : $(($rules | Where-Object {$_.Severity -eq 'low'}).Count)" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to write CKLB file." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}