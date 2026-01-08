import type { Article, Diagram } from '../types';

export const starterArticles: Article[] = [
  {
    id: 'starter-overview',
    title: 'What is Okta Device Access?',
    content: `
      <h2>Overview</h2>
      <p>Okta Device Access (ODA) extends identity and access management capabilities to the device sign-in experience for both macOS and Windows. It enables users to verify their identity using the same authenticators they use for app access, providing a secure, seamless experience for workforce devices.</p>

      <h3>Concepts to Know First</h3>
      <p>Before diving into Okta Device Access, be comfortable with these core concepts:</p>
      <ul>
        <li><strong>Okta Identity Engine (OIE):</strong> The policy and authenticator framework that powers device-level authentication.</li>
        <li><strong>Authenticators and Factors:</strong> Okta Verify, FIDO2, TOTP, and how policies decide what is allowed.</li>
        <li><strong>Device Enrollment and MDM:</strong> How macOS and Windows devices are enrolled and managed (policies, profiles, app deployment).</li>
        <li><strong>Credential Providers vs. Platform SSO:</strong> Windows uses a credential provider; macOS uses Platform SSO for password sync.</li>
        <li><strong>FastPass and Device Binding:</strong> How devices register to Okta Verify and become trusted for passwordless flows.</li>
        <li><strong>Policy Evaluation:</strong> How Okta evaluates sign-in policies at the device login screen.</li>
        <li><strong>Network Requirements:</strong> Device access to Okta endpoints, proxies, and firewall allowlists.</li>
        <li><strong>Change Management:</strong> Rollout planning, pilot groups, and user communication.</li>
      </ul>

      <h3>Key Features</h3>
      <ul>
        <li><strong>Desktop MFA:</strong> Multifactor authentication for Windows and macOS device sign-in</li>
        <li><strong>Desktop Password Sync (macOS):</strong> Synchronizes local macOS account password with Okta password</li>
        <li><strong>Desktop Password Autofill (Windows):</strong> Passwordless sign-in using Okta FastPass</li>
        <li><strong>Self-Service Password Reset:</strong> Users can reset locked-out accounts without admin help</li>
        <li><strong>Just-In-Time Account Creation (macOS):</strong> Create local accounts using Okta credentials at login</li>
        <li><strong>Device Logout:</strong> Remote sign-out capabilities for administrators</li>
      </ul>

      <h3>Core Components</h3>
      <p>Okta Device Access consists of two main features:</p>

      <h4>1. Desktop MFA for Windows and macOS</h4>
      <p>Delivers multifactor authentication to desktop and laptop computers. Administrators can establish policies for specific users and groups and configure passwordless experiences alongside self-service password reset capabilities.</p>

      <h4>2. Desktop Password Sync for macOS</h4>
      <p>Built on Apple's Platform Single Sign-On (Platform SSO) extension, this allows users to sign in with their Okta password while keeping the local account password in sync with Okta. Users register devices to Okta Verify accounts and enroll in Okta FastPass.</p>

      <h3>Supported Platforms</h3>
      <ul>
        <li><strong>Windows:</strong> Desktop MFA and Password Autofill</li>
        <li><strong>macOS:</strong> Desktop MFA, Password Sync, and JIT Account Creation</li>
      </ul>

      <h3>How It Works</h3>
      <p>Okta Device Access leverages Okta Verify on both Windows and macOS workstations to deliver these capabilities. Users authenticate at the device level using the same factors they use for application access, creating a unified identity experience across devices and apps.</p>

      <h3>Benefits</h3>
      <ul>
        <li><strong>Unified Identity:</strong> Same authenticators for device and app access</li>
        <li><strong>Enhanced Security:</strong> MFA at the device level prevents unauthorized access</li>
        <li><strong>Better User Experience:</strong> Single password to remember with password sync</li>
        <li><strong>Reduced IT Burden:</strong> Self-service password reset and recovery</li>
        <li><strong>Passwordless Options:</strong> Support for FIDO2 and Okta FastPass</li>
      </ul>
    `,
    summary: 'Okta Device Access extends identity and access management to device sign-in experiences for Windows and macOS, including desktop MFA, password sync, and self-service features.',
    category: 'overview',
    tags: ['okta device access', 'desktop mfa', 'password sync', 'overview', 'okta verify'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-concepts',
    title: 'Concepts to Understand Before Okta Device Access',
    content: `
      <h2>Why These Concepts Matter</h2>
      <p>Okta Device Access sits at the intersection of identity, device management, and the OS login experience. The topics below explain how the moving parts fit together so you can design policies, deploy MDM profiles correctly, and avoid common rollout failures.</p>

      <h3>1) Okta Identity Engine (OIE)</h3>
      <p>OIE is the policy and authenticator framework that controls device sign-in flows. Desktop MFA and Platform SSO policies are evaluated through OIE, which decides when a user must authenticate, what factors are allowed, and how device registration is enforced.</p>
      <ul>
        <li><strong>Policy layering:</strong> Device sign-in can have different rules than app sign-in.</li>
        <li><strong>Authenticator availability:</strong> Factors must be enabled, enrolled, and allowed by policy.</li>
        <li><strong>Device signals:</strong> Device registration and FastPass enrollment affect policy outcomes.</li>
      </ul>

      <h3>2) Authenticators and Factors</h3>
      <p>Desktop MFA uses the same authenticator system as app access. Knowing the differences between factors helps avoid lockouts.</p>
      <ul>
        <li><strong>Okta Verify Push/TOTP:</strong> Common online factors for interactive login.</li>
        <li><strong>FIDO2 security keys:</strong> Phishing-resistant, often used for high assurance.</li>
        <li><strong>FastPass:</strong> Device-bound, cryptographic, supports passwordless flows.</li>
        <li><strong>Offline factors:</strong> Allow login when network access is unavailable, if enabled.</li>
      </ul>

      <h3>3) Device Enrollment and MDM</h3>
      <p>Device Access depends on MDM to push profiles, payloads, and apps. MDM misconfiguration is the most common source of failed deployments.</p>
      <ul>
        <li><strong>Profiles vs. apps:</strong> Profiles configure OS behavior; apps deliver Okta Verify and services.</li>
        <li><strong>Install order:</strong> For macOS Desktop MFA, the MDM profile must arrive before the Okta Verify package installs.</li>
        <li><strong>Scope:</strong> Profiles and apps must target the same device groups.</li>
      </ul>

      <h3>4) Windows Credential Provider vs. macOS Platform SSO</h3>
      <p>Okta Device Access integrates differently on each platform:</p>
      <ul>
        <li><strong>Windows:</strong> Uses a credential provider to extend the login UI and apply Desktop MFA.</li>
        <li><strong>macOS:</strong> Uses Platform SSO for password sync and a custom settings payload for Desktop MFA.</li>
      </ul>

      <h3>5) Device Registration and FastPass</h3>
      <p>Device registration links a physical device to a user in Okta, enabling FastPass and device-bound policies.</p>
      <ul>
        <li><strong>Registration flow:</strong> Users sign in on-device, then complete Okta Verify registration.</li>
        <li><strong>Trust state:</strong> Policies can require registered devices or allow unregistered access with MFA.</li>
        <li><strong>Lifecycle:</strong> Device deprovisioning or reset requires re-registration.</li>
      </ul>

      <h3>6) Policy Evaluation at the Device Login Screen</h3>
      <p>Device login policies can differ from web or app policies. Understand how Okta evaluates rules for desktop sign-in.</p>
      <ul>
        <li><strong>Assignment:</strong> Policies apply by user, group, and platform.</li>
        <li><strong>Fallback paths:</strong> If a factor is unavailable, policies may deny access.</li>
        <li><strong>Recovery flows:</strong> Recovery PINs and self-service reset options need explicit policy enablement.</li>
      </ul>

      <h3>7) Network and Proxy Requirements</h3>
      <p>Device sign-in requires reachability to Okta endpoints and enrollment services.</p>
      <ul>
        <li><strong>Allowlists:</strong> Ensure firewall/proxy allows required Okta domains.</li>
        <li><strong>Offline behavior:</strong> Plan for offline login windows and factor availability.</li>
        <li><strong>First login risk:</strong> Initial registration often requires network connectivity.</li>
      </ul>

      <h3>8) macOS Desktop MFA Custom Settings Payload</h3>
      <p>Desktop MFA on macOS requires a complete custom payload delivered via MDM. Partial payloads or missing keys can break the login flow.</p>
      <ul>
        <li><strong>Preference domain:</strong> com.okta.deviceaccess.servicedaemon</li>
        <li><strong>OAuth values:</strong> Client ID and secret from the Desktop MFA app in Okta.</li>
        <li><strong>Behavior controls:</strong> Offline login, recovery PINs, allowed factors, and grace periods.</li>
      </ul>

      <h3>9) Testing and Rollout Strategy</h3>
      <p>Okta Device Access changes the OS login path. Use a cautious rollout approach.</p>
      <ul>
        <li><strong>Pilot groups:</strong> Start with IT or power users to validate policies.</li>
        <li><strong>Backout plan:</strong> Know how to remove profiles and uninstall components.</li>
        <li><strong>Support readiness:</strong> Ensure help desk can triage MDM and login issues.</li>
      </ul>

      <h3>10) Logging and Troubleshooting Signals</h3>
      <p>Plan how you will validate installation and troubleshoot failures.</p>
      <ul>
        <li><strong>Okta logs:</strong> System Log events for device registration and authentication.</li>
        <li><strong>Device logs:</strong> Windows Event Viewer, macOS Console, and Okta Verify logs.</li>
        <li><strong>MDM status:</strong> Confirm profile install and app deployment success.</li>
      </ul>
    `,
    summary: 'Deep foundations for Okta Device Access: OIE, factors, MDM, platform integration, device registration, policies, network requirements, payloads, rollout strategy, and troubleshooting signals.',
    category: 'overview',
    tags: ['prerequisites', 'concepts', 'foundations', 'mdm', 'policies', 'okta verify', 'desktop mfa'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-implementation-faq',
    title: 'Implementation Strategies and FAQs',
    content: `
      <h2>Implementation Strategies</h2>
      <p>Use a staged approach and align identity policy, MDM deployment, and user communication before you roll out device login changes.</p>

      <h3>1) Plan the Identity and Policy Model First</h3>
      <ul>
        <li><strong>Map policies to platforms:</strong> Separate Windows and macOS login policies; avoid one-size-fits-all rules.</li>
        <li><strong>Define allowed factors:</strong> Decide which factors are required at device sign-in and align with Okta Verify enrollment.</li>
        <li><strong>Decide offline behavior:</strong> Set offline login windows and recovery PIN settings based on risk tolerance.</li>
      </ul>

      <h3>2) Sequence MDM Deployment Correctly</h3>
      <ul>
        <li><strong>Profiles before apps (macOS):</strong> Desktop MFA MDM profiles must be deployed before the Okta Verify package installs.</li>
        <li><strong>Keep scope aligned:</strong> The MDM profile and Okta Verify app must target the same device groups.</li>
        <li><strong>Verify device enrollment:</strong> Make sure devices are fully enrolled and can receive profiles and packages.</li>
      </ul>

      <h3>3) Validate the Custom Settings Payload</h3>
      <ul>
        <li><strong>Full plist required:</strong> Desktop MFA on macOS needs the full payload under com.okta.deviceaccess.servicedaemon.</li>
        <li><strong>Check OAuth values:</strong> DMFAClientID and DMFAClientSecret must match the Desktop MFA app in Okta.</li>
        <li><strong>Confirm factor lists:</strong> MFARequiredList and AllowedFactors drive who must use Desktop MFA.</li>
      </ul>

      <h3>4) Pilot, Then Expand</h3>
      <ul>
        <li><strong>Use a pilot group:</strong> IT and power users validate profiles, policies, and recovery flows.</li>
        <li><strong>Confirm logs:</strong> Check Okta System Log and device logs for registration and sign-in events.</li>
        <li><strong>Document fallback:</strong> Have a plan to remove profiles or roll back policies quickly.</li>
      </ul>

      <h3>5) Communicate With Users</h3>
      <ul>
        <li><strong>Set expectations:</strong> Users will see a new login prompt and may need to register Okta Verify.</li>
        <li><strong>Explain recovery:</strong> Provide guidance for offline logins and recovery PINs.</li>
        <li><strong>Provide support paths:</strong> List help desk contacts and troubleshooting steps.</li>
      </ul>

      <h2>Frequently Asked Questions</h2>

      <h3>Why is Desktop MFA not appearing on macOS login?</h3>
      <ul>
        <li>Confirm the MDM profile is installed on the device.</li>
        <li>Verify the profile was deployed before the Okta Verify package.</li>
        <li>Check the payload preference domain is com.okta.deviceaccess.servicedaemon.</li>
      </ul>

      <h3>Do I need a full plist payload or just one key?</h3>
      <p>Desktop MFA on macOS requires the full Custom Settings payload. Partial payloads or missing keys can prevent the login extension from activating.</p>

      <h3>Where do I find the DMFA client ID and secret?</h3>
      <p>They are generated in Okta under the Desktop MFA app (Authentication tab -> OAuth client).</p>

      <h3>Why are users still seeing the standard login screen?</h3>
      <ul>
        <li>Okta Verify may not be installed or running.</li>
        <li>The MDM profile may not have been applied to the device.</li>
        <li>The user may be outside the policy scope.</li>
      </ul>

      <h3>How do I control which users must use Desktop MFA?</h3>
      <p>Use MFARequiredList and MFANotRequiredList in the payload, and align with Okta policy assignment.</p>

      <h3>Can users authenticate when offline?</h3>
      <p>Yes, if OfflineLoginAllowed is true and offline factors are configured. Time windows are controlled by LoginPeriodWithOfflineFactor.</p>

      <h3>What if a user cannot complete enrollment?</h3>
      <ul>
        <li>Confirm Okta Verify registration succeeds on the device.</li>
        <li>Check network reachability to Okta endpoints.</li>
        <li>Verify required factors are enabled and allowed in policy.</li>
      </ul>

      <h3>Is this different for Jamf, Intune, or Kandji?</h3>
      <p>The payload keys are the same. The main differences are how each MDM wraps and deploys the configuration profile and app package.</p>
    `,
    summary: 'Practical rollout guidance and FAQs for Okta Device Access, including policy planning, MDM sequencing, payload validation, and common troubleshooting answers.',
    category: 'implementation',
    tags: ['implementation', 'faq', 'deployment', 'mdm', 'desktop mfa', 'macos', 'windows'],
    source: 'https://iamse.blog/2023/10/20/okta-device-access-desktop-mfa-for-macos/',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-platform-sso',
    title: 'Platform SSO Deep Dive (macOS)',
    content: `
      <h2>Platform SSO Overview</h2>
      <p>Platform Single Sign-On (Platform SSO) is Apple’s framework that allows identity providers to integrate directly into macOS login and unlock flows. In Okta Device Access, Platform SSO underpins Desktop Password Sync and enables users to sign in with their Okta credentials while keeping the local account password aligned.</p>

      <h3>How Platform SSO Works with Okta</h3>
      <ul>
        <li><strong>Okta Verify app:</strong> Acts as the Platform SSO extension host.</li>
        <li><strong>SSO extension:</strong> The macOS SSO extension mediates authentication and registration.</li>
        <li><strong>Registration flow:</strong> Users enroll the device with Okta Verify, establishing a device-bound trust.</li>
        <li><strong>Password sync:</strong> Okta password changes synchronize to the local macOS account.</li>
      </ul>

      <h3>Key Components</h3>
      <ul>
        <li><strong>Extension Identifier:</strong> com.okta.macos.OktaVerify.OktaVerifyPlatformSSO</li>
        <li><strong>Team Identifier:</strong> VU9X276E3P</li>
        <li><strong>Redirect SSO type:</strong> Required for Okta Platform SSO flows.</li>
        <li><strong>Okta org URL:</strong> Used for registration and authentication endpoints.</li>
      </ul>

      <h3>Authentication and Registration Flow</h3>
      <ol>
        <li>Device receives SSO extension profile and Okta Verify is installed.</li>
        <li>User signs in to macOS (first time may be local credentials).</li>
        <li>Platform SSO prompts user to register the device with Okta.</li>
        <li>User authenticates with Okta and completes MFA.</li>
        <li>Device registers and enrolls in FastPass automatically.</li>
        <li>Password sync begins and keeps local and Okta passwords aligned.</li>
      </ol>

      <h3>Policy and User Experience Considerations</h3>
      <ul>
        <li><strong>Policy scope:</strong> Ensure macOS policies include the intended user groups.</li>
        <li><strong>First login:</strong> Requires network connectivity to Okta for registration.</li>
        <li><strong>Password changes:</strong> Okta changes sync to macOS; local-only changes can cause drift.</li>
        <li><strong>Account creation:</strong> JIT account creation can create local accounts at first login.</li>
      </ul>

      <h3>MDM Requirements</h3>
      <ul>
        <li>Device enrolled in MDM (Jamf Pro, Kandji, Microsoft Intune, etc.).</li>
        <li>Single sign-on extension profile deployed with Redirect type.</li>
        <li>Okta Verify app deployed and installed before first registration.</li>
      </ul>

      <h3>Configuration Checklist</h3>
      <ul>
        <li>Verify Platform SSO is enabled in Okta admin settings.</li>
        <li>Confirm extension identifier and team ID are correct.</li>
        <li>Confirm Okta org URLs are configured in the SSO profile.</li>
        <li>Deploy Okta Verify and validate app installation.</li>
        <li>Test registration and password sync on a pilot device.</li>
      </ul>

      <h3>Common Issues</h3>
      <ul>
        <li><strong>Registration prompt missing:</strong> SSO profile not installed or extension ID mismatch.</li>
        <li><strong>Password not syncing:</strong> Device registration incomplete or Okta Verify not running.</li>
        <li><strong>Login loops:</strong> Incorrect URLs or missing required keys in the profile.</li>
      </ul>
    `,
    summary: 'Deep dive into macOS Platform SSO in Okta Device Access, including architecture, flow, configuration, and troubleshooting.',
    category: 'enrollment',
    tags: ['platform sso', 'macos', 'password sync', 'okta verify', 'enrollment', 'sso'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/macos-pw-sync/configure-macos-password-sync.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-tpm-secure-enclave',
    title: 'TPMs and Secure Enclave Deep Dive',
    content: `
      <h2>Why Hardware Security Matters</h2>
      <p>Okta Device Access relies on device-bound cryptographic keys for strong authentication. TPMs on Windows and Secure Enclave on macOS protect those keys so they can’t be easily copied or extracted.</p>

      <h3>Trusted Platform Module (TPM) - Windows</h3>
      <p>The TPM is a dedicated hardware security chip (or firmware-backed module) that stores private keys and performs cryptographic operations.</p>
      <ul>
        <li><strong>Key protection:</strong> Private keys are generated and stored in the TPM and never leave in plaintext.</li>
        <li><strong>Attestation:</strong> The TPM can prove device integrity and key origin to services.</li>
        <li><strong>Windows Hello:</strong> Uses TPM-backed keys for PIN, biometrics, and credential protection.</li>
        <li><strong>FastPass binding:</strong> Device-bound authentication depends on TPM-backed key storage.</li>
      </ul>

      <h3>Secure Enclave - macOS</h3>
      <p>Secure Enclave is Apple’s hardware security subsystem that isolates sensitive key material and biometric data.</p>
      <ul>
        <li><strong>Isolated key storage:</strong> Private keys are protected and not accessible to the OS.</li>
        <li><strong>Biometric protection:</strong> Touch ID keys and policies are enforced by Secure Enclave.</li>
        <li><strong>Device trust:</strong> Supports device-bound authentication and cryptographic assertions.</li>
      </ul>

      <h3>How This Impacts Okta Device Access</h3>
      <ul>
        <li><strong>FastPass readiness:</strong> TPM/Secure Enclave provides the cryptographic backing for device binding.</li>
        <li><strong>Passwordless flows:</strong> Hardware-backed keys enable phishing-resistant authentication.</li>
        <li><strong>Device posture:</strong> Some policies can require hardware security capabilities.</li>
      </ul>

      <h3>Validation and Prerequisites</h3>
      <ul>
        <li><strong>Windows:</strong> Confirm TPM 2.0 is enabled in firmware and visible in Windows Security.</li>
        <li><strong>macOS:</strong> Apple Silicon devices use Secure Enclave; Intel Macs rely on the T2 chip where available.</li>
        <li><strong>MDM posture:</strong> Ensure device compliance policies require hardware-backed security where possible.</li>
      </ul>

      <h3>Common Pitfalls</h3>
      <ul>
        <li><strong>TPM disabled:</strong> FastPass or passwordless flows can fail if TPM is off in BIOS/UEFI.</li>
        <li><strong>Virtualized devices:</strong> VMs may lack a virtual TPM or Secure Enclave equivalent.</li>
        <li><strong>Legacy hardware:</strong> Older devices may not meet TPM 2.0 or T2/Secure Enclave requirements.</li>
      </ul>
    `,
    summary: 'Deep dive into TPMs and Secure Enclave, how hardware-backed keys enable Okta Device Access FastPass and passwordless authentication.',
    category: 'security',
    tags: ['tpm', 'secure enclave', 'hardware security', 'fastpass', 'passwordless', 'windows', 'macos'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-desktop-mfa',
    title: 'Desktop MFA for Windows and macOS',
    content: `
      <h2>Desktop MFA Overview</h2>
      <p>Desktop MFA extends multifactor authentication to your desktop and laptop computers, providing the same level of security at device sign-in that users experience when accessing applications.</p>

      <h3>How Desktop MFA Works</h3>
      <p>When users sign in to their Windows or macOS device:</p>
      <ol>
        <li>User enters their Okta username and password at the device login screen</li>
        <li>System prompts for MFA verification</li>
        <li>User authenticates using an approved factor (Okta Verify Push, TOTP, FIDO2, etc.)</li>
        <li>Upon successful verification, user gains access to the device</li>
      </ol>

      <h3>Supported Authentication Factors</h3>
      <ul>
        <li><strong>Okta Verify Push:</strong> Push notification to mobile device</li>
        <li><strong>Okta Verify TOTP:</strong> Time-based one-time password</li>
        <li><strong>FIDO2 Security Keys:</strong> Hardware security keys (YubiKey, etc.)</li>
        <li><strong>Okta FastPass:</strong> Passwordless authentication</li>
        <li><strong>SMS/Voice:</strong> Phone-based verification (if enabled)</li>
      </ul>

      <h3>Desktop MFA for Windows</h3>
      <h4>Key Features</h4>
      <ul>
        <li><strong>Desktop Password Autofill:</strong> Passwordless sign-in using FastPass</li>
        <li><strong>Credential Provider:</strong> Native Windows login integration</li>
        <li><strong>Self-Service Password Reset:</strong> Reset password directly from login screen</li>
        <li><strong>Policy-Based Access:</strong> Different policies for different user groups</li>
      </ul>

      <h4>Prerequisites</h4>
      <ul>
        <li>Windows 10 (version 1903 or later) or Windows 11</li>
        <li>Okta Verify for Windows installed</li>
        <li>Device enrolled in MDM (Intune, etc.)</li>
        <li>Okta Identity Engine enabled</li>
      </ul>

      <h3>Desktop MFA for macOS</h3>
      <h4>Key Features</h4>
      <ul>
        <li><strong>Native Login Integration:</strong> Works with macOS login window</li>
        <li><strong>Touch ID/Face ID Support:</strong> Biometric authentication options</li>
        <li><strong>FileVault Integration:</strong> MFA at boot for encrypted disks</li>
        <li><strong>Just-In-Time Account Creation:</strong> Create accounts at login with Okta credentials</li>
      </ul>

      <h4>Prerequisites</h4>
      <ul>
        <li>macOS 13 (Ventura) or later recommended</li>
        <li>Okta Verify for macOS installed</li>
        <li>Device enrolled in MDM (Jamf, Kandji, Intune, etc.)</li>
        <li>Okta Identity Engine enabled</li>
      </ul>

      <h4>MDM Custom Settings Payload (macOS)</h4>
      <p>Desktop MFA on macOS requires a full Custom Settings / Application &amp; Custom Settings payload, not a single key. The payload must be delivered to this preference domain:</p>
      <ul>
        <li><strong>Preference Domain:</strong> com.okta.deviceaccess.servicedaemon</li>
      </ul>
      <p>Example plist payload (trimmed):</p>
      <pre><code><?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>DMFAClientID</key>
    <string>add-your-client-ID-here</string>

    <key>DMFAClientSecret</key>
    <string>add-your-client-secret-here</string>

    <key>DMFAOrgURL</key>
    <string>https://your-org.okta.com</string>

    <key>AccountLinkingMFAFactor</key>
    <string>OV_Push</string>

    <key>AdminEmail</key>
    <string>admin@yourorg.com</string>

    <key>AdminPhone</key>
    <string>111-222-3333</string>

    <key>AllowedFactors</key>
    <array>
      <string>*</string>
    </array>

    <key>DeviceRecoveryPINDuration</key>
    <real>60</real>

    <key>DeviceRecoveryValidityInDays</key>
    <real>90</real>

    <key>LoginPeriodWithoutEnrolledFactor</key>
    <real>48</real>

    <key>LoginPeriodWithOfflineFactor</key>
    <real>168</real>

    <key>MFANotRequiredList</key>
    <array/>

    <key>MFARequiredList</key>
    <array>
      <string>*</string>
    </array>

    <key>OfflineLoginAllowed</key>
    <true/>
  </dict>
</plist></code></pre>
      <h4>Key Fields Explained</h4>
      <ul>
        <li><strong>DMFAClientID / DMFAClientSecret:</strong> From the Desktop MFA app in Okta (Authentication tab -> OAuth client).</li>
        <li><strong>DMFAOrgURL:</strong> Your Okta base URL (for example, https://your-org.okta.com).</li>
        <li><strong>AccountLinkingMFAFactor:</strong> Factor used to link the macOS local account to Okta (OV_Push, OV_TOTP, FIDO2_USB_key, etc.).</li>
        <li><strong>AllowedFactors:</strong> Which factors users can use (* = all allowed).</li>
        <li><strong>MFARequiredList / MFANotRequiredList:</strong> Control which local accounts must or must not use Desktop MFA. * in MFARequiredList = everyone.</li>
        <li><strong>LoginPeriodWithoutEnrolledFactor (hours):</strong> Grace period where user can log in with just password before they must enroll MFA.</li>
        <li><strong>LoginPeriodWithOfflineFactor (hours):</strong> How long offline login with an offline factor is allowed.</li>
        <li><strong>DeviceRecoveryPINDuration (minutes) / DeviceRecoveryValidityInDays (days):</strong> Desktop MFA recovery PIN behavior.</li>
        <li><strong>OfflineLoginAllowed (bool):</strong> Whether offline factors are exposed at all.</li>
      </ul>
      <h4>MDM Placement Examples</h4>
      <ul>
        <li><strong>Jamf Pro:</strong> Configuration Profiles -> Application &amp; Custom Settings -> Preference Domain: com.okta.deviceaccess.servicedaemon (paste full plist).</li>
        <li><strong>Intune:</strong> Custom configuration profile -> upload .mobileconfig or define matching OMA-URI settings that mirror the plist keys.</li>
      </ul>
      <h4>MDM Gotchas (from Okta docs)</h4>
      <ul>
        <li><strong>Install order matters:</strong> Deploy the Desktop MFA MDM profile before installing Okta Verify. If the profile is missing when the installer runs, Desktop MFA won't be installed.</li>
        <li><strong>Profile must be present:</strong> Devices need both the configuration profile and the Okta Verify package; a missing profile results in a standard login experience.</li>
      </ul>
      <h4>Other MDM Payload Styles</h4>
      <p>Some MDMs (for example Workspace ONE) wrap the same keys inside a full configuration profile structure. The Desktop MFA settings still live under <strong>com.okta.deviceaccess.servicedaemon</strong>, but are nested under a Forced/mcx_preference_settings block.</p>
      <pre><code><?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadContent</key>
    <dict>
      <key>com.okta.deviceaccess.servicedaemon</key>
      <dict>
        <key>Forced</key>
        <array>
          <dict>
            <key>mcx_preference_settings</key>
            <dict>
              <key>DMFAClientID</key>
              <string>add-your-client-ID-here</string>
              <!-- Remaining Desktop MFA keys go here -->
            </dict>
          </dict>
        </array>
      </dict>
    </dict>
  </dict>
</plist></code></pre>

      <h3>Configuration Steps</h3>
      <ol>
        <li><strong>Enable Desktop MFA:</strong> Activate in Okta admin console</li>
        <li><strong>Create Authentication Policy:</strong> Define which users/groups require Desktop MFA</li>
        <li><strong>Configure Factors:</strong> Select allowed authentication methods</li>
        <li><strong>Deploy Okta Verify:</strong> Push to devices via MDM</li>
        <li><strong>User Enrollment:</strong> Users sign in and register their devices</li>
      </ol>

      <h3>User Experience</h3>
      <p>From the user perspective:</p>
      <ul>
        <li><strong>First Sign-In:</strong> Register device and enroll authentication factors</li>
        <li><strong>Daily Use:</strong> Sign in with username, password, and MFA factor</li>
        <li><strong>Passwordless (Optional):</strong> Use FastPass for password-free sign-in</li>
        <li><strong>Self-Service:</strong> Reset forgotten passwords without calling IT</li>
      </ul>

      <h3>Security Benefits</h3>
      <ul>
        <li>Prevents unauthorized device access even with stolen credentials</li>
        <li>Phishing-resistant authentication with FIDO2 and FastPass</li>
        <li>Consistent security posture across devices and applications</li>
        <li>Audit trail of device sign-in events</li>
      </ul>

      <h3>Desktop MFA Recovery</h3>
      <p>If users lose access to their MFA factors, administrators can generate time-limited recovery PINs that enable users to restore access without full admin intervention.</p>
    `,
    summary: 'Desktop MFA extends multifactor authentication to Windows and macOS device sign-in, supporting various factors including Okta Verify, FIDO2, and passwordless authentication.',
    category: 'authentication',
    tags: ['desktop mfa', 'authentication', 'windows', 'macos', 'okta verify', 'mfa'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-password-sync',
    title: 'Desktop Password Sync for macOS',
    content: `
      <h2>Desktop Password Sync Overview</h2>
      <p>Desktop Password Sync for macOS (also known as Platform Single Sign-On) is built on Apple's Platform SSO extension. It allows users to sign in or unlock their Mac with their Okta password while keeping the local macOS account password automatically synchronized with Okta.</p>

      <h3>How Password Sync Works</h3>
      <ol>
        <li><strong>Initial Setup:</strong> User registers their Mac device to their Okta Verify account</li>
        <li><strong>Password Synchronization:</strong> Local macOS password is synced with Okta password</li>
        <li><strong>FastPass Enrollment:</strong> User is automatically enrolled in Okta FastPass</li>
        <li><strong>Unified Sign-In:</strong> User signs in to Mac with Okta credentials</li>
        <li><strong>Automatic Sync:</strong> Any password changes in Okta sync to the local account</li>
      </ol>

      <h3>Key Benefits</h3>
      <ul>
        <li><strong>Single Password:</strong> Users only need to remember their Okta password</li>
        <li><strong>Automatic Sync:</strong> Password changes sync immediately to the Mac</li>
        <li><strong>FastPass Integration:</strong> Enables passwordless authentication</li>
        <li><strong>Self-Service Password Reset:</strong> Users can reset their own passwords</li>
        <li><strong>Phishing Resistance:</strong> FastPass provides cryptographic authentication</li>
      </ul>

      <h3>Technical Requirements</h3>
      <h4>macOS Requirements</h4>
      <ul>
        <li>macOS 13 (Ventura) or later (macOS 14 Sonoma recommended)</li>
        <li>Apple Silicon (M1/M2/M3) or Intel-based Mac</li>
        <li>Okta Verify for macOS installed</li>
      </ul>

      <h4>Okta Requirements</h4>
      <ul>
        <li>Okta Identity Engine enabled</li>
        <li>Desktop Password Sync feature enabled in admin console</li>
        <li>Appropriate authentication policies configured</li>
      </ul>

      <h4>MDM Requirements</h4>
      <ul>
        <li>Device enrolled in MDM (Jamf Pro, Kandji, Microsoft Intune, etc.)</li>
        <li>Platform SSO payload configured and deployed</li>
        <li>Okta Verify app deployed via MDM</li>
      </ul>

      <h3>Configuration with Jamf Pro</h3>
      <ol>
        <li><strong>Enable in Okta:</strong> Navigate to Security -> Device Access -> Desktop Password Sync</li>
        <li><strong>Create Configuration Profile:</strong> In Jamf, create a new configuration profile</li>
        <li><strong>Add Platform SSO Payload:</strong> Choose Single Sign-On Extensions and select Redirect</li>
        <li><strong>Configure Extension:</strong> Extension ID com.okta.macos.OktaVerify.OktaVerifyPlatformSSO and Team ID VU9X276E3P</li>
        <li><strong>Set URLs:</strong> Add your Okta org URL to the allowed/redirect URLs</li>
        <li><strong>Set Registration:</strong> Add registration URL if required by your org policy</li>
        <li><strong>Deploy Okta Verify:</strong> Push app to devices via Jamf</li>
        <li><strong>Scope and Deploy:</strong> Assign profile to smart/static groups and deploy</li>
      </ol>

      <h3>Configuration with Kandji</h3>
      <ol>
        <li><strong>Enable in Okta:</strong> Navigate to Security -> Device Access -> Desktop Password Sync</li>
        <li><strong>Create Profile:</strong> In Kandji, add a new profile to a Library item or Blueprint</li>
        <li><strong>Add SSO Extension:</strong> Use the Single Sign-On extension payload and set type to Redirect</li>
        <li><strong>Configure Extension:</strong> Extension ID com.okta.macos.OktaVerify.OktaVerifyPlatformSSO and Team ID VU9X276E3P</li>
        <li><strong>Set URLs:</strong> Add your Okta org URL to the allowed/redirect URLs</li>
        <li><strong>Deploy Okta Verify:</strong> Add Okta Verify as a managed app in the same Blueprint</li>
        <li><strong>Assign Scope:</strong> Apply the Blueprint to target devices and verify profile install</li>
      </ol>

      <h3>Configuration with Microsoft Intune</h3>
      <ol>
        <li><strong>Enable in Okta:</strong> Configure Desktop Password Sync settings</li>
        <li><strong>Create Device Configuration:</strong> In Intune, create a new macOS configuration profile</li>
        <li><strong>Add SSO Extension:</strong> Use "Single sign-on app extension" settings with Redirect</li>
        <li><strong>Configure Extension:</strong> Extension ID com.okta.macos.OktaVerify.OktaVerifyPlatformSSO and Team ID VU9X276E3P</li>
        <li><strong>Set URLs:</strong> Add your Okta org URL to the allowed/redirect URLs list</li>
        <li><strong>Deploy Okta Verify:</strong> Use Intune app deployment</li>
        <li><strong>Assign Profile:</strong> Deploy to target user/device groups and sync devices</li>
      </ol>

      <h3>User Enrollment Process</h3>
      <ol>
        <li><strong>Receive Device:</strong> User gets Mac with MDM configuration</li>
        <li><strong>Initial Sign-In:</strong> Sign in with existing local credentials (first time only)</li>
        <li><strong>Okta Registration:</strong> System prompts to register device with Okta</li>
        <li><strong>Authenticate:</strong> User signs in with Okta username and password</li>
        <li><strong>MFA Verification:</strong> Complete multi-factor authentication</li>
        <li><strong>FastPass Setup:</strong> Device enrolled in FastPass automatically</li>
        <li><strong>Password Sync:</strong> Local account password synced with Okta</li>
      </ol>

      <h3>Day-to-Day User Experience</h3>
      <h4>Sign-In</h4>
      <ul>
        <li>User opens Mac and sees Okta-branded login screen</li>
        <li>Enters Okta username and password</li>
        <li>System unlocks - no local password needed</li>
      </ul>

      <h4>Password Changes</h4>
      <ul>
        <li>User changes password in Okta (via web or mobile app)</li>
        <li>Next time signing in to Mac, new password works automatically</li>
        <li>Local macOS account password updated in background</li>
      </ul>

      <h4>Password Reset</h4>
      <ul>
        <li>If user forgets password, they can reset via Okta self-service</li>
        <li>Reset syncs to Mac automatically</li>
        <li>No IT involvement required</li>
      </ul>

      <h3>Just-In-Time (JIT) Account Creation</h3>
      <p>With JIT provisioning enabled, users can create their macOS account directly from the login window:</p>
      <ol>
        <li>User receives new Mac with ODA configured</li>
        <li>At login screen, clicks "Sign in with Okta"</li>
        <li>Enters Okta credentials and completes MFA</li>
        <li>System creates local macOS account automatically</li>
        <li>User gains access without admin pre-provisioning</li>
      </ol>

      <h3>Platform SSO vs. Desktop Password Sync</h3>
      <p><strong>Note:</strong> Starting in September 2024, the Okta application name changed from "Desktop Password Sync" to "Platform Single Sign-On for macOS" in the admin console. The functionality remains the same.</p>

      <h3>Troubleshooting Common Issues</h3>
      <h4>Registration Not Appearing</h4>
      <ul>
        <li>Verify MDM profile is deployed and installed</li>
        <li>Check Okta Verify app is installed</li>
        <li>Confirm Desktop Password Sync is enabled in Okta admin</li>
        <li>Check device meets macOS version requirements</li>
      </ul>

      <h4>Password Not Syncing</h4>
      <ul>
        <li>Verify device is registered to Okta Verify</li>
        <li>Check network connectivity to Okta</li>
        <li>Review Okta Verify logs in Console app</li>
        <li>Try signing out and back in to the device</li>
      </ul>

      <h4>FastPass Not Working</h4>
      <ul>
        <li>Ensure FastPass is enabled in authentication policy</li>
        <li>Verify device completed full registration</li>
        <li>Check that user has enrolled FastPass</li>
        <li>Review policy rules for device authentication</li>
      </ul>
    `,
    summary: 'Desktop Password Sync for macOS uses Apple Platform SSO to synchronize local account passwords with Okta, enabling single password management and FastPass enrollment.',
    category: 'enrollment',
    tags: ['password sync', 'macos', 'platform sso', 'fastpass', 'okta verify', 'enrollment'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/macos-pw-sync/configure-macos-password-sync.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-setup',
    title: 'Setting Up Okta Device Access',
    content: `
      <h2>Prerequisites</h2>
      <p>Before deploying Okta Device Access, ensure you have:</p>

      <h3>Okta Requirements</h3>
      <ul>
        <li>Okta Identity Engine (OIE) enabled</li>
        <li>Appropriate Okta licenses that include Device Access features</li>
        <li>Admin access to Okta admin console</li>
        <li>Authentication policies configured</li>
      </ul>

      <h3>Device Requirements</h3>
      <h4>For Windows</h4>
      <ul>
        <li>Windows 10 version 1903 or later, or Windows 11</li>
        <li>Devices enrolled in MDM (Microsoft Intune, Workspace ONE, etc.)</li>
        <li>Network connectivity to Okta services</li>
      </ul>

      <h4>For macOS</h4>
      <ul>
        <li>macOS 13 (Ventura) or later (macOS 14 Sonoma recommended)</li>
        <li>Devices enrolled in MDM (Jamf Pro, Kandji, Microsoft Intune, etc.)</li>
        <li>Network connectivity to Okta services</li>
      </ul>

      <h3>MDM Requirements</h3>
      <ul>
        <li>Active MDM solution (Jamf Pro, Kandji, Microsoft Intune, VMware Workspace ONE, etc.)</li>
        <li>Ability to deploy applications via MDM</li>
        <li>Ability to deploy configuration profiles/policies</li>
      </ul>

      <h2>Step 1: Enable Okta Device Access</h2>
      <ol>
        <li>Log in to Okta admin console</li>
        <li>Navigate to <strong>Security -> Device Access</strong></li>
        <li>Enable <strong>Desktop MFA</strong> for your desired platforms</li>
        <li>Enable <strong>Desktop Password Sync</strong> (for macOS, if desired)</li>
        <li>Configure feature-specific settings</li>
      </ol>

      <h2>Step 2: Configure Authentication Policies</h2>
      <h3>Create Desktop MFA Policy</h3>
      <ol>
        <li>Go to <strong>Security -> Authentication Policies</strong></li>
        <li>Click <strong>Add Policy</strong></li>
        <li>Name the policy (e.g., "Desktop MFA Policy")</li>
        <li>Assign to target groups/users</li>
        <li>Configure rules:
          <ul>
            <li>Set authentication requirements (password + MFA)</li>
            <li>Select allowed authenticators (Okta Verify, FIDO2, etc.)</li>
            <li>Configure session settings</li>
          </ul>
        </li>
        <li>Enable self-service password reset if desired</li>
        <li>Save and activate policy</li>
      </ol>

      <h2>Step 3: Deploy Okta Verify</h2>
      <h3>For Windows (via Intune)</h3>
      <ol>
        <li>Download Okta Verify Windows installer</li>
        <li>In Intune, go to <strong>Apps -> Windows apps -> Add</strong></li>
        <li>Select <strong>Line-of-business app</strong></li>
        <li>Upload Okta Verify installer</li>
        <li>Configure app information and requirements</li>
        <li>Assign to target device/user groups</li>
        <li>Deploy app</li>
      </ol>

      <h3>For macOS (via Jamf Pro)</h3>
      <ol>
        <li>Download Okta Verify macOS installer (PKG)</li>
        <li>In Jamf Pro, upload package to <strong>Computer Management -> Packages</strong></li>
        <li>Create policy under <strong>Computers -> Policies</strong></li>
        <li>Add Okta Verify package to policy</li>
        <li>Set trigger (enrollment, recurring check-in, etc.)</li>
        <li>Scope to target computer groups (smart or static)</li>
        <li>Save and enable policy</li>
      </ol>

      <h3>For macOS (via Kandji)</h3>
      <ol>
        <li>Download Okta Verify macOS installer (PKG)</li>
        <li>Create a Kandji Library item for the PKG</li>
        <li>Assign the Library item to the target Blueprint</li>
        <li>Set install behavior (enrollment or on-demand) as needed</li>
        <li>Sync a test device to confirm installation</li>
      </ol>

      <h3>For macOS (via Intune)</h3>
      <ol>
        <li>Download Okta Verify macOS PKG</li>
        <li>Convert to .intunemac format using Intune App Wrapping Tool</li>
        <li>In Intune, go to <strong>Apps -> macOS apps -> Add</strong></li>
        <li>Select <strong>Line-of-business app</strong> (PKG)</li>
        <li>Upload wrapped app</li>
        <li>Configure installation settings and requirements</li>
        <li>Assign to target groups</li>
      </ol>

      <h2>Step 4: Configure Platform SSO (macOS Password Sync)</h2>
      <p>If deploying Desktop Password Sync for macOS:</p>

      <h3>Configuration Values Needed</h3>
      <ul>
        <li><strong>Extension Identifier:</strong> com.okta.macos.OktaVerify.OktaVerifyPlatformSSO</li>
        <li><strong>Type:</strong> Redirect</li>
        <li><strong>URLs:</strong> Your Okta org URL (e.g., https://yourdomain.okta.com)</li>
        <li><strong>Team Identifier:</strong> VU9X276E3P</li>
      </ul>

      <h3>Via Jamf Pro</h3>
      <ol>
        <li>Go to <strong>Computers -> Configuration Profiles -> New</strong></li>
        <li>Select <strong>Single Sign-On Extensions</strong> payload</li>
        <li>Choose <strong>SSO</strong> as the Payload Type</li>
        <li>Enter extension identifier: com.okta.macos.OktaVerify.OktaVerifyPlatformSSO</li>
        <li>Set SSO Type to <strong>Redirect</strong></li>
        <li>Enter Team Identifier: VU9X276E3P</li>
        <li>Add your Okta org URLs to the allowed/redirect URLs</li>
        <li>Configure additional keys (registration URL, etc.) if required</li>
        <li>Scope to target computers or smart groups</li>
        <li>Save and deploy</li>
      </ol>

      <h3>Via Kandji</h3>
      <ol>
        <li>Create a new configuration profile in Kandji</li>
        <li>Add the Single Sign-On extension payload and set type to Redirect</li>
        <li>Extension identifier: com.okta.macos.OktaVerify.OktaVerifyPlatformSSO</li>
        <li>Team identifier: VU9X276E3P</li>
        <li>Add your Okta org URLs to the allowed/redirect URLs</li>
        <li>Add registration URL and any required keys</li>
        <li>Assign to the target Blueprint and deploy</li>
      </ol>

      <h3>Via Microsoft Intune</h3>
      <ol>
        <li>Go to <strong>Devices -> Configuration profiles -> Create profile</strong></li>
        <li>Platform: <strong>macOS</strong>, Profile type: <strong>Templates -> Device features</strong></li>
        <li>Select <strong>Single sign-on app extension</strong></li>
        <li>SSO app extension type: <strong>Redirect</strong></li>
        <li>Extension identifier: com.okta.macos.OktaVerify.OktaVerifyPlatformSSO</li>
        <li>Team identifier: VU9X276E3P</li>
        <li>Add Okta URLs to the allowed/redirect URLs list</li>
        <li>Add registration URL and required keys</li>
        <li>Assign to target groups and sync devices</li>
        <li>Save and deploy</li>
      </ol>

      <h2>Step 4a: Configure Desktop MFA Custom Settings (macOS)</h2>
      <p>Desktop MFA on macOS requires a full Custom Settings payload delivered to the preference domain <strong>com.okta.deviceaccess.servicedaemon</strong>. MDMs must push the entire plist (not just a single key).</p>

      <h3>Via Jamf Pro</h3>
      <ol>
        <li>Go to <strong>Computers -> Configuration Profiles -> New</strong></li>
        <li>Choose <strong>Application &amp; Custom Settings</strong></li>
        <li>Set Preference Domain to <strong>com.okta.deviceaccess.servicedaemon</strong></li>
        <li>Paste the full Desktop MFA plist payload (see macOS Desktop MFA section)</li>
        <li>Scope to target devices/groups and deploy</li>
      </ol>

      <h3>Via Kandji</h3>
      <ol>
        <li>Create a new configuration profile in Kandji</li>
        <li>Add <strong>Custom Settings</strong> payload</li>
        <li>Set Preference Domain to <strong>com.okta.deviceaccess.servicedaemon</strong></li>
        <li>Paste the full Desktop MFA plist payload</li>
        <li>Assign to the target Blueprint and deploy</li>
      </ol>

      <h3>Via Microsoft Intune</h3>
      <ol>
        <li>Create a custom macOS configuration profile</li>
        <li>Upload a .mobileconfig containing the full Desktop MFA plist payload</li>
        <li>Alternatively, define OMA-URI settings that mirror the plist keys</li>
        <li>Assign to target device groups and sync devices</li>
      </ol>

      <h2>Step 5: User Enrollment and Testing</h2>
      <h3>Test Device Setup</h3>
      <ol>
        <li>Select a test device that has received the MDM configurations</li>
        <li>Ensure Okta Verify is installed</li>
        <li>Sign in to device with test user account</li>
        <li>Follow registration prompts</li>
        <li>Complete MFA enrollment</li>
        <li>Verify authentication works as expected</li>
      </ol>

      <h3>Windows Desktop MFA Testing</h3>
      <ol>
        <li>Lock or sign out of Windows device</li>
        <li>At login screen, enter Okta username and password</li>
        <li>Complete MFA challenge (push notification, TOTP, etc.)</li>
        <li>Verify successful sign-in</li>
        <li>Test self-service password reset (if enabled)</li>
      </ol>

      <h3>macOS Password Sync Testing</h3>
      <ol>
        <li>Sign in to Mac (may use existing local credentials first time)</li>
        <li>System prompts for Okta registration</li>
        <li>Enter Okta credentials and complete MFA</li>
        <li>Verify FastPass enrollment</li>
        <li>Sign out and back in using Okta password</li>
        <li>Test password change propagation</li>
      </ol>

      <h2>Step 6: Rollout Strategy</h2>
      <h3>Phased Deployment Approach</h3>
      <ol>
        <li><strong>Pilot (Week 1-2):</strong> Deploy to IT team and early adopters</li>
        <li><strong>Beta (Week 3-4):</strong> Expand to friendly user groups</li>
        <li><strong>General Availability:</strong> Roll out to all users in waves</li>
      </ol>

      <h3>Communication Plan</h3>
      <ul>
        <li>Announce feature availability and benefits</li>
        <li>Provide user guides and training materials</li>
        <li>Set up help desk support</li>
        <li>Create FAQ documentation</li>
        <li>Establish feedback channels</li>
      </ul>

      <h2>Step 7: Monitoring and Maintenance</h2>
      <h3>What to Monitor</h3>
      <ul>
        <li>Device registration success rates</li>
        <li>Authentication success/failure rates</li>
        <li>Password reset requests</li>
        <li>Support ticket volume</li>
        <li>User feedback and satisfaction</li>
      </ul>

      <h3>Ongoing Maintenance</h3>
      <ul>
        <li>Keep Okta Verify apps updated</li>
        <li>Review and update authentication policies</li>
        <li>Monitor Okta system log for errors</li>
        <li>Maintain MDM configurations</li>
        <li>Review security reports regularly</li>
      </ul>
    `,
    summary: 'Complete guide to setting up Okta Device Access, including prerequisites, configuration steps for Windows and macOS, MDM deployment, and rollout strategies.',
    category: 'integration',
    tags: ['setup', 'configuration', 'deployment', 'mdm', 'intune', 'jamf', 'windows', 'macos'],
    source: 'https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'starter-troubleshooting',
    title: 'Troubleshooting Okta Device Access',
    content: `
      <h2>Common Issues and Solutions</h2>

      <h3>Desktop MFA Issues</h3>

      <h4>Problem: Desktop MFA option not appearing at login</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Verify Okta Verify is installed on the device</li>
        <li>Check that device is enrolled in MDM</li>
        <li>Confirm Desktop MFA is enabled in Okta admin console</li>
        <li>Review authentication policy assignment</li>
        <li>Restart the device</li>
        <li>Check Okta Verify service is running (Windows Services or macOS Activity Monitor)</li>
      </ul>

      <h4>Problem: MFA prompts not appearing</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Check network connectivity to Okta</li>
        <li>Verify user has enrolled MFA factors in Okta</li>
        <li>Review Okta system log for authentication errors</li>
        <li>Ensure authentication policy allows the registered factors</li>
        <li>Try re-registering the device</li>
      </ul>

      <h4>Problem: "Device not registered" error</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Complete device registration process in Okta Verify</li>
        <li>Check that user account is active in Okta</li>
        <li>Verify MDM policies are deployed correctly</li>
        <li>Review Okta Verify logs for registration errors</li>
        <li>Uninstall and reinstall Okta Verify if needed</li>
      </ul>

      <h3>Password Sync Issues (macOS)</h3>

      <h4>Problem: Platform SSO registration not appearing</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Verify macOS version meets requirements (macOS 13+)</li>
        <li>Check MDM profile is installed: System Settings → Profiles</li>
        <li>Confirm Okta Verify app is installed</li>
        <li>Verify Platform SSO extension identifier is correct</li>
        <li>Check that Desktop Password Sync is enabled in Okta</li>
        <li>Review MDM deployment logs</li>
      </ul>

      <h4>Problem: Password not syncing to macOS</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Verify device is registered in Okta Verify</li>
        <li>Check network connectivity to Okta</li>
        <li>Sign out and back in to macOS</li>
        <li>Review Console logs for Okta Verify errors</li>
        <li>Verify user changed password in Okta (not locally)</li>
        <li>Check that Platform SSO profile is active</li>
      </ul>

      <h4>Problem: "Registration failed" error</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Check user has permission to use Device Access</li>
        <li>Verify authentication policy allows device authentication</li>
        <li>Ensure all required MFA factors are enrolled</li>
        <li>Check Okta system log for specific error messages</li>
        <li>Try registering from a different network</li>
      </ul>

      <h3>Self-Service Password Reset Issues</h3>

      <h4>Problem: Password reset option not available</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Verify SSPR is enabled in authentication policy</li>
        <li>Check user has enrolled recovery factors</li>
        <li>Ensure password policy allows self-service reset</li>
        <li>Review policy rules and scope</li>
      </ul>

      <h4>Problem: Password reset fails</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Check password meets complexity requirements</li>
        <li>Verify Active Directory writeback is configured (if applicable)</li>
        <li>Review Okta system log for specific errors</li>
        <li>Ensure recovery factor (email, SMS) is working</li>
        <li>Check network connectivity</li>
      </ul>

      <h3>Windows-Specific Issues</h3>

      <h4>Problem: Credential provider not loading</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Verify Okta Verify service is running: services.msc → Okta Verify Service</li>
        <li>Check Windows Event Viewer for errors</li>
        <li>Ensure Okta Verify is installed for "All Users"</li>
        <li>Verify no conflicting credential providers</li>
        <li>Restart the OktaVerifyService</li>
        <li>Reinstall Okta Verify if needed</li>
      </ul>

      <h4>Problem: FastPass not working on Windows</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Check device meets TPM requirements</li>
        <li>Verify FastPass is enabled in policy</li>
        <li>Ensure device is registered and enrolled</li>
        <li>Check Windows Hello is configured</li>
        <li>Review policy authenticator requirements</li>
      </ul>

      <h3>macOS-Specific Issues</h3>

      <h4>Problem: Can't sign in after password change</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Wait a few minutes for sync to complete</li>
        <li>Check network connectivity</li>
        <li>Try signing in with old password if recent change</li>
        <li>Use recovery mode to reset if locked out</li>
        <li>Contact IT for administrative unlock</li>
      </ul>

      <h4>Problem: FileVault login issues</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Note: FileVault unlock uses cached credentials</li>
        <li>After password change, first unlock may require old password</li>
        <li>After successful login, FileVault cache updates</li>
        <li>If stuck, boot to Recovery Mode and unlock</li>
      </ul>

      <h3>MDM Configuration Issues</h3>

      <h4>Problem: Configuration profile not installing</h4>
      <p><strong>Jamf Solutions:</strong></p>
      <ul>
        <li>Check profile scope and smart group membership</li>
        <li>Verify device can communicate with Jamf server</li>
        <li>Review Jamf policy logs</li>
        <li>Force profile installation from Self Service</li>
        <li>Run "sudo jamf policy" on device</li>
      </ul>

      <p><strong>Kandji Solutions:</strong></p>
      <ul>
        <li>Confirm the device is assigned to the correct Blueprint</li>
        <li>Verify the Library item is scoped to the device</li>
        <li>Check Kandji device status and last check-in time</li>
        <li>Force a sync from the Kandji agent</li>
        <li>Review profile install status in the Kandji console</li>
      </ul>

      <p><strong>Intune Solutions:</strong></p>
      <ul>
        <li>Check device compliance and enrollment status</li>
        <li>Verify profile assignment to correct groups</li>
        <li>Review Intune deployment status in portal</li>
        <li>Check device sync status</li>
        <li>Force sync from Company Portal app</li>
      </ul>

      <h3>Network and Connectivity Issues</h3>

      <h4>Problem: Can't reach Okta services</h4>
      <p><strong>Solutions:</strong></p>
      <ul>
        <li>Verify firewall allows connections to *.okta.com</li>
        <li>Check proxy settings if applicable</li>
        <li>Test connectivity: ping your-org.okta.com</li>
        <li>Review required URLs and ports in Okta documentation</li>
        <li>Check VPN connectivity if required</li>
      </ul>

      <h3>Logging and Diagnostics</h3>

      <h4>Windows Logging</h4>
      <ul>
        <li><strong>Okta Verify Logs:</strong> C:\\ProgramData\\Okta\\OktaVerify\\logs</li>
        <li><strong>Event Viewer:</strong> Windows Logs → Application (filter for OktaVerify)</li>
        <li><strong>Service Status:</strong> services.msc → Okta Verify Service</li>
      </ul>

      <h4>macOS Logging</h4>
      <ul>
        <li><strong>Console App:</strong> Filter for "okta" or "OktaVerify"</li>
        <li><strong>System Extension:</strong> System Settings → Privacy & Security → Extensions</li>
        <li><strong>Profile Status:</strong> System Settings → Profiles</li>
        <li><strong>Okta Verify Logs:</strong> ~/Library/Logs/Okta/OktaVerify</li>
      </ul>

      <h4>Okta Admin Diagnostics</h4>
      <ul>
        <li><strong>System Log:</strong> Reports → System Log (filter by user or device)</li>
        <li><strong>Authentication Events:</strong> Look for device-level authentication</li>
        <li><strong>Device Management:</strong> Directory → Devices (check registration status)</li>
        <li><strong>Policy Evaluation:</strong> Review which policies matched</li>
      </ul>

      <h3>Getting Additional Help</h3>

      <h4>Information to Collect</h4>
      <p>When contacting support, gather:</p>
      <ul>
        <li>Okta org URL</li>
        <li>Affected user's username</li>
        <li>Device OS and version</li>
        <li>Okta Verify version</li>
        <li>MDM solution and version</li>
        <li>Error messages and screenshots</li>
        <li>Okta system log entries</li>
        <li>Device logs (Windows Event Viewer or macOS Console)</li>
        <li>Steps to reproduce the issue</li>
      </ul>

      <h4>Support Resources</h4>
      <ul>
        <li><strong>Okta Help Center:</strong> help.okta.com</li>
        <li><strong>Okta Community:</strong> community.okta.com</li>
        <li><strong>Okta Support:</strong> Open ticket in admin console</li>
        <li><strong>Known Issues:</strong> Check Okta Trust (trust.okta.com)</li>
      </ul>
    `,
    summary: 'Comprehensive troubleshooting guide for Okta Device Access issues including Desktop MFA problems, Password Sync errors, and platform-specific solutions for Windows and macOS.',
    category: 'troubleshooting',
    tags: ['troubleshooting', 'errors', 'debugging', 'support', 'windows', 'macos', 'password sync', 'desktop mfa'],
    source: 'https://support.okta.com/help/s/article/frequently-asked-questions-about-desktop-mfa',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
];

export const starterDiagrams: Diagram[] = [
  {
    id: 'diagram-desktop-mfa-flow',
    title: 'Desktop MFA Sign-In Flow',
    description: 'Step-by-step flow showing how Desktop MFA works for Windows and macOS',
    category: 'authentication',
    isStarter: true,
    nodes: [
      {
        id: 'start',
        type: 'start',
        label: 'User at Login Screen',
        position: { x: 250, y: 0 },
      },
      {
        id: 'enter-creds',
        type: 'process',
        label: 'Enter Username & Password',
        description: 'User enters Okta credentials at device login',
        position: { x: 250, y: 100 },
      },
      {
        id: 'check-policy',
        type: 'decision',
        label: 'Check Auth Policy',
        description: 'Okta evaluates authentication policy for the user',
        position: { x: 250, y: 200 },
      },
      {
        id: 'mfa-prompt',
        type: 'process',
        label: 'MFA Challenge',
        description: 'System prompts for additional factor (Push, TOTP, FIDO2)',
        position: { x: 450, y: 300 },
      },
      {
        id: 'no-mfa',
        type: 'end',
        label: 'Access Denied',
        description: 'Policy requires MFA but user has no factors',
        position: { x: 50, y: 300 },
      },
      {
        id: 'verify-factor',
        type: 'process',
        label: 'User Verifies',
        description: 'User completes MFA verification',
        position: { x: 450, y: 400 },
      },
      {
        id: 'check-success',
        type: 'decision',
        label: 'Verification Success?',
        position: { x: 450, y: 500 },
      },
      {
        id: 'failed',
        type: 'end',
        label: 'Access Denied',
        position: { x: 250, y: 600 },
      },
      {
        id: 'granted',
        type: 'end',
        label: 'Device Unlocked',
        description: 'User gains access to device',
        position: { x: 650, y: 600 },
      },
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'enter-creds' },
      { id: 'e2', source: 'enter-creds', target: 'check-policy' },
      { id: 'e3', source: 'check-policy', target: 'no-mfa', label: 'No MFA Enrolled' },
      { id: 'e4', source: 'check-policy', target: 'mfa-prompt', label: 'MFA Required' },
      { id: 'e5', source: 'mfa-prompt', target: 'verify-factor' },
      { id: 'e6', source: 'verify-factor', target: 'check-success' },
      { id: 'e7', source: 'check-success', target: 'failed', label: 'Failed' },
      { id: 'e8', source: 'check-success', target: 'granted', label: 'Success' },
    ],
  },
  {
    id: 'diagram-password-sync-flow',
    title: 'Desktop Password Sync Registration (macOS)',
    description: 'How macOS Password Sync registration and synchronization works',
    category: 'enrollment',
    isStarter: true,
    nodes: [
      {
        id: 'start',
        type: 'start',
        label: 'User Signs In to Mac',
        position: { x: 250, y: 0 },
      },
      {
        id: 'check-profile',
        type: 'decision',
        label: 'Platform SSO Configured?',
        description: 'Check if MDM profile is installed',
        position: { x: 250, y: 100 },
      },
      {
        id: 'no-profile',
        type: 'end',
        label: 'Standard Login',
        position: { x: 50, y: 200 },
      },
      {
        id: 'prompt-registration',
        type: 'process',
        label: 'Prompt Registration',
        description: 'System prompts to register with Okta',
        position: { x: 450, y: 200 },
      },
      {
        id: 'okta-auth',
        type: 'process',
        label: 'Okta Authentication',
        description: 'User enters Okta credentials and completes MFA',
        position: { x: 450, y: 300 },
      },
      {
        id: 'register-device',
        type: 'process',
        label: 'Register Device',
        description: 'Device registered to Okta Verify account',
        position: { x: 450, y: 400 },
      },
      {
        id: 'enroll-fastpass',
        type: 'process',
        label: 'Enroll FastPass',
        description: 'Automatic FastPass enrollment',
        position: { x: 450, y: 500 },
      },
      {
        id: 'sync-password',
        type: 'process',
        label: 'Sync Password',
        description: 'Local account password synced with Okta',
        position: { x: 450, y: 600 },
      },
      {
        id: 'complete',
        type: 'end',
        label: 'Registration Complete',
        position: { x: 450, y: 700 },
      },
    ],
    edges: [
      { id: 'e1', source: 'start', target: 'check-profile' },
      { id: 'e2', source: 'check-profile', target: 'no-profile', label: 'Not Configured' },
      { id: 'e3', source: 'check-profile', target: 'prompt-registration', label: 'Configured' },
      { id: 'e4', source: 'prompt-registration', target: 'okta-auth' },
      { id: 'e5', source: 'okta-auth', target: 'register-device' },
      { id: 'e6', source: 'register-device', target: 'enroll-fastpass' },
      { id: 'e7', source: 'enroll-fastpass', target: 'sync-password' },
      { id: 'e8', source: 'sync-password', target: 'complete' },
    ],
  },
];
