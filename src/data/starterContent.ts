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

      <h3>Common Challenges and How Okta Device Access Solves Them</h3>
      <ul>
        <li><strong>Weak device login security:</strong> Desktop MFA enforces strong factors at OS sign-in.</li>
        <li><strong>Password sprawl and drift:</strong> Platform SSO keeps macOS passwords synced to Okta.</li>
        <li><strong>Phishing and credential theft:</strong> FastPass and FIDO2 reduce reliance on passwords.</li>
        <li><strong>Account lockouts:</strong> Self-service password reset and recovery PINs reduce help desk tickets.</li>
        <li><strong>Inconsistent policy enforcement:</strong> Okta policies unify device and app access rules.</li>
        <li><strong>Remote support friction:</strong> Device-based registration and self-service recovery reduce admin intervention.</li>
        <li><strong>Offline access gaps:</strong> Configurable offline factors and grace periods support continuity.</li>
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

      <h3>Challenges Solved by Desktop MFA</h3>
      <ul>
        <li><strong>Local-only logins:</strong> Adds Okta policy and MFA to device sign-in.</li>
        <li><strong>Credential theft risk:</strong> Requires a second factor at the login screen.</li>
        <li><strong>Inconsistent enforcement:</strong> Applies centralized Okta policies to endpoints.</li>
        <li><strong>Help desk overload:</strong> Supports recovery PINs and self-service reset flows.</li>
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

      <h3>Challenges Solved by Desktop Password Sync</h3>
      <ul>
        <li><strong>Password drift:</strong> Keeps local macOS and Okta passwords aligned.</li>
        <li><strong>Multiple credentials:</strong> Eliminates separate device and app passwords.</li>
        <li><strong>Account recovery pain:</strong> Reduces lockouts with self-service reset.</li>
        <li><strong>Low trust sign-ins:</strong> FastPass enables device-bound authentication.</li>
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
  {
    id: 'se-discovery-framework',
    title: 'Discovery Question Framework for Solution Engineers',
    content: `
      <h2>Overview</h2>
      <p>This framework helps Solution Engineers conduct effective discovery conversations that uncover customer needs, pain points, and technical requirements for Okta Device Access.</p>

      <h3>Discovery Structure</h3>
      <p>Organize your discovery around these five key areas:</p>
      <ol>
        <li><strong>Current State Assessment</strong> - Understand what they have today</li>
        <li><strong>Pain Point Identification</strong> - Uncover what's not working</li>
        <li><strong>Technical Environment</strong> - Map their infrastructure</li>
        <li><strong>Business Requirements</strong> - Understand success criteria</li>
        <li><strong>Decision Process</strong> - Identify stakeholders and timeline</li>
      </ol>

      <h2>1. Current State Assessment</h2>

      <h3>Device Management</h3>
      <ul>
        <li><strong>What MDM solution are you currently using?</strong> (Jamf, Intune, Workspace ONE, Kandji, other)</li>
        <li><strong>What percentage of your device fleet is enrolled in MDM?</strong></li>
        <li><strong>Do you manage both Windows and macOS devices?</strong> What's the split?</li>
        <li><strong>Are devices company-owned, BYOD, or a mix?</strong></li>
        <li><strong>How many devices total?</strong> (Helps size the deployment)</li>
        <li><strong>Do you have shared/kiosk devices?</strong> What's the use case?</li>
      </ul>

      <h3>Current Authentication & Identity</h3>
      <ul>
        <li><strong>What identity provider do you use today?</strong> (Active Directory, Azure AD, Okta, other)</li>
        <li><strong>How do users currently sign in to their devices?</strong> (Local accounts, AD, Azure AD join, etc.)</li>
        <li><strong>Do you require MFA for any systems today?</strong> Which ones?</li>
        <li><strong>What MFA solutions are you using?</strong> (Okta, Duo, Microsoft, other)</li>
        <li><strong>Are you already using Okta for SSO?</strong> Which applications?</li>
        <li><strong>Do users have different passwords for devices vs applications?</strong></li>
      </ul>

      <h3>Current Security Posture</h3>
      <ul>
        <li><strong>How do you enforce security policies on endpoints today?</strong></li>
        <li><strong>Do you have device compliance requirements?</strong> (FileVault, BitLocker, antivirus, etc.)</li>
        <li><strong>Are there regulatory compliance requirements?</strong> (HIPAA, SOC2, PCI-DSS, etc.)</li>
        <li><strong>How do you handle lost or stolen devices?</strong></li>
        <li><strong>Do you have passwordless authentication anywhere?</strong></li>
      </ul>

      <h2>2. Pain Point Identification</h2>

      <h3>Help Desk & Support Pain Points</h3>
      <ul>
        <li><strong>How many help desk tickets do you get monthly for password resets?</strong></li>
        <li><strong>What's your average resolution time for a locked account?</strong></li>
        <li><strong>How do users reset passwords when locked out of their device?</strong></li>
        <li><strong>Do you have users who work remotely or offline frequently?</strong></li>
        <li><strong>What's the cost per ticket for your help desk?</strong></li>
      </ul>

      <h3>Security Pain Points</h3>
      <ul>
        <li><strong>Have you experienced phishing attacks targeting user credentials?</strong></li>
        <li><strong>Are you concerned about weak passwords at the device level?</strong></li>
        <li><strong>Have you had unauthorized device access incidents?</strong></li>
        <li><strong>Do you have visibility into who's signing into devices?</strong></li>
        <li><strong>Are you working toward Zero Trust?</strong> What's your current progress?</li>
      </ul>

      <h3>User Experience Pain Points</h3>
      <ul>
        <li><strong>Do users complain about password sprawl?</strong> (Different passwords for device, email, apps)</li>
        <li><strong>How do users feel about your current MFA solution?</strong></li>
        <li><strong>What's the onboarding experience for new devices?</strong></li>
        <li><strong>Do you have VIP users (executives) with special requirements?</strong></li>
        <li><strong>What happens when users forget their device password while traveling?</strong></li>
      </ul>

      <h3>IT Operations Pain Points</h3>
      <ul>
        <li><strong>How long does it take to provision a new device for a user?</strong></li>
        <li><strong>How do you handle device reprovisioning?</strong></li>
        <li><strong>Do you have manual processes for device setup?</strong></li>
        <li><strong>How do you manage password policy enforcement across devices and apps?</strong></li>
        <li><strong>What's your biggest operational bottleneck with device management?</strong></li>
      </ul>

      <h2>3. Technical Environment Assessment</h2>

      <h3>Network Architecture</h3>
      <ul>
        <li><strong>Do users work on-premise, remote, or hybrid?</strong> What's the breakdown?</li>
        <li><strong>Do you have proxy servers or firewall restrictions?</strong></li>
        <li><strong>Are there network segments that need special consideration?</strong> (DMZ, isolated networks)</li>
        <li><strong>What's your VPN solution?</strong> Always-on or on-demand?</li>
        <li><strong>Do you have direct internet access or forced tunneling?</strong></li>
      </ul>

      <h3>Active Directory Environment</h3>
      <ul>
        <li><strong>Do you use Active Directory?</strong> On-prem, Azure AD, or hybrid?</li>
        <li><strong>Single forest or multi-forest?</strong></li>
        <li><strong>Do you use AD password sync to Okta already?</strong></li>
        <li><strong>What's your password policy in AD?</strong> (Complexity, rotation, etc.)</li>
        <li><strong>Do you have any AD-integrated applications that must continue working?</strong></li>
      </ul>

      <h3>MDM Deep Dive</h3>
      <ul>
        <li><strong>What version of your MDM are you running?</strong></li>
        <li><strong>How do you deploy applications via MDM?</strong></li>
        <li><strong>Do you use configuration profiles extensively?</strong></li>
        <li><strong>Who manages your MDM?</strong> (Internal team, MSP, consultant)</li>
        <li><strong>Have you deployed any SSO extensions before?</strong> (For macOS)</li>
        <li><strong>Do you have staging/testing environments?</strong></li>
      </ul>

      <h3>Okta Environment (if existing customer)</h3>
      <ul>
        <li><strong>What Okta features are you using today?</strong></li>
        <li><strong>Are you on Okta Identity Engine (OIE)?</strong></li>
        <li><strong>What authentication policies do you have configured?</strong></li>
        <li><strong>How are you using Okta Verify today?</strong></li>
        <li><strong>Do you have any custom integrations or workflows?</strong></li>
      </ul>

      <h2>4. Business Requirements & Success Criteria</h2>

      <h3>Project Goals</h3>
      <ul>
        <li><strong>What's driving this project?</strong> (Security incident, compliance, user experience, cost reduction)</li>
        <li><strong>What does success look like for you?</strong></li>
        <li><strong>Are there specific KPIs you need to achieve?</strong></li>
        <li><strong>What's the business impact if you don't solve this?</strong></li>
        <li><strong>How will you measure ROI?</strong></li>
      </ul>

      <h3>Use Case Priorities</h3>
      <ul>
        <li><strong>Is Desktop MFA your primary goal, or is password sync equally important?</strong></li>
        <li><strong>Are you interested in passwordless authentication?</strong></li>
        <li><strong>Do you want self-service password reset at the device login?</strong></li>
        <li><strong>Is JIT account creation relevant for your macOS environment?</strong></li>
        <li><strong>Do you need device trust signals for conditional access?</strong></li>
      </ul>

      <h3>Constraints & Requirements</h3>
      <ul>
        <li><strong>Are there any deployment windows or blackout periods?</strong></li>
        <li><strong>Do you have change management processes we need to follow?</strong></li>
        <li><strong>Are there union or employee privacy considerations?</strong></li>
        <li><strong>What's your tolerance for user disruption?</strong></li>
        <li><strong>Do you need to maintain backward compatibility with anything?</strong></li>
      </ul>

      <h2>5. Decision Process & Stakeholders</h2>

      <h3>Stakeholder Identification</h3>
      <ul>
        <li><strong>Who are the key stakeholders for this project?</strong></li>
        <li><strong>Who is the technical decision maker?</strong></li>
        <li><strong>Who is the business/budget owner?</strong></li>
        <li><strong>Who will be involved in the POC evaluation?</strong></li>
        <li><strong>Are there any executive sponsors?</strong></li>
        <li><strong>Who manages end-user communication and change management?</strong></li>
      </ul>

      <h3>Evaluation Process</h3>
      <ul>
        <li><strong>What's your evaluation process?</strong> (Demo, POC, vendor comparison)</li>
        <li><strong>Are you evaluating other solutions?</strong> Which ones?</li>
        <li><strong>What are your POC success criteria?</strong></li>
        <li><strong>How long do you need for evaluation?</strong></li>
        <li><strong>What happens after a successful POC?</strong></li>
      </ul>

      <h3>Timeline & Budget</h3>
      <ul>
        <li><strong>What's your desired timeline for deployment?</strong></li>
        <li><strong>Is there budget allocated for this project?</strong></li>
        <li><strong>When does your fiscal year end?</strong></li>
        <li><strong>Are there dependencies on other projects?</strong></li>
        <li><strong>What's the urgency level?</strong> (Nice to have, strategic initiative, compliance deadline)</li>
      </ul>

      <h2>Discovery Best Practices</h2>

      <h3>Conversation Tips</h3>
      <ul>
        <li><strong>Listen more than you talk</strong> - 70% listening, 30% talking</li>
        <li><strong>Ask "why"</strong> - Dig deeper into motivations and pain points</li>
        <li><strong>Take detailed notes</strong> - Capture technical details and stakeholder quotes</li>
        <li><strong>Confirm understanding</strong> - Repeat back what you heard</li>
        <li><strong>Don't pitch too early</strong> - Complete discovery before jumping to solutions</li>
      </ul>

      <h3>Red Flags to Watch For</h3>
      <ul>
        <li>No clear business driver or urgency</li>
        <li>Can't identify a technical champion</li>
        <li>Budget not allocated or unclear</li>
        <li>Unrealistic timeline expectations</li>
        <li>Existing solution "works fine"</li>
        <li>No executive sponsorship for a large deployment</li>
        <li>Technical environment doesn't meet prerequisites</li>
      </ul>

      <h3>Green Flags (High-Quality Opportunities)</h3>
      <ul>
        <li>Clear business pain points with measurable impact</li>
        <li>Executive sponsorship and budget allocated</li>
        <li>Recent security incident driving urgency</li>
        <li>Compliance deadline requiring action</li>
        <li>Already using Okta for SSO</li>
        <li>Modern MDM in place with good coverage</li>
        <li>IT team engaged and excited about the solution</li>
      </ul>

      <h2>Post-Discovery Actions</h2>

      <h3>Document and Share</h3>
      <ol>
        <li>Create a discovery summary document</li>
        <li>Document technical architecture diagram</li>
        <li>List pain points with quantified impact</li>
        <li>Map stakeholders with their priorities</li>
        <li>Identify risks and mitigation strategies</li>
        <li>Share internally with your account team</li>
      </ol>

      <h3>Next Steps</h3>
      <ol>
        <li>Schedule technical deep-dive demo tailored to their environment</li>
        <li>Prepare POC scope document if appropriate</li>
        <li>Create custom ROI analysis based on their pain points</li>
        <li>Develop deployment roadmap aligned with their timeline</li>
        <li>Identify reference customers in similar industries/situations</li>
      </ol>
    `,
    summary: 'Comprehensive discovery framework for Solution Engineers to qualify opportunities, uncover pain points, understand technical environments, and identify stakeholders for Okta Device Access projects.',
    category: 'discovery',
    tags: ['discovery', 'qualification', 'sales', 'solution engineering', 'pain points', 'stakeholders'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-use-case-library',
    title: 'Use Case Library for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This library contains real-world use cases that demonstrate the value of Okta Device Access across different scenarios. Use these to help prospects understand how the solution applies to their situation.</p>

      <h2>Use Case 1: Remote Workforce Security</h2>

      <h3>Business Scenario</h3>
      <p>Company has shifted to 70% remote workforce. Employees access corporate resources from home networks, coffee shops, and while traveling. Traditional VPN + password authentication creates security gaps.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>No MFA enforcement at device login leaves endpoints vulnerable</li>
        <li>Users reuse weak passwords across device and applications</li>
        <li>Help desk overwhelmed with password reset requests from remote users</li>
        <li>No visibility into who's accessing devices when not on corporate network</li>
        <li>Phishing attacks successfully stealing device credentials</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Desktop MFA</strong> enforces strong authentication before device access</li>
        <li><strong>Password Sync</strong> eliminates password drift between device and Okta</li>
        <li><strong>Self-Service Password Reset</strong> reduces help desk tickets by 40-60%</li>
        <li><strong>FastPass</strong> enables passwordless, phishing-resistant authentication</li>
        <li><strong>Okta System Log</strong> provides audit trail of all device sign-ins</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>60% reduction in password-related help desk tickets</li>
        <li>Eliminated unauthorized device access incidents</li>
        <li>Users save 5-10 minutes per week on password management</li>
        <li>IT achieves full visibility into device authentication events</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Technology, Professional Services, Consulting, Financial Services</p>

      <h2>Use Case 2: Contractor & BYOD Access Management</h2>

      <h3>Business Scenario</h3>
      <p>Company relies on contractors and consultants who need temporary access to corporate resources. They use personal devices (BYOD) that can't be fully managed by IT.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Can't enforce corporate security policies on contractor devices</li>
        <li>Contractors create local accounts with weak passwords</li>
        <li>No way to revoke device access when contract ends</li>
        <li>Audit compliance requires tracking contractor device access</li>
        <li>Risk of data leakage on unmanaged devices</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Desktop MFA</strong> enforces authentication without full MDM enrollment</li>
        <li><strong>Okta policy engine</strong> applies different rules for contractors vs employees</li>
        <li><strong>Device logout</strong> enables remote sign-out when access is revoked</li>
        <li><strong>Conditional access</strong> can require registered devices for sensitive data</li>
        <li><strong>Audit logs</strong> track all contractor device authentication</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>100% of contractor devices require MFA</li>
        <li>Reduced offboarding time from 2 hours to 10 minutes</li>
        <li>Zero data leakage incidents from contractor devices</li>
        <li>Full audit compliance for contractor access</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Healthcare, Consulting, Manufacturing, Retail</p>

      <h2>Use Case 3: HIPAA/SOC2 Compliance Requirements</h2>

      <h3>Business Scenario</h3>
      <p>Healthcare provider or SaaS company must demonstrate device-level access controls for HIPAA or SOC2 compliance audits.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Auditors require MFA for all system access, including endpoints</li>
        <li>Need audit logs showing who accessed devices and when</li>
        <li>Must prevent unauthorized device access to PHI/PII</li>
        <li>Password-only authentication insufficient for compliance</li>
        <li>Manual processes for tracking device access don't scale</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Desktop MFA</strong> satisfies auditor requirements for device-level MFA</li>
        <li><strong>Okta System Log</strong> provides tamper-proof audit trail</li>
        <li><strong>Policy enforcement</strong> ensures consistent security across all devices</li>
        <li><strong>Device registration</strong> creates inventory of authorized devices</li>
        <li><strong>FIDO2 support</strong> enables phishing-resistant authentication</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>100% compliance with MFA requirements for audits</li>
        <li>Automated audit reports reduce prep time by 80%</li>
        <li>Zero audit findings related to device access controls</li>
        <li>Reduced audit costs and faster certification</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Healthcare, SaaS, Financial Services, Insurance</p>

      <h2>Use Case 4: M&A Integration</h2>

      <h3>Business Scenario</h3>
      <p>Company acquiring another organization needs to quickly integrate new employees while maintaining security standards.</p>

      <h3>Pain Points</h3>
      <li>Acquired company has different identity and device management systems</li>
        <li>Need to enforce corporate security policies on newly acquired devices</li>
        <li>Users resistant to changing authentication methods</li>
        <li>Timeline pressure to complete integration quickly</li>
        <li>Can't afford to rebuild all devices during transition</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Desktop MFA</strong> layers onto existing devices without reimaging</li>
        <li><strong>Phased rollout</strong> allows gradual migration of users</li>
        <li><strong>Okta SSO</strong> unifies authentication across both organizations</li>
        <li><strong>Policy flexibility</strong> allows different rules during transition</li>
        <li><strong>Self-service onboarding</strong> reduces IT burden</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>Integrated 500 users in 4 weeks vs 6 months projected</li>
        <li>Maintained security posture during transition</li>
        <li>Zero increase in help desk tickets during integration</li>
        <li>85% user satisfaction with unified authentication</li>
      </ul>

      <h3>Target Industries</h3>
      <p>All industries experiencing M&A activity</p>

      <h2>Use Case 5: Zero Trust Implementation</h2>

      <h3>Business Scenario</h3>
      <p>Enterprise moving from perimeter-based security to Zero Trust architecture. Need to verify device and user identity before granting access to resources.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Legacy VPN provides broad network access once authenticated</li>
        <li>No continuous verification of user and device trust</li>
        <li>Device posture signals not integrated with access decisions</li>
        <li>Can't differentiate between managed and unmanaged devices</li>
        <li>Lateral movement risk within network</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Device registration</strong> establishes device identity and trust</li>
        <li><strong>FastPass</strong> provides cryptographic device binding</li>
        <li><strong>Okta conditional access</strong> uses device signals for authorization</li>
        <li><strong>Continuous verification</strong> at device and app level</li>
        <li><strong>Device posture integration</strong> with Okta Device Trust</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>Eliminated VPN for 80% of use cases</li>
        <li>Reduced attack surface by enforcing least privilege</li>
        <li>Improved user experience with seamless authentication</li>
        <li>Foundation for broader Zero Trust architecture</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Financial Services, Technology, Government, Critical Infrastructure</p>

      <h2>Use Case 6: Shared Device Environments</h2>

      <h3>Business Scenario</h3>
      <p>Healthcare clinics, retail stores, or manufacturing facilities with shared workstations used by multiple employees per shift.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Users share generic accounts ("clinic1", "register2")</li>
        <li>No accountability for actions taken on shared devices</li>
        <li>Compliance requirements need individual authentication</li>
        <li>Password sticky notes on shared devices</li>
        <li>Can't track who accessed patient/customer data</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Desktop MFA</strong> requires individual authentication even on shared devices</li>
        <li><strong>Fast user switching</strong> allows quick transition between users</li>
        <li><strong>Okta Verify Push</strong> eliminates password typing at shared stations</li>
        <li><strong>Session management</strong> automatically logs out inactive users</li>
        <li><strong>Audit logs</strong> track individual user access on shared devices</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>100% accountability for actions on shared devices</li>
        <li>HIPAA compliance for shared clinical workstations</li>
        <li>Eliminated password sharing and sticky notes</li>
        <li>Improved security without impacting clinical workflow</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Healthcare, Retail, Manufacturing, Education</p>

      <h2>Use Case 7: High-Security Environments</h2>

      <h3>Business Scenario</h3>
      <p>Financial services firm or government agency with strict security requirements and sensitive data handling.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Regulatory requirements for phishing-resistant authentication</li>
        <li>Need cryptographic proof of device and user identity</li>
        <li>Password-based auth insufficient for high-value systems</li>
        <li>Insider threat concerns require strong device controls</li>
        <li>Audit requirements for all privileged access</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>FIDO2 security keys</strong> provide phishing-resistant authentication</li>
        <li><strong>FastPass</strong> uses hardware-backed keys (TPM/Secure Enclave)</li>
        <li><strong>Device registration</strong> proves device ownership</li>
        <li><strong>Policy enforcement</strong> requires registered + compliant devices</li>
        <li><strong>Comprehensive logging</strong> for forensics and compliance</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>Zero successful phishing attacks on device credentials</li>
        <li>Met regulatory requirements for strong authentication</li>
        <li>Passed security audits without findings</li>
        <li>Reduced insider threat risk with device-level controls</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Financial Services, Government, Defense, Critical Infrastructure</p>

      <h2>Use Case 8: Password Sprawl Elimination</h2>

      <h3>Business Scenario</h3>
      <p>Users manage separate passwords for device login, email, VPN, and dozens of applications, leading to security and productivity issues.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Users forget which password goes with which system</li>
        <li>Password drift between device and directory causes lockouts</li>
        <li>Help desk spends 30% of time on password resets</li>
        <li>Users write passwords on sticky notes</li>
        <li>Password complexity requirements frustrate users</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Password Sync</strong> unifies device and Okta passwords</li>
        <li><strong>Okta SSO</strong> eliminates app-specific passwords</li>
        <li><strong>FastPass passwordless</strong> removes password entirely</li>
        <li><strong>Self-service reset</strong> empowers users to fix their own issues</li>
        <li><strong>Single password policy</strong> enforced across all systems</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>Users manage 1 password instead of 15+</li>
        <li>60% reduction in password-related help desk tickets</li>
        <li>Improved security with stronger, consistent passwords</li>
        <li>User satisfaction scores increase 35%</li>
        <li>IT team freed up to focus on strategic initiatives</li>
      </ul>

      <h3>Target Industries</h3>
      <p>All industries, especially those with large user bases</p>

      <h2>Use Case 9: Offline Worker Support</h2>

      <h3>Business Scenario</h3>
      <p>Field service workers, aircraft crew, or remote site employees who frequently work without reliable network connectivity.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>Can't authenticate to devices when offline</li>
        <li>Users locked out of devices in remote locations</li>
        <li>Security team concerned about cached credentials</li>
        <li>Grace periods too permissive or too restrictive</li>
        <li>No audit trail for offline authentication</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Offline factors</strong> allow authentication without network</li>
        <li><strong>Configurable grace periods</strong> balance security and usability</li>
        <li><strong>Cached authentication</strong> with secure credential storage</li>
        <li><strong>Offline TOTP</strong> for time-based codes without connectivity</li>
        <li><strong>Sync when online</strong> updates policies and logs events</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>Zero productivity loss from offline lockouts</li>
        <li>Maintained security posture for offline scenarios</li>
        <li>Reduced emergency IT callouts by 70%</li>
        <li>Policy flexibility supports diverse work environments</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Energy & Utilities, Transportation, Construction, Field Services</p>

      <h2>Use Case 10: Legacy System Modernization</h2>

      <h3>Business Scenario</h3>
      <p>Company with aging Active Directory infrastructure wants to modernize identity without rip-and-replace migration.</p>

      <h3>Pain Points</h3>
      <ul>
        <li>AD password policies outdated and inflexible</li>
        <li>Can't implement modern auth (MFA, passwordless) with AD alone</li>
        <li>Hybrid AD + cloud identity creates complexity</li>
        <li>Want to reduce AD dependency over time</li>
        <li>Need to maintain compatibility during transition</li>
      </ul>

      <h3>Okta Device Access Solution</h3>
      <ul>
        <li><strong>Desktop MFA</strong> adds modern auth layer on top of AD</li>
        <li><strong>AD writeback</strong> maintains compatibility with AD-dependent apps</li>
        <li><strong>Gradual migration</strong> from AD to Okta-primary identity</li>
        <li><strong>FastPass</strong> enables passwordless while AD still exists</li>
        <li><strong>Unified policy</strong> across hybrid environment</li>
      </ul>

      <h3>Measurable Outcomes</h3>
      <ul>
        <li>Modernized authentication without AD replacement</li>
        <li>Reduced AD dependency by 60% over 12 months</li>
        <li>Enabled cloud migration roadmap</li>
        <li>Improved security posture without disruption</li>
      </ul>

      <h3>Target Industries</h3>
      <p>Enterprises with legacy AD infrastructure across all industries</p>

      <h2>How to Use This Library</h2>

      <h3>During Discovery</h3>
      <ul>
        <li>Listen for pain points that match these use cases</li>
        <li>Ask questions that reveal which scenarios apply</li>
        <li>Use use cases to help prospects articulate their challenges</li>
      </ul>

      <h3>During Demos</h3>
      <ul>
        <li>Frame demos around relevant use cases</li>
        <li>Show features in context of solving specific problems</li>
        <li>Use customer quotes from similar scenarios</li>
      </ul>

      <h3>In Proposals</h3>
      <ul>
        <li>Reference use cases that match prospect situation</li>
        <li>Include measurable outcomes in ROI calculations</li>
        <li>Provide case studies from similar industries</li>
      </ul>
    `,
    summary: '10 real-world use cases demonstrating Okta Device Access value across remote workforce, compliance, M&A, Zero Trust, shared devices, and more.',
    category: 'use-cases',
    tags: ['use cases', 'scenarios', 'remote work', 'compliance', 'zero trust', 'shared devices', 'ROI'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-objection-handling',
    title: 'Objection Handling for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This guide provides structured responses to the most common objections SEs encounter when selling Okta Device Access. Each objection includes empathy, reframe, proof points, and next steps.</p>

      <h2>Objection 1: "We Already Have Intune/Jamf"</h2>

      <h3>Why They Say It</h3>
      <p>Customer invested in MDM platform and believes it covers device access control. They see Okta Device Access as overlapping or redundant functionality.</p>

      <h3>Empathy Response</h3>
      <p>"I completely understand. You've already invested in Intune/Jamf and want to maximize that investment. Many of our customers had the same initial reaction."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access complements Intune/Jamf rather than replacing it. Think of MDM as device management (policies, apps, compliance) and Okta as identity and authentication. Together they create a complete solution:</p>
      <ul>
        <li><strong>MDM</strong> ensures devices are configured correctly and compliant</li>
        <li><strong>Okta Device Access</strong> verifies WHO is accessing the device with strong authentication</li>
        <li><strong>Integration</strong>: Okta can read device signals from Intune/Jamf for conditional access decisions</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>Intune/Jamf don't provide MFA at device login - they authenticate to MDM, not the device itself</li>
        <li>Password sync between device and cloud directory not available in standalone MDM</li>
        <li>No passwordless desktop authentication in Intune/Jamf alone</li>
        <li>Okta unifies authentication across devices AND applications (single identity fabric)</li>
        <li>Customer example: "Company X uses both Intune for device compliance and Okta Device Access for authentication - reduced password tickets by 60%"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Show architecture diagram illustrating MDM + Okta integration</li>
        <li>Demo how device signals from Intune/Jamf feed into Okta policies</li>
        <li>Provide customer reference who uses both successfully</li>
      </ul>

      <h2>Objection 2: "Users Won't Accept More Security Friction"</h2>

      <h3>Why They Say It</h3>
      <p>Customer concerned about user pushback on additional authentication steps. Previous security initiatives caused complaints. They prioritize user experience.</p>

      <h3>Empathy Response</h3>
      <p>"That's a valid concern. User adoption is critical for any security initiative. We've learned from customers who worried about the same thing."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access actually reduces friction for users in several ways:</p>
      <ul>
        <li><strong>Single sign-on</strong>: Authenticate to device, automatically signed into apps</li>
        <li><strong>Passwordless FastPass</strong>: Biometric authentication is faster and easier than passwords</li>
        <li><strong>Self-service password reset</strong>: Users fix their own issues without calling help desk</li>
        <li><strong>Password sync</strong>: Eliminates password drift - one password that always works</li>
        <li><strong>Remember device</strong>: Trusted devices require MFA less frequently</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>Users save 5-10 minutes per week on password management</li>
        <li>85-90% user satisfaction scores from customers post-deployment</li>
        <li>FastPass authentication is 3-5 seconds faster than traditional password</li>
        <li>60% reduction in password-related frustration and help desk tickets</li>
        <li>Customer quote: "Our users actually thanked us for rolling out FastPass - they love the biometric login"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Conduct user experience demo showing FastPass vs traditional login</li>
        <li>Propose phased rollout starting with IT/early adopters</li>
        <li>Share user testimonial videos from other customers</li>
        <li>Offer pilot program to measure user satisfaction</li>
      </ul>

      <h2>Objection 3: "This Is Too Complex to Deploy"</h2>

      <h3>Why They Say It</h3>
      <p>Customer has limited IT resources. Previous identity projects were difficult. They're concerned about disruption to business operations during rollout.</p>

      <h3>Empathy Response</h3>
      <p>"I hear you. You need solutions that are practical to implement with your current team. Complexity is a real risk."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access is designed for phased, low-risk deployment:</p>
      <ul>
        <li><strong>No re-imaging required</strong>: Deploys via MDM or installer to existing devices</li>
        <li><strong>Pilot groups</strong>: Start with IT, expand gradually based on learnings</li>
        <li><strong>Self-service enrollment</strong>: Users register their own devices, reducing IT burden</li>
        <li><strong>Flexible policies</strong>: Begin with password sync only, add MFA when ready</li>
        <li><strong>Rollback capability</strong>: Can disable policies without uninstalling</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>Average deployment: 4-6 weeks from kickoff to production for 1000 users</li>
        <li>Okta Professional Services available for hands-on implementation support</li>
        <li>Pre-built MDM profiles reduce configuration time by 80%</li>
        <li>Customers report 2-3 hours per week IT admin time after initial setup</li>
        <li>Customer example: "Deployed to 2500 users across 3 locations with only 2 IT staff in 6 weeks"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Provide detailed deployment timeline and resource plan</li>
        <li>Offer Professional Services scoping session</li>
        <li>Share deployment runbook and best practices guide</li>
        <li>Connect with customer reference who had similar constraints</li>
      </ul>

      <h2>Objection 4: "What About Offline Users?"</h2>

      <h3>Why They Say It</h3>
      <p>Customer has field workers, travelers, or remote locations with poor connectivity. Concerned users will be locked out when offline. Previous cloud solutions failed offline.</p>

      <h3>Empathy Response</h3>
      <p>"That's an important consideration. Offline access is critical for your business continuity. Let me show you how we've solved this."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access has robust offline capabilities built-in:</p>
      <ul>
        <li><strong>Cached credentials</strong>: Securely stored for offline authentication</li>
        <li><strong>Offline MFA factors</strong>: TOTP codes work without network</li>
        <li><strong>Configurable grace periods</strong>: Define how long offline access is permitted</li>
        <li><strong>Automatic sync</strong>: When device comes online, logs sync and policies update</li>
        <li><strong>Secure offline storage</strong>: Encrypted credential cache meets security requirements</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>Users can authenticate offline for 30, 60, or 90 days (configurable)</li>
        <li>Offline TOTP factor provides MFA without connectivity</li>
        <li>Zero lockout incidents for customers with field workers</li>
        <li>Policy changes take effect when device reconnects - no manual intervention</li>
        <li>Customer example: "Our construction site workers go weeks offline - Okta Device Access handles it seamlessly"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Demo offline authentication flow with network disabled</li>
        <li>Review offline policy configuration options</li>
        <li>Discuss grace period recommendations for their use case</li>
        <li>Connect with field services customer reference</li>
      </ul>

      <h2>Objection 5: "We're Not Ready for Passwordless"</h2>

      <h3>Why They Say It</h3>
      <p>Customer perceives passwordless as risky or unproven. They have legacy applications requiring passwords. Change management concerns about moving away from familiar authentication.</p>

      <h3>Empathy Response</h3>
      <p>"I understand. Passwordless is a big shift from traditional authentication. You want to move at a pace that's comfortable for your organization."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access supports a gradual journey to passwordless:</p>
      <ul>
        <li><strong>Phase 1</strong>: Start with Desktop MFA (password + second factor)</li>
        <li><strong>Phase 2</strong>: Add Password Sync to eliminate password drift</li>
        <li><strong>Phase 3</strong>: Enable FastPass for willing early adopters</li>
        <li><strong>Phase 4</strong>: Expand FastPass as users gain comfort</li>
        <li><strong>Flexibility</strong>: Some users passwordless, others password-based - both work</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>90% of Okta Device Access customers start with password + MFA, not passwordless</li>
        <li>FastPass creates phishing-resistant credentials (FIDO2/WebAuthn standard)</li>
        <li>Passwords can still work for legacy apps even with FastPass enabled</li>
        <li>Users who try FastPass have 95% retention rate - they prefer it to passwords</li>
        <li>Customer example: "We ran password + MFA for 6 months, then piloted FastPass with IT - now rolling to everyone by popular demand"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Propose phased roadmap starting with Desktop MFA only</li>
        <li>Demo both password-based and passwordless flows</li>
        <li>Share passwordless maturity model and assessment</li>
        <li>Provide customer case study of gradual FastPass adoption</li>
      </ul>

      <h2>Objection 6: "Too Expensive"</h2>

      <h3>Why They Say It</h3>
      <p>Budget constraints or sticker shock. Customer doesn't see clear ROI. Comparing to "free" options included with Microsoft E5 or existing tools. Need to justify cost to leadership.</p>

      <h3>Empathy Response</h3>
      <p>"Budget is always a consideration. You need to show clear value for any investment. Let's talk about the business case."</p>

      <h3>Reframe</h3>
      <p>The cost of NOT solving device access problems is higher than Okta pricing:</p>
      <ul>
        <li><strong>Help desk tickets</strong>: Password resets cost $25-70 each, 100s per month</li>
        <li><strong>Security incidents</strong>: Compromised credentials average $150K per incident</li>
        <li><strong>User productivity</strong>: 30 minutes per month per user on password issues</li>
        <li><strong>IT admin time</strong>: Manual device access management doesn't scale</li>
        <li><strong>Compliance fines</strong>: Audit failures can cost millions</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>Average customer ROI: 250% over 3 years</li>
        <li>Payback period: 6-9 months from help desk savings alone</li>
        <li>For 1000 users: Save $150K/year in help desk costs + $180K in productivity gains</li>
        <li>Avoided security incident: Single prevented breach pays for 3-5 years of Okta</li>
        <li>Customer example: "We saved $200K in first year from help desk reduction - Okta Device Access paid for itself twice over"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Build custom ROI model using their ticket volumes and costs</li>
        <li>Provide TCO comparison including "hidden costs" of alternatives</li>
        <li>Share business value calculator and case studies</li>
        <li>Offer pilot to prove ROI before full commitment</li>
      </ul>

      <h2>Objection 7: "We Need Active Directory Integration"</h2>

      <h3>Why They Say It</h3>
      <p>Customer has applications and infrastructure dependent on AD. Concerned Okta Device Access won't work with AD. Don't want to replace AD infrastructure.</p>

      <h3>Empathy Response</h3>
      <p>"Active Directory is critical to your environment. You need solutions that work with AD, not against it."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access integrates deeply with Active Directory:</p>
      <ul>
        <li><strong>AD Writeback</strong>: Password changes sync from Okta back to AD</li>
        <li><strong>AD domain join</strong>: Devices remain domain-joined, Okta layers on top</li>
        <li><strong>Hybrid authentication</strong>: Supports cloud + on-prem scenarios</li>
        <li><strong>GPO compatibility</strong>: Works alongside existing Group Policy</li>
        <li><strong>Migration path</strong>: Enables gradual move from AD-centric to cloud-centric</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>80% of Okta Device Access customers use AD integration</li>
        <li>Password writeback syncs in under 5 seconds</li>
        <li>Devices can authenticate to AD-joined resources after Okta login</li>
        <li>Supports complex scenarios: multiple AD forests, trust relationships</li>
        <li>Customer example: "We've had Okta Device Access running with AD for 2 years - zero issues with domain-joined apps"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Review AD integration architecture diagram</li>
        <li>Demo password writeback and domain join compatibility</li>
        <li>Discuss AD cloud sync options (AD Connect, cloud sync)</li>
        <li>Connect with customer reference running hybrid AD + Okta</li>
      </ul>

      <h2>Objection 8: "What About VDI/Virtual Desktops?"</h2>

      <h3>Why They Say It</h3>
      <p>Customer has Citrix, VMware Horizon, or AVD environment. Concerned about VDI compatibility. Not sure how device authentication applies to virtual desktops.</p>

      <h3>Empathy Response</h3>
      <p>"VDI environments have unique requirements. You need to understand exactly how Okta Device Access works in your virtual desktop setup."</p>

      <h3>Reframe</h3>
      <p>Okta Device Access supports multiple VDI scenarios:</p>
      <ul>
        <li><strong>Physical device authentication</strong>: Secure the endpoint accessing VDI</li>
        <li><strong>Virtual desktop authentication</strong>: Okta can authenticate into the virtual desktop itself</li>
        <li><strong>Dual-layer security</strong>: MFA at endpoint + MFA at VDI login</li>
        <li><strong>SSO to VDI</strong>: Authenticate once to device, SSO into virtual desktop</li>
        <li><strong>Verified compatibility</strong>: Works with Citrix, VMware, AVD</li>
      </ul>

      <h3>Proof Points</h3>
      <ul>
        <li>Okta partners with Citrix and VMware for certified integrations</li>
        <li>Can apply different policies to physical vs virtual desktops</li>
        <li>Supports persistent and non-persistent VDI deployments</li>
        <li>Customers use Okta Device Access on both endpoints and VDI sessions</li>
        <li>Customer example: "We protect both our physical laptops and Citrix virtual desktops with Okta Device Access - consistent security everywhere"</li>
      </ul>

      <h3>Next Steps</h3>
      <ul>
        <li>Review VDI architecture and integration points</li>
        <li>Discuss whether to protect endpoint, VDI, or both</li>
        <li>Provide VDI-specific deployment guide</li>
        <li>Connect with customer running similar VDI platform</li>
      </ul>

      <h2>How to Use This Guide</h2>

      <h3>Before the Call</h3>
      <ul>
        <li>Review likely objections based on prospect profile</li>
        <li>Prepare specific proof points relevant to their industry</li>
        <li>Have customer references ready for each objection type</li>
      </ul>

      <h3>During the Call</h3>
      <ul>
        <li>Listen fully before responding - understand the real concern</li>
        <li>Use empathy first - validate their concern is legitimate</li>
        <li>Reframe with "and" not "but" - build on their concern</li>
        <li>Provide 2-3 proof points maximum - don't overwhelm</li>
      </ul>

      <h3>After the Objection</h3>
      <ul>
        <li>Confirm you've addressed the concern: "Does that help with your question about...?"</li>
        <li>Offer concrete next step to prove your answer</li>
        <li>Document the objection and your response in CRM</li>
      </ul>
    `,
    summary: 'Structured responses to the 8 most common objections for Okta Device Access, including empathy, reframes, proof points, and next steps for SEs.',
    category: 'objection-handling',
    tags: ['objections', 'competitive', 'sales', 'responses', 'proof points', 'MDM', 'pricing'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-competitive-positioning',
    title: 'Competitive Positioning for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This guide provides battle cards for positioning Okta Device Access against common competitors and alternative approaches. Use these to differentiate Okta and win competitive deals.</p>

      <h2>vs. Microsoft Intune Alone</h2>

      <h3>Their Positioning</h3>
      <ul>
        <li>"Intune is included with Microsoft 365 E5 - you already own it"</li>
        <li>"Provides device compliance, conditional access, and app management"</li>
        <li>"Native integration with Windows and Azure AD"</li>
        <li>"Single pane of glass for device and identity management"</li>
      </ul>

      <h3>Our Positioning</h3>
      <ul>
        <li><strong>Identity-first approach</strong>: Okta unifies identity across devices, apps, and infrastructure</li>
        <li><strong>Desktop MFA at login</strong>: Intune doesn't provide MFA at the Windows/Mac login screen</li>
        <li><strong>Passwordless desktop auth</strong>: FastPass enables FIDO2 authentication Intune can't match</li>
        <li><strong>Multi-cloud support</strong>: Works with Azure AD, but also Google Workspace, AWS, and on-prem AD</li>
        <li><strong>Superior user experience</strong>: Password sync and self-service reduce friction and help desk load</li>
      </ul>

      <h3>When They Win</h3>
      <ul>
        <li>Customer is 100% Microsoft shop with no other cloud platforms</li>
        <li>Budget is extremely constrained and "free" is non-negotiable</li>
        <li>Customer only needs basic device compliance checks</li>
        <li>IT team deeply invested in Microsoft ecosystem and resistant to multi-vendor</li>
      </ul>

      <h3>When We Win</h3>
      <ul>
        <li>Customer uses multiple cloud platforms (Google, AWS, Salesforce)</li>
        <li>Security team requires MFA at device login, not just app access</li>
        <li>Help desk drowning in password reset tickets</li>
        <li>Customer wants passwordless authentication roadmap</li>
        <li>Need to support Mac devices (Intune Mac support is limited)</li>
        <li>Compliance requirements demand unified identity audit trail</li>
      </ul>

      <h3>Trap-Setting Questions</h3>
      <ul>
        <li>"How do you enforce MFA when users sign into their Windows or Mac device itself?"</li>
        <li>"When a user changes their password, does it sync automatically to all their devices?"</li>
        <li>"What's your plan for passwordless authentication at the desktop?"</li>
        <li>"How do you unify device authentication with application authentication in your logs?"</li>
        <li>"What happens when users access AWS, Google Workspace, or Salesforce - can Intune handle that?"</li>
      </ul>

      <h2>vs. Azure AD Joined Devices</h2>

      <h3>Their Positioning</h3>
      <ul>
        <li>"Azure AD Join provides modern device authentication"</li>
        <li>"Windows Hello for Business enables passwordless"</li>
        <li>"Seamless SSO to Microsoft 365 apps"</li>
        <li>"Conditional access based on device compliance state"</li>
      </ul>

      <h3>Our Positioning</h3>
      <ul>
        <li><strong>Vendor diversity</strong>: Not locked into Microsoft ecosystem</li>
        <li><strong>Mac support</strong>: Azure AD Join is Windows-only; Okta supports Mac natively</li>
        <li><strong>Unified identity fabric</strong>: One identity across devices, SaaS, on-prem, cloud infrastructure</li>
        <li><strong>Better user experience</strong>: Okta Password Sync simpler than Windows Hello provisioning</li>
        <li><strong>Flexibility</strong>: Support hybrid scenarios (some Azure AD, some on-prem AD, some local accounts)</li>
      </ul>

      <h3>When They Win</h3>
      <ul>
        <li>Customer is Windows-only environment</li>
        <li>Already fully committed to Azure AD as sole identity provider</li>
        <li>Microsoft E5 licenses already purchased and in use</li>
        <li>No plans to use non-Microsoft SaaS applications</li>
      </ul>

      <h3>When We Win</h3>
      <ul>
        <li>Customer has Mac devices (Azure AD Join doesn't support Mac)</li>
        <li>Multi-cloud environment (AWS, GCP, Oracle)</li>
        <li>Large SaaS portfolio beyond Microsoft 365</li>
        <li>Need to support hybrid identity (cloud + on-prem AD)</li>
        <li>Want best-of-breed identity vs single-vendor lock-in</li>
        <li>Require granular policy control beyond Microsoft capabilities</li>
      </ul>

      <h3>Trap-Setting Questions</h3>
      <ul>
        <li>"How many Mac devices do you have? How will Azure AD Join work for those?"</li>
        <li>"What non-Microsoft applications do your users access? How does Azure AD handle those?"</li>
        <li>"Do you have any on-premises Active Directory you still need to support?"</li>
        <li>"How do you feel about being 100% dependent on Microsoft for identity across your entire organization?"</li>
        <li>"What's your disaster recovery plan if Azure AD has an outage?"</li>
      </ul>

      <h2>vs. Jamf Connect</h2>

      <h3>Their Positioning</h3>
      <ul>
        <li>"Purpose-built for Mac device authentication"</li>
        <li>"Integrates deeply with Jamf Pro for complete Mac management"</li>
        <li>"Supports multiple identity providers including Okta"</li>
        <li>"FileVault integration for disk encryption"</li>
      </ul>

      <h3>Our Positioning</h3>
      <ul>
        <li><strong>Cross-platform</strong>: One solution for Mac AND Windows, not Mac-only</li>
        <li><strong>Native Okta integration</strong>: First-party solution, not third-party integration</li>
        <li><strong>Advanced features</strong>: FastPass passwordless, Desktop MFA, Password Sync all native</li>
        <li><strong>Unified logs and policies</strong>: Device auth in same system as app auth</li>
        <li><strong>Broader ecosystem</strong>: Okta ecosystem of 7000+ integrations vs Jamf's limited scope</li>
      </ul>

      <h3>When They Win</h3>
      <ul>
        <li>Customer is Mac-only environment (no Windows devices)</li>
        <li>Already deeply invested in Jamf Pro</li>
        <li>Mac-specific features like FileVault integration are critical</li>
        <li>Jamf relationship is strategic and they want single-vendor</li>
      </ul>

      <h3>When We Win</h3>
      <ul>
        <li>Customer has both Mac and Windows devices</li>
        <li>Already using Okta for application SSO</li>
        <li>Want passwordless FastPass for both desktop and apps</li>
        <li>Need unified identity across all systems, not just Mac devices</li>
        <li>Help desk overwhelmed with password issues - need Password Sync</li>
        <li>Security team wants consistent policies across all endpoints</li>
      </ul>

      <h3>Trap-Setting Questions</h3>
      <ul>
        <li>"What percentage of your devices are Windows vs Mac? How do you handle Windows authentication?"</li>
        <li>"Do you want different identity solutions for Mac vs Windows, or one unified approach?"</li>
        <li>"When users authenticate to their Mac, how does that relate to their app authentication?"</li>
        <li>"If you're already using Okta for SSO, do you want to manage another identity platform just for Mac?"</li>
        <li>"What's your roadmap for passwordless - just Mac or all endpoints?"</li>
      </ul>

      <h2>vs. Traditional VPN + Passwords</h2>

      <h3>Their Positioning</h3>
      <ul>
        <li>"VPN provides secure access to corporate network"</li>
        <li>"Passwords work fine - users know them"</li>
        <li>"Already have VPN infrastructure - no new investment needed"</li>
        <li>"Simple and proven approach that's worked for years"</li>
      </ul>

      <h3>Our Positioning</h3>
      <ul>
        <li><strong>Zero Trust architecture</strong>: Verify identity and device at every access, not once at network perimeter</li>
        <li><strong>Device-level security</strong>: Protect the endpoint itself, not just network access</li>
        <li><strong>Passwordless future</strong>: Eliminate phishing risk and password burden</li>
        <li><strong>User experience</strong>: No VPN connection steps - seamless access</li>
        <li><strong>Modern compliance</strong>: Auditors demand MFA and device authentication, not just VPN</li>
      </ul>

      <h3>When They Win</h3>
      <ul>
        <li>Customer extremely resistant to change</li>
        <li>Very small organization with minimal security requirements</li>
        <li>No budget for any new security investments</li>
        <li>No compliance or audit requirements</li>
      </ul>

      <h3>When We Win</h3>
      <ul>
        <li>Help desk drowning in password reset tickets</li>
        <li>Security team aware of phishing and credential theft risks</li>
        <li>Compliance requirements for MFA and device-level security</li>
        <li>Remote workforce frustrated with VPN connection issues</li>
        <li>Leadership wants to move to Zero Trust security model</li>
        <li>Recent security incident related to stolen credentials</li>
      </ul>

      <h3>Trap-Setting Questions</h3>
      <ul>
        <li>"How many password reset tickets does your help desk handle per month?"</li>
        <li>"What happens if an employee's password is stolen in a phishing attack?"</li>
        <li>"Do your auditors ask about MFA for device access, not just application access?"</li>
        <li>"How do users feel about connecting to VPN before they can start working?"</li>
        <li>"What's your plan for moving to Zero Trust security?"</li>
      </ul>

      <h2>General Competitive Best Practices</h2>

      <h3>Discovery Phase</h3>
      <ul>
        <li>Ask trap-setting questions early to expose competitor weaknesses</li>
        <li>Understand which competitor is in the deal before technical presentation</li>
        <li>Map customer pain points to areas where we differentiate</li>
        <li>Identify the "Why Okta?" criteria early - make them our strengths</li>
      </ul>

      <h3>Demo Phase</h3>
      <ul>
        <li>Lead with features competitors can't match (FastPass, Password Sync, Desktop MFA)</li>
        <li>Show cross-platform consistency if they use Mac + Windows</li>
        <li>Demonstrate unified logging across devices and apps</li>
        <li>Highlight user experience advantages (speed, ease, self-service)</li>
      </ul>

      <h3>Proposal Phase</h3>
      <ul>
        <li>Create comparison matrix showing our advantages</li>
        <li>Include TCO analysis - "free" Microsoft isn't actually free (implementation, support, limitations)</li>
        <li>Provide customer references who switched from competitor</li>
        <li>Address "Why not competitor?" explicitly in proposal</li>
      </ul>

      <h3>Closing Phase</h3>
      <ul>
        <li>Offer proof of concept to demonstrate superiority head-to-head</li>
        <li>Bring in customer reference for peer-to-peer validation</li>
        <li>Executive alignment on strategic identity vision, not just tactical features</li>
        <li>Risk reversal: pilot program, money-back guarantee, phased commitment</li>
      </ul>
    `,
    summary: 'Battle cards for positioning Okta Device Access against Microsoft Intune, Azure AD, Jamf Connect, and traditional VPN approaches with trap-setting questions.',
    category: 'competitive',
    tags: ['competitive', 'positioning', 'battle cards', 'Microsoft', 'Intune', 'Jamf', 'Azure AD', 'VPN'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-roi-framework',
    title: 'ROI Calculator and Business Value Framework',
    content: `
      <h2>Overview</h2>
      <p>This framework helps SEs quantify the business value of Okta Device Access using real customer data and industry benchmarks. Use these formulas and scenarios to build compelling ROI cases.</p>

      <h2>Cost Categories to Calculate</h2>

      <h3>1. Help Desk Ticket Reduction</h3>

      <h4>Baseline Metrics</h4>
      <ul>
        <li><strong>Average password reset cost</strong>: $25-70 per ticket (industry average: $40)</li>
        <li><strong>Typical password reset rate</strong>: 20-30% of users per month without Okta</li>
        <li><strong>Average ticket time</strong>: 15-20 minutes per password reset</li>
        <li><strong>Help desk hourly cost</strong>: $35-50 per hour (fully loaded)</li>
      </ul>

      <h4>Okta Device Access Impact</h4>
      <ul>
        <li><strong>Password reset reduction</strong>: 60-75% (typical: 65%)</li>
        <li><strong>Self-service adoption</strong>: 85-95% (typical: 90%)</li>
        <li><strong>Device lockout reduction</strong>: 70-80% (typical: 75%)</li>
      </ul>

      <h4>Formula</h4>
      <p><code>Annual Savings = (Users × Monthly Reset Rate × 12 × Cost per Ticket) × Reduction %</code></p>

      <h4>Example Calculation (1000 users)</h4>
      <ul>
        <li>Baseline: 1000 users × 25% reset rate = 250 tickets/month</li>
        <li>Annual tickets: 250 × 12 = 3,000 tickets</li>
        <li>Annual cost: 3,000 × $40 = $120,000</li>
        <li>With Okta: $120,000 × 65% reduction = $78,000 saved</li>
      </ul>

      <h3>2. Password Reset Time Savings</h3>

      <h4>Baseline Metrics</h4>
      <ul>
        <li><strong>Time per password reset call</strong>: 15-20 minutes (average: 17 minutes)</li>
        <li><strong>Self-service reset time</strong>: 2-3 minutes with Okta</li>
        <li><strong>User productivity value</strong>: $35-75 per hour (based on salary)</li>
      </ul>

      <h4>Formula</h4>
      <p><code>Time Savings = (Tickets Prevented × Minutes Saved) × (Hourly Productivity / 60)</code></p>

      <h4>Example Calculation (1000 users)</h4>
      <ul>
        <li>Tickets prevented: 3,000 × 65% = 1,950 tickets</li>
        <li>Time saved per ticket: 17 - 3 = 14 minutes</li>
        <li>Total minutes saved: 1,950 × 14 = 27,300 minutes = 455 hours</li>
        <li>Value at $50/hour: 455 × $50 = $22,750 saved</li>
      </ul>

      <h3>3. Security Incident Cost Avoidance</h3>

      <h4>Baseline Metrics</h4>
      <ul>
        <li><strong>Average breach cost</strong>: $150,000 - $500,000 per incident (Ponemon Institute)</li>
        <li><strong>Phishing success rate</strong>: 15-20% with passwords only</li>
        <li><strong>Credential theft incidents</strong>: 80% of breaches involve stolen credentials</li>
        <li><strong>MFA prevention rate</strong>: 99.9% of automated attacks (Microsoft data)</li>
      </ul>

      <h4>Okta Device Access Impact</h4>
      <ul>
        <li><strong>Phishing resistance</strong>: FastPass eliminates 99.9% of phishing risk</li>
        <li><strong>Desktop MFA</strong>: Prevents unauthorized device access even with stolen password</li>
        <li><strong>Device visibility</strong>: Audit logs enable faster incident response</li>
      </ul>

      <h4>Conservative Formula</h4>
      <p><code>Risk Reduction = (Probability of Incident × Avg Cost) × MFA Prevention Rate</code></p>

      <h4>Example Calculation</h4>
      <ul>
        <li>Assume 10% annual probability of credential-related incident</li>
        <li>Average cost: $200,000</li>
        <li>Expected annual loss: $200,000 × 10% = $20,000</li>
        <li>With Desktop MFA: $20,000 × 99% prevention = $19,800 avoided</li>
      </ul>

      <h3>4. IT Admin Time Savings</h3>

      <h4>Baseline Metrics</h4>
      <ul>
        <li><strong>Manual device provisioning</strong>: 30-60 minutes per device</li>
        <li><strong>Password policy management</strong>: 5-10 hours per month</li>
        <li><strong>Device access troubleshooting</strong>: 10-20 hours per month</li>
        <li><strong>IT admin hourly cost</strong>: $50-85 per hour (fully loaded)</li>
      </ul>

      <h4>Okta Device Access Impact</h4>
      <ul>
        <li><strong>Self-service enrollment</strong>: Reduces provisioning to 5 minutes</li>
        <li><strong>Automated policy enforcement</strong>: Saves 8 hours/month</li>
        <li><strong>Reduced troubleshooting</strong>: Saves 12 hours/month (fewer password issues)</li>
      </ul>

      <h4>Formula</h4>
      <p><code>Annual Savings = (Hours Saved per Month × 12) × IT Admin Hourly Cost</code></p>

      <h4>Example Calculation</h4>
      <ul>
        <li>Total hours saved: 20 hours/month (policy + troubleshooting)</li>
        <li>Annual hours: 20 × 12 = 240 hours</li>
        <li>Cost savings: 240 × $65 = $15,600</li>
      </ul>

      <h3>5. User Productivity Gains</h3>

      <h4>Baseline Metrics</h4>
      <ul>
        <li><strong>Time managing passwords</strong>: 5-10 minutes per week per user</li>
        <li><strong>Login time traditional auth</strong>: 30-45 seconds</li>
        <li><strong>Login time with FastPass</strong>: 5-10 seconds</li>
        <li><strong>Logins per day</strong>: 3-5 times (sleep, lock, restart)</li>
      </ul>

      <h4>Formula</h4>
      <p><code>Annual Productivity = (Users × Weekly Minutes Saved × 52 weeks) × (Hourly Value / 60)</code></p>

      <h4>Example Calculation (1000 users)</h4>
      <ul>
        <li>Time saved: 7 minutes per week per user (password management + faster login)</li>
        <li>Annual minutes: 1000 × 7 × 52 = 364,000 minutes = 6,067 hours</li>
        <li>Value at $50/hour: 6,067 × $50 = $303,333</li>
      </ul>

      <h2>Sample ROI Scenarios by Company Size</h2>

      <h3>Small Company: 500 Users</h3>

      <h4>Annual Costs Without Okta Device Access</h4>
      <ul>
        <li>Help desk tickets: 500 × 25% × 12 × $40 = $60,000</li>
        <li>User time on password issues: 500 × 7 min/week × 52 × ($45/60) = $136,500</li>
        <li>IT admin time: 15 hours/month × 12 × $60 = $10,800</li>
        <li>Security incident risk: $200K × 8% probability = $16,000</li>
        <li><strong>Total Annual Pain: $223,300</strong></li>
      </ul>

      <h4>Annual Benefits With Okta Device Access</h4>
      <ul>
        <li>Help desk reduction: $60,000 × 65% = $39,000</li>
        <li>User productivity: $136,500 × 50% = $68,250</li>
        <li>IT time savings: $10,800 × 60% = $6,480</li>
        <li>Security risk reduction: $16,000 × 90% = $14,400</li>
        <li><strong>Total Annual Benefit: $128,130</strong></li>
      </ul>

      <h4>Estimated Okta Cost</h4>
      <ul>
        <li>Okta Device Access: 500 users × $X per user = $Y annually (insert actual pricing)</li>
        <li><strong>Net ROI: ($128,130 - $Y) / $Y × 100%</strong></li>
        <li><strong>Payback Period: $Y / $10,677 per month = Z months</strong></li>
      </ul>

      <h3>Mid-Market: 2,500 Users</h3>

      <h4>Annual Costs Without Okta Device Access</h4>
      <ul>
        <li>Help desk tickets: 2,500 × 25% × 12 × $40 = $300,000</li>
        <li>User time on password issues: 2,500 × 7 min/week × 52 × ($50/60) = $758,333</li>
        <li>IT admin time: 25 hours/month × 12 × $65 = $19,500</li>
        <li>Security incident risk: $300K × 12% probability = $36,000</li>
        <li><strong>Total Annual Pain: $1,113,833</strong></li>
      </ul>

      <h4>Annual Benefits With Okta Device Access</h4>
      <ul>
        <li>Help desk reduction: $300,000 × 65% = $195,000</li>
        <li>User productivity: $758,333 × 50% = $379,167</li>
        <li>IT time savings: $19,500 × 65% = $12,675</li>
        <li>Security risk reduction: $36,000 × 95% = $34,200</li>
        <li><strong>Total Annual Benefit: $621,042</strong></li>
      </ul>

      <h4>Estimated Okta Cost</h4>
      <ul>
        <li>Okta Device Access: 2,500 users × $X per user = $Y annually</li>
        <li><strong>Net ROI: ($621,042 - $Y) / $Y × 100%</strong></li>
        <li><strong>Payback Period: $Y / $51,753 per month = Z months</strong></li>
      </ul>

      <h3>Enterprise: 10,000 Users</h3>

      <h4>Annual Costs Without Okta Device Access</h4>
      <ul>
        <li>Help desk tickets: 10,000 × 25% × 12 × $45 = $1,350,000</li>
        <li>User time on password issues: 10,000 × 8 min/week × 52 × ($60/60) = $4,160,000</li>
        <li>IT admin time: 40 hours/month × 12 × $75 = $36,000</li>
        <li>Security incident risk: $500K × 15% probability = $75,000</li>
        <li><strong>Total Annual Pain: $5,621,000</strong></li>
      </ul>

      <h4>Annual Benefits With Okta Device Access</h4>
      <ul>
        <li>Help desk reduction: $1,350,000 × 70% = $945,000</li>
        <li>User productivity: $4,160,000 × 55% = $2,288,000</li>
        <li>IT time savings: $36,000 × 70% = $25,200</li>
        <li>Security risk reduction: $75,000 × 99% = $74,250</li>
        <li><strong>Total Annual Benefit: $3,332,450</strong></li>
      </ul>

      <h4>Estimated Okta Cost</h4>
      <ul>
        <li>Okta Device Access: 10,000 users × $X per user = $Y annually</li>
        <li><strong>Net ROI: ($3,332,450 - $Y) / $Y × 100%</strong></li>
        <li><strong>Payback Period: $Y / $277,704 per month = Z months</strong></li>
      </ul>

      <h2>TCO Analysis Framework</h2>

      <h3>Compare: Okta Device Access vs. Alternatives</h3>

      <h4>Microsoft Intune/Azure AD</h4>
      <ul>
        <li><strong>Licensing cost</strong>: Requires E5 ($57/user/month) vs E3 ($36/user/month) = $21/user/month premium</li>
        <li><strong>Implementation cost</strong>: 3-6 months, $150K-300K professional services</li>
        <li><strong>Support cost</strong>: 2-3 FTE admins required for ongoing management</li>
        <li><strong>Limitation cost</strong>: Mac support gaps, help desk tickets remain high, no true passwordless</li>
        <li><strong>Total 3-Year TCO (1000 users)</strong>: $756K licensing + $200K implementation + $360K support = $1.316M</li>
      </ul>

      <h4>Jamf Connect</h4>
      <ul>
        <li><strong>Licensing cost</strong>: $8-12/user/month (Mac only)</li>
        <li><strong>Implementation cost</strong>: 1-2 months, $30K-60K</li>
        <li><strong>Support cost</strong>: 0.5-1 FTE for Jamf Pro + Connect</li>
        <li><strong>Limitation cost</strong>: Windows devices require separate solution, password sync limited</li>
        <li><strong>Total 3-Year TCO (1000 users, Mac only)</strong>: $360K licensing + $45K implementation + $120K support = $525K</li>
        <li><strong>Note</strong>: Add separate Windows solution costs for true comparison</li>
      </ul>

      <h4>Traditional VPN + Passwords (Status Quo)</h4>
      <ul>
        <li><strong>VPN infrastructure cost</strong>: $50K-150K for licenses + hardware</li>
        <li><strong>Support cost</strong>: 1-2 FTE for VPN + password management</li>
        <li><strong>Help desk burden</strong>: $120K-500K annually (depending on company size)</li>
        <li><strong>Security risk</strong>: $20K-75K annual expected loss from credential incidents</li>
        <li><strong>User productivity loss</strong>: $150K-4M annually (see calculations above)</li>
        <li><strong>Total 3-Year TCO (1000 users)</strong>: $100K infrastructure + $240K support + $360K help desk + $60K security + $450K productivity = $1.21M</li>
      </ul>

      <h3>Okta Device Access TCO</h3>
      <ul>
        <li><strong>Licensing cost</strong>: $X per user/month × 36 months</li>
        <li><strong>Implementation cost</strong>: 4-6 weeks, $20K-40K (much faster than alternatives)</li>
        <li><strong>Support cost</strong>: 0.25-0.5 FTE (minimal ongoing management)</li>
        <li><strong>Benefit realization</strong>: $128K-3.3M annually (see ROI scenarios)</li>
        <li><strong>Total 3-Year TCO (1000 users)</strong>: $Y licensing + $30K implementation + $60K support - $384K benefits = Net TCO</li>
      </ul>

      <h2>How to Build a Custom ROI Model</h2>

      <h3>Step 1: Discovery - Gather Customer Data</h3>
      <ul>
        <li>Number of users requiring device access</li>
        <li>Current help desk ticket volume for password resets</li>
        <li>Cost per help desk ticket (or hourly cost × avg time)</li>
        <li>Average employee hourly productivity value</li>
        <li>IT admin team size and hourly cost</li>
        <li>Recent security incidents related to credentials</li>
        <li>Current solutions in place (VPN, MDM, identity provider)</li>
      </ul>

      <h3>Step 2: Calculate Current State Costs</h3>
      <ul>
        <li>Use formulas above to calculate annual cost of password management</li>
        <li>Quantify user productivity loss from password friction</li>
        <li>Calculate IT admin time spent on device access issues</li>
        <li>Estimate security risk in dollar terms</li>
      </ul>

      <h3>Step 3: Project Future State Benefits</h3>
      <ul>
        <li>Apply Okta reduction percentages (be conservative)</li>
        <li>Calculate annual benefit across all categories</li>
        <li>Project 3-year cumulative benefit</li>
      </ul>

      <h3>Step 4: Calculate ROI Metrics</h3>
      <ul>
        <li><strong>Total Annual Benefit</strong>: Sum of all benefit categories</li>
        <li><strong>Net Annual Benefit</strong>: Total benefit - Okta annual cost</li>
        <li><strong>ROI %</strong>: (Net benefit / Okta cost) × 100</li>
        <li><strong>Payback Period</strong>: Okta cost / Monthly benefit = months to break even</li>
        <li><strong>3-Year NPV</strong>: Account for time value of money (optional)</li>
      </ul>

      <h3>Step 5: Present in Business Terms</h3>
      <ul>
        <li>Lead with payback period: "You'll recover your investment in X months"</li>
        <li>Show annual benefit: "After payback, you'll save $Y per year ongoing"</li>
        <li>Highlight biggest impact area: "The largest savings comes from..."</li>
        <li>Include risk mitigation: "Plus protection against $Z security incidents"</li>
        <li>Provide comparison: "vs. alternative X which costs more and delivers less"</li>
      </ul>

      <h2>ROI Presentation Best Practices</h2>

      <h3>For IT Audience</h3>
      <ul>
        <li>Emphasize time savings and reduction in help desk burden</li>
        <li>Show technical implementation ease and speed</li>
        <li>Highlight ongoing support and maintenance reduction</li>
      </ul>

      <h3>For Security Audience</h3>
      <ul>
        <li>Lead with risk reduction and compliance benefits</li>
        <li>Quantify cost of prevented security incidents</li>
        <li>Show audit trail and visibility improvements</li>
      </ul>

      <h3>For Finance/Executive Audience</h3>
      <ul>
        <li>Lead with ROI % and payback period</li>
        <li>Show total 3-year cost savings</li>
        <li>Compare TCO vs alternatives (especially "free" Microsoft)</li>
        <li>Include productivity gains in business terms</li>
      </ul>

      <h3>Common Pitfalls to Avoid</h3>
      <ul>
        <li>Don't overstate benefits - be conservative and defensible</li>
        <li>Don't ignore implementation costs - include them in TCO</li>
        <li>Don't compare licensing cost only - show total TCO</li>
        <li>Don't use generic industry data - customize with customer's actual numbers</li>
        <li>Don't forget to subtract Okta cost from benefits to show net value</li>
      </ul>
    `,
    summary: 'Comprehensive ROI calculator with formulas, industry benchmarks, and sample scenarios for 500, 2,500, and 10,000 users to quantify business value.',
    category: 'business-value',
    tags: ['ROI', 'business value', 'TCO', 'cost savings', 'help desk', 'productivity', 'security'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-demo-scripts',
    title: 'Demo Scripts for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This library provides ready-to-use demo scripts for different audiences and time constraints. Each script includes positioning, key highlights, technical steps, and talking points.</p>

      <h2>15-Minute Executive Demo</h2>

      <h3>Audience</h3>
      <p>C-level, VP-level, business decision makers with limited technical background</p>

      <h3>Objectives</h3>
      <ul>
        <li>Show business value, not technical features</li>
        <li>Demonstrate improved user experience</li>
        <li>Highlight security benefits</li>
        <li>Create urgency for next steps</li>
      </ul>

      <h3>Opening (2 minutes)</h3>
      <p><strong>Positioning</strong>: "Today I'll show you how Okta Device Access solves three critical challenges: reducing help desk costs by 60%, improving security at the device level, and creating a better user experience. We'll focus on business outcomes, not technical details."</p>

      <h3>Demo Flow</h3>

      <h4>Scene 1: The Password Problem (3 minutes)</h4>
      <p><strong>Show</strong>: Traditional Windows login with password</p>
      <ul>
        <li><strong>Say</strong>: "This is how most employees log into their devices today - username and password"</li>
        <li><strong>Show</strong>: User forgets password, types wrong one</li>
        <li><strong>Say</strong>: "When they forget their password - which happens to 25% of users every month - they call the help desk. Each call costs your organization $40 and takes 15 minutes of the employee's time. For a 1000-person company, that's $120,000 per year just in password resets."</li>
      </ul>

      <h4>Scene 2: Self-Service Password Reset (3 minutes)</h4>
      <p><strong>Show</strong>: Click "Forgot Password" link at login screen</p>
      <ul>
        <li><strong>Say</strong>: "With Okta Device Access, users can reset their own password right from the login screen"</li>
        <li><strong>Show</strong>: User verifies with push notification on phone, creates new password</li>
        <li><strong>Say</strong>: "They verify their identity with MFA on their phone - proving it's really them - then set a new password. Takes 2 minutes, zero help desk involvement. This alone reduces password reset tickets by 60-75%."</li>
        <li><strong>Show</strong>: Successfully log in with new password</li>
        <li><strong>Say</strong>: "And because this password is synced with Okta, it works for all their applications too - no password drift"</li>
      </ul>

      <h4>Scene 3: Passwordless with FastPass (4 minutes)</h4>
      <p><strong>Show</strong>: Mac or Windows login screen with FastPass</p>
      <ul>
        <li><strong>Say</strong>: "But we can take this even further. With FastPass, employees don't need passwords at all"</li>
        <li><strong>Show</strong>: Click username, use Touch ID / Windows Hello</li>
        <li><strong>Say</strong>: "Just their fingerprint or face - same biometric they use to unlock their phone. It's faster, more secure, and completely eliminates phishing risk because there's no password to steal"</li>
        <li><strong>Show</strong>: Device unlocks, user is signed in</li>
        <li><strong>Say</strong>: "And they're automatically signed into all their applications because Okta handles both device and app authentication"</li>
      </ul>

      <h4>Scene 4: Security & Visibility (2 minutes)</h4>
      <p><strong>Show</strong>: Okta System Log with device authentication events</p>
      <ul>
        <li><strong>Say</strong>: "For your security team, every device login is logged here - who accessed which device, when, and from where. This satisfies auditors and gives you complete visibility"</li>
        <li><strong>Show</strong>: Filter to show failed authentication attempts</li>
        <li><strong>Say</strong>: "You can see failed attempts - potential unauthorized access - and investigate immediately"</li>
      </ul>

      <h3>Closing (1 minute)</h3>
      <p><strong>Say</strong>: "So in summary, Okta Device Access delivers three key outcomes:</p>
      <ul>
        <li>60-75% reduction in help desk costs from password issues</li>
        <li>Stronger security through MFA and passwordless authentication at the device level</li>
        <li>Better user experience - faster logins, self-service, no password frustration</li>
      </ul>
      <p>Most customers see ROI within 6-9 months just from help desk savings alone."</p>

      <p><strong>Call to Action</strong>: "Next step: I'd recommend a technical deep dive with your IT and security teams to show how this works in your environment. Does next week work?"</p>

      <h2>45-Minute Technical Deep Dive</h2>

      <h3>Audience</h3>
      <p>IT admins, security engineers, architects - technical decision makers and influencers</p>

      <h3>Objectives</h3>
      <ul>
        <li>Demonstrate technical capabilities in depth</li>
        <li>Show architecture and integration points</li>
        <li>Address technical questions and concerns</li>
        <li>Prove feasibility for their environment</li>
      </ul>

      <h3>Opening (3 minutes)</h3>
      <p><strong>Positioning</strong>: "Today we'll go deep on how Okta Device Access works technically. We'll cover architecture, deployment options, user flows, policy configuration, and integration with your existing systems. I'll leave time for Q&A throughout - please interrupt with questions."</p>

      <h3>Demo Flow</h3>

      <h4>Section 1: Architecture Overview (5 minutes)</h4>
      <p><strong>Show</strong>: Architecture diagram</p>
      <ul>
        <li>Okta Device Access components (Okta Verify, credential provider, MDM profile/agent)</li>
        <li>Integration with Okta tenant</li>
        <li>Connection to existing identity sources (AD, Azure AD, etc.)</li>
        <li>MDM integration points (Intune, Jamf, Workspace ONE)</li>
      </ul>

      <p><strong>Say</strong>: "Here's how it works at a high level. Okta Verify on the device handles authentication, the credential provider integrates with Windows/Mac login, and everything communicates with your Okta tenant. We integrate with your existing identity sources - whether that's Active Directory, Azure AD, or Okta as the primary directory."</p>

      <h4>Section 2: Desktop MFA Flow (10 minutes)</h4>
      <p><strong>Show</strong>: Windows/Mac login with Desktop MFA</p>
      <ul>
        <li><strong>User enters credentials</strong>: "User provides username and password like normal"</li>
        <li><strong>MFA challenge</strong>: "Okta evaluates the authentication policy and prompts for second factor"</li>
        <li><strong>Show policy configuration</strong>: Navigate to Okta admin console, show Desktop MFA policy settings</li>
        <li><strong>Say</strong>: "You control which factor types are allowed - push notification, TOTP, SMS, FIDO2. You can require MFA always, or only when certain conditions aren't met"</li>
        <li><strong>Complete MFA</strong>: Approve push notification</li>
        <li><strong>Device unlocks</strong>: "Once verified, user gains access to the device"</li>
      </ul>

      <p><strong>Technical Details</strong>:</p>
      <ul>
        <li>Show System Log entry for device authentication</li>
        <li>Explain offline caching for disconnected scenarios</li>
        <li>Discuss grace periods and offline policy</li>
      </ul>

      <h4>Section 3: Password Sync Setup (8 minutes)</h4>
      <p><strong>Show</strong>: Password Sync configuration in Okta admin</p>
      <ul>
        <li><strong>Navigate to</strong>: Settings > Account > Password Sync</li>
        <li><strong>Say</strong>: "Password Sync keeps the device password and Okta password in sync. When users change password in either location, it updates both"</li>
        <li><strong>Show options</strong>: Writeback to AD, local account sync, password policy enforcement</li>
      </ul>

      <p><strong>Demo Password Change Flow</strong>:</p>
      <ul>
        <li>User changes password in Okta dashboard</li>
        <li>Show sync happening in background</li>
        <li>Log into device with new password - it works immediately</li>
        <li><strong>Say</strong>: "Sync happens within seconds. Users never experience password drift between device and applications"</li>
      </ul>

      <p><strong>Technical Details</strong>:</p>
      <ul>
        <li>Explain AD writeback architecture (Okta AD agent)</li>
        <li>Discuss password policy enforcement (Okta vs AD)</li>
        <li>Show how to handle multiple AD domains</li>
      </ul>

      <h4>Section 4: FastPass Passwordless (10 minutes)</h4>
      <p><strong>Show</strong>: FastPass enrollment process</p>
      <ul>
        <li><strong>User clicks</strong>: "Set up Passwordless" prompt</li>
        <li><strong>Authenticate</strong>: Complete MFA to verify identity</li>
        <li><strong>Enroll biometric</strong>: Set up Touch ID or Windows Hello</li>
        <li><strong>Say</strong>: "FastPass enrollment is automatic for most users - they just verify identity once and register biometric"</li>
      </ul>

      <p><strong>Demo FastPass Login</strong>:</p>
      <ul>
        <li>Lock device, return to login screen</li>
        <li>Click username</li>
        <li>Use biometric (fingerprint or face)</li>
        <li>Device unlocks in 3-5 seconds</li>
        <li><strong>Say</strong>: "That's it - no password needed. This uses FIDO2/WebAuthn standards, so it's phishing-resistant and highly secure"</li>
      </ul>

      <p><strong>Technical Details</strong>:</p>
      <ul>
        <li>Show FastPass policy configuration</li>
        <li>Explain TPM/Secure Enclave requirement</li>
        <li>Discuss fallback options (password still works)</li>
        <li>Show device bound passkey in Okta admin</li>
      </ul>

      <h4>Section 5: Policy Configuration (5 minutes)</h4>
      <p><strong>Show</strong>: Okta admin console - Authentication Policies</p>
      <ul>
        <li><strong>Navigate to</strong>: Security > Authentication Policies</li>
        <li><strong>Create example policy</strong>: "Desktop MFA for Remote Users"</li>
        <li><strong>Show conditions</strong>: Network zone (outside corporate network), group membership, device platform</li>
        <li><strong>Show actions</strong>: Require MFA, allowed factor types, session lifetime</li>
        <li><strong>Say</strong>: "You have granular control - require MFA only for certain users, or only when off VPN, or always. You can have different policies for different groups"</li>
      </ul>

      <h4>Section 6: Reporting & Visibility (4 minutes)</h4>
      <p><strong>Show</strong>: System Log filtered for device authentication</p>
      <ul>
        <li>Filter: Event Type = "user.authentication.auth_via_desktop_sso"</li>
        <li><strong>Show details</strong>: User, device, location, time, factor used, result</li>
        <li><strong>Say</strong>: "Every device login is logged here. You can see who accessed what device, when, from where, and with which factor"</li>
        <li><strong>Show</strong>: Export to SIEM or create report</li>
      </ul>

      <h3>Q&A and Closing (remainder of time)</h3>
      <p><strong>Invite questions</strong>: "What questions do you have about the technical implementation?"</p>

      <p><strong>Common questions to be ready for</strong>:</p>
      <ul>
        <li>How does this work offline?</li>
        <li>What happens if Okta is down?</li>
        <li>Can we integrate with our existing MDM?</li>
        <li>How long does deployment take?</li>
        <li>What happens to existing local accounts?</li>
        <li>How do we handle shared devices?</li>
      </ul>

      <p><strong>Call to Action</strong>: "Next step: Let's set up a proof of concept in your environment with a pilot group. We can have that running in 1-2 weeks."</p>

      <h2>Persona-Based Demos</h2>

      <h3>For IT Admin Persona (20 minutes)</h3>

      <h4>Focus Areas</h4>
      <ul>
        <li>Easy deployment via MDM</li>
        <li>Minimal ongoing management</li>
        <li>Self-service capabilities reduce tickets</li>
        <li>Troubleshooting and support tools</li>
      </ul>

      <h4>Demo Highlights</h4>
      <ul>
        <li><strong>Show</strong>: MDM profile deployment (Intune, Jamf)</li>
        <li><strong>Show</strong>: Bulk user enrollment via group assignment</li>
        <li><strong>Show</strong>: Self-service password reset reducing help desk calls</li>
        <li><strong>Show</strong>: Admin console for device management and troubleshooting</li>
        <li><strong>Show</strong>: Logs and reports for support investigations</li>
      </ul>

      <h4>Key Messages</h4>
      <ul>
        <li>"Deploy to 1000 devices in a weekend using your existing MDM"</li>
        <li>"Users fix their own password issues - 60% reduction in tickets"</li>
        <li>"Manage all device access from one console, not multiple tools"</li>
        <li>"Ongoing maintenance is 2-3 hours per week maximum"</li>
      </ul>

      <h3>For Security Team Persona (20 minutes)</h3>

      <h4>Focus Areas</h4>
      <ul>
        <li>MFA at device level prevents unauthorized access</li>
        <li>Passwordless eliminates phishing risk</li>
        <li>Audit trail for compliance</li>
        <li>Policy enforcement and conditional access</li>
      </ul>

      <h4>Demo Highlights</h4>
      <ul>
        <li><strong>Show</strong>: Desktop MFA preventing access with stolen password</li>
        <li><strong>Show</strong>: FastPass FIDO2 credentials - phishing-resistant</li>
        <li><strong>Show</strong>: Policy requiring registered device for sensitive apps</li>
        <li><strong>Show</strong>: System Log audit trail for SOC2/HIPAA compliance</li>
        <li><strong>Show</strong>: Device posture signals feeding conditional access</li>
      </ul>

      <h4>Key Messages</h4>
      <ul>
        <li>"MFA at device login closes the biggest security gap in your environment"</li>
        <li>"FastPass eliminates 99.9% of phishing attacks targeting credentials"</li>
        <li>"Complete audit trail of who accessed which device, when, from where"</li>
        <li>"Integrate device posture with app access policies - Zero Trust foundation"</li>
      </ul>

      <h3>For End User Persona (10 minutes)</h3>

      <h4>Focus Areas</h4>
      <ul>
        <li>Faster, easier login experience</li>
        <li>Self-service password reset</li>
        <li>One password for everything</li>
        <li>Biometric authentication instead of typing</li>
      </ul>

      <h4>Demo Highlights</h4>
      <ul>
        <li><strong>Show</strong>: FastPass biometric login - quick and easy</li>
        <li><strong>Show</strong>: Self-service password reset when locked out</li>
        <li><strong>Show</strong>: Password sync - change once, works everywhere</li>
        <li><strong>Show</strong>: SSO into applications after device login</li>
      </ul>

      <h4>Key Messages</h4>
      <ul>
        <li>"Log in with your fingerprint instead of typing passwords"</li>
        <li>"Forgot your password? Reset it yourself in 2 minutes"</li>
        <li>"Change your password once and it works for your device and all apps"</li>
        <li>"Less time managing passwords = more time doing your real work"</li>
      </ul>

      <h3>For Help Desk Persona (15 minutes)</h3>

      <h4>Focus Areas</h4>
      <ul>
        <li>Massive reduction in password reset tickets</li>
        <li>Self-service tools empower users</li>
        <li>Better troubleshooting when issues do occur</li>
        <li>Happier users = happier help desk</li>
      </ul>

      <h4>Demo Highlights</h4>
      <ul>
        <li><strong>Show</strong>: User completing self-service password reset (help desk doesn't get called)</li>
        <li><strong>Show</strong>: Before/after ticket volume reports</li>
        <li><strong>Show</strong>: Troubleshooting tools in admin console for the rare issues</li>
        <li><strong>Show</strong>: User satisfaction improvements</li>
      </ul>

      <h4>Key Messages</h4>
      <ul>
        <li>"Your password reset tickets drop by 60-75% within first month"</li>
        <li>"Users fix their own issues without calling you"</li>
        <li>"When there are issues, you have better logs and tools to resolve quickly"</li>
        <li>"Users happier, your job easier - win-win"</li>
      </ul>

      <h2>Demo Environment Setup Guide</h2>

      <h3>Required Components</h3>
      <ul>
        <li><strong>Okta tenant</strong>: Preview or production environment</li>
        <li><strong>Windows VM</strong>: Windows 10/11 with Okta Device Access configured</li>
        <li><strong>Mac VM or device</strong>: macOS 13+ with Platform SSO configured</li>
        <li><strong>Test users</strong>: 3-5 users with different scenarios (MFA enrolled, FastPass enrolled, not enrolled)</li>
        <li><strong>Mobile device</strong>: Phone with Okta Verify for push notifications</li>
        <li><strong>MDM integration</strong>: Intune or Jamf connected to show deployment</li>
      </ul>

      <h3>Demo User Personas to Create</h3>
      <ul>
        <li><strong>demo-user-mfa</strong>: Has Desktop MFA enabled, password + push</li>
        <li><strong>demo-user-fastpass</strong>: Has FastPass enrolled, passwordless</li>
        <li><strong>demo-user-new</strong>: New user for showing enrollment flow</li>
        <li><strong>demo-admin</strong>: For showing admin console and configuration</li>
      </ul>

      <h3>Pre-Demo Checklist</h3>
      <ul>
        <li>Test all demo flows 30 minutes before the call</li>
        <li>Ensure devices are logged out and ready for login demos</li>
        <li>Clear browser cache and close unnecessary applications</li>
        <li>Have Okta admin console open in another tab</li>
        <li>Have architecture diagrams ready to share screen</li>
        <li>Test screen sharing with both Windows and Mac devices</li>
        <li>Have backup device in case of technical issues</li>
        <li>Prepare custom talking points based on prospect's industry/size</li>
      </ul>

      <h3>Common Demo Pitfalls to Avoid</h3>
      <ul>
        <li><strong>Don't</strong>: Get stuck in admin console configuration - keep it brief</li>
        <li><strong>Don't</strong>: Show every single feature - focus on what matters to this audience</li>
        <li><strong>Don't</strong>: Let technical issues derail the demo - have screenshots as backup</li>
        <li><strong>Don't</strong>: Talk while waiting for something to load - narrate what's happening</li>
        <li><strong>Don't</strong>: Forget to tie features back to business value</li>
        <li><strong>Do</strong>: Practice the demo 3-5 times before delivering</li>
        <li><strong>Do</strong>: Pause for questions after each major section</li>
        <li><strong>Do</strong>: Keep demo moving - 80% showing, 20% talking</li>
      </ul>
    `,
    summary: 'Ready-to-use demo scripts for 15-min executive and 45-min technical demos, plus persona-based demos for IT admin, security, end user, and help desk audiences.',
    category: 'demo',
    tags: ['demo', 'scripts', 'presentation', 'executive', 'technical', 'personas', 'best practices'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-poc-success-kit',
    title: 'POC Success Kit for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This comprehensive POC Success Kit provides everything you need to plan, execute, and convert a successful Okta Device Access proof of concept. Follow these templates and frameworks to ensure POC success and smooth conversion to production.</p>

      <h2>POC Scope Definition Template</h2>

      <h3>Objectives</h3>
      <p>Clear, measurable objectives are critical for POC success. Define 3-5 specific objectives:</p>
      <ul>
        <li><strong>Technical Validation</strong>: Verify Okta Device Access works in your environment with your identity sources, MDM, and device fleet</li>
        <li><strong>User Experience</strong>: Validate that end users can successfully authenticate and the experience meets requirements</li>
        <li><strong>Security Requirements</strong>: Confirm MFA enforcement, audit logging, and security controls meet compliance standards</li>
        <li><strong>Integration Validation</strong>: Test integration with existing systems (AD, Azure AD, Jamf, Intune, etc.)</li>
        <li><strong>Operational Readiness</strong>: Ensure IT team can deploy, manage, and support the solution</li>
      </ul>

      <h3>Success Criteria</h3>
      <p>Define specific, measurable success criteria for each objective:</p>
      <ul>
        <li><strong>Technical</strong>: 95%+ successful authentication rate across Windows and macOS devices</li>
        <li><strong>User Experience</strong>: 80%+ user satisfaction score on post-POC survey</li>
        <li><strong>Security</strong>: 100% MFA enforcement for desktop authentication, complete audit trail in System Log</li>
        <li><strong>Integration</strong>: Successful bidirectional password sync with Active Directory, MDM profile deployment success rate >90%</li>
        <li><strong>Support</strong>: IT team can troubleshoot and resolve 90% of issues without vendor escalation</li>
      </ul>

      <h3>Timeline Template</h3>
      <ul>
        <li><strong>Week 1</strong>: Environment setup, configuration, admin training</li>
        <li><strong>Week 2</strong>: Pilot group enrollment (5-10 users), initial testing</li>
        <li><strong>Week 3</strong>: Expand to 25-50 users, collect feedback, iterate</li>
        <li><strong>Week 4</strong>: Scale testing, edge case validation, final assessment</li>
        <li><strong>Week 5</strong>: Executive readout, production planning, contract discussion</li>
      </ul>

      <h3>Participants and Roles</h3>
      <ul>
        <li><strong>Executive Sponsor</strong>: Signs off on POC success, approves production rollout (CIO, CISO, VP IT)</li>
        <li><strong>Technical Lead</strong>: Owns configuration and integration (Sr. Systems Engineer, Identity Architect)</li>
        <li><strong>Security Lead</strong>: Validates security controls and compliance (Security Engineer, Compliance Manager)</li>
        <li><strong>End User Representatives</strong>: Pilot users from different departments and roles (5-10 users)</li>
        <li><strong>Help Desk Lead</strong>: Evaluates supportability and training needs (Help Desk Manager)</li>
        <li><strong>Okta SE</strong>: Provides technical guidance, best practices, escalation path</li>
      </ul>

      <h2>User Group Selection Guide</h2>

      <h3>Pilot Size Recommendations</h3>
      <ul>
        <li><strong>Week 1-2</strong>: 5-10 early adopters (technical users, friendly stakeholders)</li>
        <li><strong>Week 3</strong>: 25-50 broader representation</li>
        <li><strong>Week 4</strong>: 50-100 diverse user scenarios</li>
      </ul>

      <h3>Diversity Requirements</h3>
      <p>Ensure pilot group includes:</p>
      <ul>
        <li><strong>Device types</strong>: Windows 10, Windows 11, macOS 13+, macOS 14+ (if applicable)</li>
        <li><strong>User roles</strong>: Developers, sales, executives, remote workers, on-site workers</li>
        <li><strong>Departments</strong>: IT, sales, marketing, engineering, finance</li>
        <li><strong>Locations</strong>: Office-based, remote, international (if applicable)</li>
        <li><strong>Technical proficiency</strong>: Power users, average users, less technical users</li>
        <li><strong>Edge cases</strong>: Users with multiple devices, shared workstations, compliance requirements</li>
      </ul>

      <h3>Technical Readiness Criteria</h3>
      <p>Pilot users should meet these requirements:</p>
      <ul>
        <li>Device running supported OS version (Windows 10 1903+, macOS 13+)</li>
        <li>Already enrolled in MDM (Intune, Jamf, Workspace ONE)</li>
        <li>Active Okta account with MFA factor enrolled</li>
        <li>Mobile device with Okta Verify installed (for push notifications)</li>
        <li>Willingness to provide feedback and tolerate occasional issues</li>
      </ul>

      <h2>Week-by-Week POC Execution Plan</h2>

      <h3>Week 1: Foundation (Days 1-7)</h3>
      <h4>Day 1-2: Environment Setup</h4>
      <ul>
        <li>Configure Okta Device Access in Okta tenant</li>
        <li>Set up Desktop MFA authentication policy</li>
        <li>Configure password sync settings</li>
        <li>Integrate with identity source (AD, Azure AD)</li>
        <li>Create test MDM profiles (Intune config, Jamf policy)</li>
      </ul>

      <h4>Day 3-4: Admin Training</h4>
      <ul>
        <li>Train IT team on Okta Device Access architecture</li>
        <li>Walk through configuration and policy settings</li>
        <li>Cover user enrollment and troubleshooting</li>
        <li>Review System Log and reporting</li>
        <li>Establish escalation path to Okta SE</li>
      </ul>

      <h4>Day 5-7: Internal Testing</h4>
      <ul>
        <li>IT team tests on their own devices</li>
        <li>Validate Windows Desktop MFA flow</li>
        <li>Validate macOS Desktop MFA flow</li>
        <li>Test password sync from Okta to device</li>
        <li>Test FastPass enrollment (if in scope)</li>
        <li>Document any issues or questions</li>
      </ul>

      <h3>Week 2: Pilot Group Launch (Days 8-14)</h3>
      <h4>Day 8: Pilot Communications</h4>
      <ul>
        <li>Send pilot announcement email (use template below)</li>
        <li>Schedule pilot kickoff meeting with 5-10 initial users</li>
        <li>Share quick start guide and FAQs</li>
      </ul>

      <h4>Day 9-10: Pilot Enrollment</h4>
      <ul>
        <li>Deploy MDM profiles to pilot user devices</li>
        <li>Assign users to Okta Device Access group</li>
        <li>Monitor device registration in Okta Verify admin console</li>
        <li>Provide hands-on support for first logins</li>
      </ul>

      <h4>Day 11-14: Initial Feedback</h4>
      <ul>
        <li>Daily check-ins with pilot users</li>
        <li>Monitor System Log for authentication events and errors</li>
        <li>Document issues and resolutions in shared tracker</li>
        <li>Iterate on configuration based on feedback</li>
        <li>Send mid-week survey to pilot users</li>
      </ul>

      <h3>Week 3: Expansion (Days 15-21)</h3>
      <h4>Day 15: Expand Pilot Group</h4>
      <ul>
        <li>Add 20-40 additional users to pilot</li>
        <li>Ensure diversity in roles, departments, locations</li>
        <li>Deploy MDM profiles and group assignments</li>
      </ul>

      <h4>Day 16-18: Monitor and Support</h4>
      <ul>
        <li>Active monitoring of authentication success rates</li>
        <li>Help desk handles user questions (track ticket volume)</li>
        <li>Resolve any integration or policy issues</li>
        <li>Test FastPass passwordless enrollment with subset of users</li>
      </ul>

      <h4>Day 19-21: Edge Case Testing</h4>
      <ul>
        <li>Test offline scenarios (laptop disconnected from network)</li>
        <li>Test password change workflows (Okta → device, device → Okta)</li>
        <li>Test self-service password reset at login screen</li>
        <li>Validate MFA policy enforcement and exceptions</li>
        <li>Test device unenrollment and re-enrollment</li>
      </ul>

      <h3>Week 4: Scale Testing (Days 22-28)</h3>
      <h4>Day 22-24: Scale Validation</h4>
      <ul>
        <li>Expand to 50-100 users if environment allows</li>
        <li>Monitor authentication performance and latency</li>
        <li>Validate MDM deployment scalability</li>
        <li>Test help desk support procedures</li>
      </ul>

      <h4>Day 25-26: Security and Compliance Review</h4>
      <ul>
        <li>Security team reviews audit logs and MFA enforcement</li>
        <li>Validate compliance requirements (SOC2, HIPAA, etc.)</li>
        <li>Test conditional access policy integration</li>
        <li>Review device posture signals (if applicable)</li>
      </ul>

      <h4>Day 27-28: Final Assessment</h4>
      <ul>
        <li>Send final survey to all pilot users</li>
        <li>Compile metrics against success criteria</li>
        <li>Document lessons learned and best practices</li>
        <li>Prepare executive readout presentation</li>
      </ul>

      <h3>Week 5: Readout and Planning (Days 29-35)</h3>
      <h4>Day 29-30: Executive Readout</h4>
      <ul>
        <li>Present POC results to executive sponsor and stakeholders</li>
        <li>Review objectives vs. outcomes</li>
        <li>Share user feedback and testimonials</li>
        <li>Recommend production rollout approach</li>
      </ul>

      <h4>Day 31-33: Production Planning</h4>
      <ul>
        <li>Define production rollout timeline (phased vs. big bang)</li>
        <li>Identify any remaining blockers or requirements</li>
        <li>Plan user communication and training strategy</li>
        <li>Establish production support model</li>
      </ul>

      <h4>Day 34-35: Commercial Discussion</h4>
      <ul>
        <li>Review licensing requirements for production</li>
        <li>Discuss contract terms and timeline</li>
        <li>Align on next steps and kickoff date</li>
      </ul>

      <h2>Stakeholder Communication Templates</h2>

      <h3>POC Announcement Email</h3>
      <pre>
Subject: You're invited to pilot Okta Device Access

Hi [Name],

You've been selected to participate in a pilot of Okta Device Access, a new solution that will modernize how we authenticate to our Windows and Mac devices.

<strong>What is it?</strong>
Okta Device Access adds multi-factor authentication to your device login and enables passwordless authentication using biometrics (fingerprint or face). It also allows self-service password reset right from the login screen.

<strong>Why are we doing this?</strong>
- Stronger security: MFA at device login prevents unauthorized access
- Better experience: Faster logins with biometrics, self-service password reset
- Fewer help desk tickets: Users can fix password issues themselves

<strong>What do you need to do?</strong>
1. Attend the kickoff meeting on [Date/Time] - [Calendar Invite Link]
2. Follow the setup instructions when prompted on your device
3. Provide feedback via short surveys during the pilot
4. Report any issues to [Help Desk Email/Slack Channel]

<strong>Timeline:</strong>
The pilot runs for 4 weeks starting [Start Date]. After successful validation, we'll roll out to the entire company.

<strong>Questions?</strong>
Contact [POC Lead Name] at [Email] or join #okta-pilot on Slack.

Thank you for being an early adopter!

[Your Name]
      </pre>

      <h3>Weekly Status Update Email</h3>
      <pre>
Subject: Okta Device Access POC - Week [X] Update

<strong>POC Status: [On Track / Needs Attention / At Risk]</strong>

<strong>This Week's Progress:</strong>
- [X] users enrolled (target: [Y])
- [X]% successful authentication rate (target: 95%)
- [X] support tickets resolved
- Key milestone: [Achievement]

<strong>User Feedback Highlights:</strong>
- Positive: [Quote or trend]
- Concern: [Quote or trend]
- Suggestion: [Quote or trend]

<strong>Blockers/Issues:</strong>
- [Issue description] - Status: [In Progress / Resolved / Escalated]
- [Issue description] - Status: [In Progress / Resolved / Escalated]

<strong>Next Week's Focus:</strong>
- [Goal 1]
- [Goal 2]
- [Goal 3]

<strong>Metrics Dashboard:</strong>
[Link to metrics dashboard or summary table]

Questions? Contact [POC Lead]
      </pre>

      <h3>Executive Readout Presentation Outline</h3>
      <ul>
        <li><strong>Slide 1</strong>: POC Overview (objectives, timeline, participants)</li>
        <li><strong>Slide 2</strong>: Success Criteria vs. Results (table format, green/yellow/red indicators)</li>
        <li><strong>Slide 3</strong>: User Feedback (satisfaction score, quotes, testimonials)</li>
        <li><strong>Slide 4</strong>: Technical Validation (authentication success rate, integration results)</li>
        <li><strong>Slide 5</strong>: Security Benefits (MFA enforcement, audit logging, compliance)</li>
        <li><strong>Slide 6</strong>: Business Impact (projected help desk savings, user productivity gains)</li>
        <li><strong>Slide 7</strong>: Lessons Learned (what worked, what to adjust for production)</li>
        <li><strong>Slide 8</strong>: Production Rollout Recommendation (phased approach, timeline, resources needed)</li>
        <li><strong>Slide 9</strong>: Next Steps (decision needed, timeline, contract discussion)</li>
      </ul>

      <h2>Technical Validation Checklist</h2>

      <h3>Windows Validation</h3>
      <ul>
        <li><input type="checkbox"> Desktop MFA enforced at Windows login (password + MFA)</li>
        <li><input type="checkbox"> MFA prompts appear correctly (push, TOTP, SMS)</li>
        <li><input type="checkbox"> Successful authentication unlocks device</li>
        <li><input type="checkbox"> Failed MFA blocks access</li>
        <li><input type="checkbox"> Password sync works (Okta → Windows, Windows → Okta)</li>
        <li><input type="checkbox"> Self-service password reset at login screen functional</li>
        <li><input type="checkbox"> FastPass enrollment flow works (if in scope)</li>
        <li><input type="checkbox"> FastPass Windows Hello authentication works (if in scope)</li>
        <li><input type="checkbox"> Offline authentication works (cached credentials)</li>
        <li><input type="checkbox"> Offline grace period enforced correctly</li>
        <li><input type="checkbox"> Authentication events logged in Okta System Log</li>
        <li><input type="checkbox"> Integration with Intune/SCCM/other MDM successful</li>
      </ul>

      <h3>macOS Validation</h3>
      <ul>
        <li><input type="checkbox"> Platform SSO MDM profile deploys successfully</li>
        <li><input type="checkbox"> Registration prompt appears at first login</li>
        <li><input type="checkbox"> Desktop MFA enforced at macOS login</li>
        <li><input type="checkbox"> Password sync works bidirectionally</li>
        <li><input type="checkbox"> Self-service password reset functional</li>
        <li><input type="checkbox"> FastPass enrollment works (automatic or manual)</li>
        <li><input type="checkbox"> FastPass Touch ID authentication works</li>
        <li><input type="checkbox"> Keychain integration works correctly</li>
        <li><input type="checkbox"> Offline authentication and grace period work</li>
        <li><input type="checkbox"> Authentication events logged in System Log</li>
        <li><input type="checkbox"> Integration with Jamf/other MDM successful</li>
      </ul>

      <h3>Integration Validation</h3>
      <ul>
        <li><input type="checkbox"> Active Directory integration working (if applicable)</li>
        <li><input type="checkbox"> Azure AD integration working (if applicable)</li>
        <li><input type="checkbox"> Password writeback to AD functional (if configured)</li>
        <li><input type="checkbox"> MDM profile deployment at scale validated</li>
        <li><input type="checkbox"> Group-based policy assignment working</li>
        <li><input type="checkbox"> SSO to applications post-login working</li>
        <li><input type="checkbox"> Device posture signals available (if applicable)</li>
      </ul>

      <h3>Security Validation</h3>
      <ul>
        <li><input type="checkbox"> MFA enforcement cannot be bypassed</li>
        <li><input type="checkbox"> Authentication policy correctly applied to users</li>
        <li><input type="checkbox"> Audit trail complete in System Log</li>
        <li><input type="checkbox"> Failed authentication attempts logged</li>
        <li><input type="checkbox"> Device registration tracked and reportable</li>
        <li><input type="checkbox"> Compliance requirements met (SOC2, HIPAA, etc.)</li>
      </ul>

      <h2>Status Reporting Templates</h2>

      <h3>POC Metrics Dashboard</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Metric</th>
          <th>Target</th>
          <th>Current</th>
          <th>Status</th>
        </tr>
        <tr>
          <td>Users Enrolled</td>
          <td>[Target Number]</td>
          <td>[Actual Number]</td>
          <td>[On Track/Behind/Ahead]</td>
        </tr>
        <tr>
          <td>Authentication Success Rate</td>
          <td>95%</td>
          <td>[Actual %]</td>
          <td>[Green/Yellow/Red]</td>
        </tr>
        <tr>
          <td>User Satisfaction Score</td>
          <td>80%</td>
          <td>[Actual %]</td>
          <td>[Green/Yellow/Red]</td>
        </tr>
        <tr>
          <td>Support Tickets</td>
          <td><10 per week</td>
          <td>[Actual Number]</td>
          <td>[Green/Yellow/Red]</td>
        </tr>
        <tr>
          <td>FastPass Enrollment Rate</td>
          <td>70%</td>
          <td>[Actual %]</td>
          <td>[Green/Yellow/Red]</td>
        </tr>
      </table>

      <h2>Issue Escalation Process</h2>

      <h3>Issue Severity Definitions</h3>
      <ul>
        <li><strong>P0 - Critical</strong>: Blocks POC progress, affects all users, no workaround
          <br>Example: Authentication completely broken, all users locked out
          <br>Response: Immediate Okta SE escalation, 1-hour response SLA</li>
        <li><strong>P1 - High</strong>: Impacts multiple users, workaround exists but difficult
          <br>Example: Password sync failing for 25% of users
          <br>Response: Same-day Okta SE engagement, 4-hour response SLA</li>
        <li><strong>P2 - Medium</strong>: Affects small number of users or specific scenario
          <br>Example: FastPass not enrolling on specific macOS version
          <br>Response: Next-business-day response, troubleshooting session</li>
        <li><strong>P3 - Low</strong>: Cosmetic issue, feature question, enhancement request
          <br>Example: UI text unclear, documentation request
          <br>Response: Logged for review, addressed in regular sync meetings</li>
      </ul>

      <h3>Escalation Path</h3>
      <ol>
        <li><strong>Level 1</strong>: Internal IT team troubleshooting (reference documentation, logs)</li>
        <li><strong>Level 2</strong>: Okta SE review (email or Slack with issue details and logs)</li>
        <li><strong>Level 3</strong>: Okta Support ticket (for product bugs or advanced troubleshooting)</li>
        <li><strong>Level 4</strong>: Okta Engineering escalation (for critical product issues)</li>
      </ol>

      <h3>Information to Provide for Escalation</h3>
      <ul>
        <li>Issue severity (P0/P1/P2/P3)</li>
        <li>Detailed description of issue (what's happening vs. what's expected)</li>
        <li>Number of users affected</li>
        <li>Device type and OS version</li>
        <li>Okta System Log event IDs and timestamps</li>
        <li>Screenshots or screen recordings if applicable</li>
        <li>Steps to reproduce the issue</li>
        <li>Workarounds attempted</li>
      </ul>

      <h2>Common POC Objections and Handlers</h2>

      <h3>Objection: "Our users won't like change"</h3>
      <p><strong>Handler</strong>: "That's a valid concern. That's why we're doing a pilot first with early adopters. In our experience, users actually love the change because it makes their lives easier - faster login with biometrics, self-service password reset instead of calling help desk. We'll collect user satisfaction data during the pilot to validate this with your specific users."</p>

      <h3>Objection: "What if it breaks and users can't log in?"</h3>
      <p><strong>Handler</strong>: "We have multiple safeguards. First, we start with a small pilot group, so impact is limited. Second, there's an offline authentication mode with cached credentials if network is unavailable. Third, admins can always unenroll a device remotely if needed. Fourth, the Okta credential provider runs alongside the default Windows/Mac credential provider, so there's a fallback. We'll test all failure scenarios during the POC."</p>

      <h3>Objection: "We don't have time for a POC right now"</h3>
      <p><strong>Handler</strong>: "I understand. The POC is designed to be lightweight - mostly automated deployment via your existing MDM, and the pilot users are doing their normal work while testing. IT involvement is about 5-10 hours per week. We can also adjust the timeline - some customers do a 2-week focused POC, others spread it over 6 weeks. What timeline would work better for your team?"</p>

      <h3>Objection: "Our MDM integration isn't ready"</h3>
      <p><strong>Handler</strong>: "No problem. For the POC, we can manually configure a few test devices without MDM to validate the functionality. We'll use the POC period to finalize the MDM integration in parallel. By the time we're ready for production rollout, MDM will be ready. We can also provide documentation and best practices from other customers using [your MDM platform]."</p>

      <h3>Objection: "We're not sure we can justify the cost"</h3>
      <p><strong>Handler</strong>: "That's exactly what the POC will help quantify. We'll measure the help desk ticket reduction during the pilot and extrapolate the annual savings for your full user base. Most customers see 60-75% reduction in password reset tickets, which at $40 per ticket adds up quickly. For a 1000-person company, that's $120K in annual savings. We'll also measure security benefits and user productivity gains. After the POC, you'll have hard data for the business case."</p>

      <h3>Objection: "What happens after the POC if we don't move forward?"</h3>
      <p><strong>Handler</strong>: "You're in control. If you decide not to proceed, we simply unenroll the pilot users' devices and remove the MDM profiles. Their devices return to standard authentication. There's no long-term commitment or data lock-in. The POC is a true evaluation period to make sure this is the right solution for you."</p>

      <h2>Converting POC to Production Guide</h2>

      <h3>POC Success Indicators</h3>
      <p>You're ready to convert to production when:</p>
      <ul>
        <li>Authentication success rate consistently >95%</li>
        <li>User satisfaction score >80%</li>
        <li>All success criteria met or exceeded</li>
        <li>Security team approves audit and compliance controls</li>
        <li>IT team confident in deployment and support procedures</li>
        <li>Executive sponsor approves production rollout</li>
        <li>No P0 or P1 blockers remaining</li>
      </ul>

      <h3>Production Readiness Checklist</h3>
      <ul>
        <li><input type="checkbox"> Production Okta tenant configured (if different from POC)</li>
        <li><input type="checkbox"> MDM profiles finalized for production distribution</li>
        <li><input type="checkbox"> Authentication policies configured for production groups</li>
        <li><input type="checkbox"> Password sync configured for production directories</li>
        <li><input type="checkbox"> Help desk trained on support procedures</li>
        <li><input type="checkbox"> User communication plan finalized</li>
        <li><input type="checkbox"> Rollout timeline and phases defined</li>
        <li><input type="checkbox"> Rollback procedures documented and tested</li>
        <li><input type="checkbox"> Success metrics and reporting dashboard configured</li>
        <li><input type="checkbox"> Licensing and contracts finalized</li>
      </ul>

      <h3>Transition Planning</h3>
      <ul>
        <li><strong>Week 1</strong>: Finalize production configuration, train help desk</li>
        <li><strong>Week 2</strong>: Pilot group transitions to production (if using separate tenant)</li>
        <li><strong>Week 3-4</strong>: First production wave (100-200 users)</li>
        <li><strong>Week 5-8</strong>: Subsequent waves based on phased rollout plan</li>
        <li><strong>Week 9+</strong>: Continue rollout, monitor metrics, iterate</li>
      </ul>

      <h3>Contract Discussion Points</h3>
      <ul>
        <li>Number of licensed users (current + growth projection)</li>
        <li>Contract term (annual vs. multi-year)</li>
        <li>Support tier (standard vs. premium)</li>
        <li>Professional services needs (deployment assistance, custom integration)</li>
        <li>Training requirements (admin training, end user materials)</li>
        <li>Success metrics and business case alignment</li>
      </ul>

      <h2>POC Success Stories</h2>

      <h3>Financial Services Company (5,000 users)</h3>
      <p><strong>Challenge</strong>: High help desk costs from password resets, compliance requirements for MFA</p>
      <p><strong>POC Approach</strong>: 4-week pilot with 50 users across different roles</p>
      <p><strong>Results</strong>: 70% reduction in password reset tickets, 92% user satisfaction, full production rollout 6 weeks after POC</p>
      <p><strong>ROI</strong>: $180K annual savings in help desk costs, compliance achieved for SOC2 and FINRA</p>

      <h3>Healthcare Provider (2,000 users)</h3>
      <p><strong>Challenge</strong>: HIPAA compliance, shared workstation security, user experience</p>
      <p><strong>POC Approach</strong>: 3-week focused pilot with clinical and administrative users</p>
      <p><strong>Results</strong>: 95% authentication success rate, FastPass adoption by 80% of users, security audit passed</p>
      <p><strong>ROI</strong>: HIPAA compliance achieved, 5-minute average time savings per day per user, improved security posture</p>

      <h3>Technology Company (10,000 users)</h3>
      <p><strong>Challenge</strong>: Developer productivity, security for remote workforce, phishing prevention</p>
      <p><strong>POC Approach</strong>: 5-week pilot with developers, remote workers, and executives</p>
      <p><strong>Results</strong>: 88% user satisfaction, FastPass passwordless adoption by 85%, zero phishing incidents during POC</p>
      <p><strong>ROI</strong>: Full production rollout in 10 weeks, $250K annual savings, measurable productivity gains</p>
    `,
    summary: 'Complete POC success kit including scope definition, user selection, week-by-week execution plan, stakeholder templates, validation checklists, escalation processes, objection handlers, and production conversion guide.',
    category: 'poc',
    tags: ['poc', 'pilot', 'planning', 'execution', 'stakeholders', 'validation', 'conversion', 'templates'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-maturity-model',
    title: 'Okta Device Access Adoption Maturity Model',
    content: `
      <h2>Overview</h2>
      <p>This maturity model helps organizations understand their current state and chart a path to advanced Okta Device Access adoption. Use this framework to assess readiness, identify gaps, and plan your journey from basic desktop authentication to advanced Zero Trust capabilities.</p>

      <h2>Maturity Level Overview</h2>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Level</th>
          <th>Name</th>
          <th>Description</th>
          <th>Typical Timeline</th>
        </tr>
        <tr>
          <td>Level 0</td>
          <td>Pre-Okta Device Access</td>
          <td>Traditional device authentication, no Okta integration</td>
          <td>Current State</td>
        </tr>
        <tr>
          <td>Level 1</td>
          <td>Basic Desktop MFA</td>
          <td>MFA enforced at device login</td>
          <td>2-4 weeks</td>
        </tr>
        <tr>
          <td>Level 2</td>
          <td>Password Sync + FastPass</td>
          <td>Unified password, passwordless enabled</td>
          <td>4-8 weeks</td>
        </tr>
        <tr>
          <td>Level 3</td>
          <td>Full Passwordless</td>
          <td>FIDO2 credentials, biometric authentication</td>
          <td>8-12 weeks</td>
        </tr>
        <tr>
          <td>Level 4</td>
          <td>Device Trust + Conditional Access</td>
          <td>Zero Trust integration, policy sophistication</td>
          <td>12-16 weeks</td>
        </tr>
        <tr>
          <td>Level 5</td>
          <td>Advanced Automation</td>
          <td>Workflow integration, JIT provisioning</td>
          <td>16+ weeks</td>
        </tr>
      </table>

      <h2>Level 0: Pre-Okta Device Access</h2>

      <h3>Current State Description</h3>
      <ul>
        <li>Users authenticate to devices with local accounts or AD credentials</li>
        <li>No MFA at device login (only at application level)</li>
        <li>Password management is manual and fragmented</li>
        <li>High volume of password reset help desk tickets</li>
        <li>Device authentication separate from application authentication</li>
        <li>Limited audit trail for device access</li>
        <li>Weak protection against device-level attacks</li>
      </ul>

      <h3>Pain Points</h3>
      <ul>
        <li><strong>Security Gaps</strong>: Stolen device password = full device access</li>
        <li><strong>High Support Costs</strong>: 25% of users reset password monthly, $40 per ticket</li>
        <li><strong>Poor User Experience</strong>: Multiple passwords to remember, frequent lockouts</li>
        <li><strong>Compliance Challenges</strong>: Difficult to audit who accessed which device when</li>
        <li><strong>Operational Complexity</strong>: Managing passwords across multiple systems</li>
      </ul>

      <h3>Readiness Indicators</h3>
      <p>You're ready to move to Level 1 when:</p>
      <ul>
        <li>Okta deployed for SSO and application MFA (foundation in place)</li>
        <li>MDM solution deployed (Intune, Jamf, Workspace ONE)</li>
        <li>Users have Okta Verify enrolled on mobile devices</li>
        <li>Stakeholder buy-in for desktop authentication modernization</li>
        <li>IT resources available for 2-4 week deployment project</li>
      </ul>

      <h3>Typical Organizations</h3>
      <ul>
        <li>Early in digital transformation journey</li>
        <li>Recently adopted Okta for SSO and application access</li>
        <li>High help desk ticket volume driving cost concerns</li>
        <li>Security team pushing for MFA everywhere</li>
      </ul>

      <h2>Level 1: Basic Desktop MFA</h2>

      <h3>What It Includes</h3>
      <ul>
        <li>Desktop MFA enforced at Windows and/or macOS login</li>
        <li>Users enter password + MFA factor (push, TOTP, SMS)</li>
        <li>Authentication events logged in Okta System Log</li>
        <li>Okta Verify deployed and configured on end-user devices</li>
        <li>Basic authentication policy (require MFA for all users)</li>
        <li>Integration with existing identity source (AD, Azure AD)</li>
      </ul>

      <h3>Technical Requirements</h3>
      <ul>
        <li>Okta Workforce Identity (WIC) or Enterprise licenses</li>
        <li>Okta Verify installed on user devices</li>
        <li>MDM for profile/agent deployment (or manual installation)</li>
        <li>Supported OS: Windows 10/11 1903+, macOS 13+</li>
        <li>Network connectivity to Okta tenant (cloud or via proxy)</li>
        <li>Users have MFA factors enrolled (mobile device with Okta Verify)</li>
      </ul>

      <h3>Implementation Approach</h3>
      <ul>
        <li><strong>Week 1</strong>: Configure Okta Device Access, create authentication policy</li>
        <li><strong>Week 2</strong>: Pilot with 10-20 IT users, validate flows</li>
        <li><strong>Week 3</strong>: Expand to 100-200 early adopters across departments</li>
        <li><strong>Week 4</strong>: Broad rollout in waves, monitor and support</li>
      </ul>

      <h3>Success Metrics</h3>
      <ul>
        <li>95%+ authentication success rate</li>
        <li>MFA enforcement across all device logins</li>
        <li>Complete audit trail in System Log</li>
        <li>Security team satisfied with compliance controls</li>
        <li>Initial reduction in password reset tickets (20-30%)</li>
      </ul>

      <h3>Business Value</h3>
      <ul>
        <li><strong>Security</strong>: Prevents unauthorized device access even with stolen password</li>
        <li><strong>Compliance</strong>: Audit trail for SOC2, HIPAA, PCI requirements</li>
        <li><strong>Cost Savings</strong>: 20-30% reduction in password reset tickets (early stage)</li>
        <li><strong>Foundation</strong>: Establishes platform for advanced capabilities</li>
      </ul>

      <h3>Typical Timeline</h3>
      <p>2-4 weeks from kickoff to broad deployment</p>

      <h2>Level 2: Password Sync + FastPass</h2>

      <h3>What It Includes (In Addition to Level 1)</h3>
      <ul>
        <li>Password sync between Okta and device (bidirectional)</li>
        <li>Self-service password reset at device login screen</li>
        <li>FastPass passwordless enrollment enabled</li>
        <li>Subset of users (20-40%) using FastPass biometric authentication</li>
        <li>AD writeback configured (if using Active Directory)</li>
        <li>Enhanced authentication policies (conditional MFA based on context)</li>
      </ul>

      <h3>Incremental Value</h3>
      <ul>
        <li><strong>Unified Password</strong>: Change once, works everywhere (device + apps)</li>
        <li><strong>Self-Service</strong>: Users reset passwords without help desk involvement</li>
        <li><strong>Passwordless Option</strong>: Early adopters use biometrics instead of passwords</li>
        <li><strong>Major Cost Savings</strong>: 60-75% reduction in password reset tickets</li>
        <li><strong>Better User Experience</strong>: Faster, easier authentication for end users</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Level 1 deployed and stable (95%+ success rate)</li>
        <li>AD integration configured with Okta AD Agent (if applicable)</li>
        <li>Password policies aligned between Okta and AD/Azure AD</li>
        <li>User communication strategy for password sync and self-service</li>
        <li>Devices support biometric authentication (Windows Hello, Touch ID)</li>
      </ul>

      <h3>Implementation Approach</h3>
      <ul>
        <li><strong>Week 1</strong>: Configure password sync and AD writeback</li>
        <li><strong>Week 2</strong>: Pilot password sync with 50 users, validate bidirectional flow</li>
        <li><strong>Week 3</strong>: Enable self-service password reset, test at login screen</li>
        <li><strong>Week 4</strong>: Enable FastPass, pilot with 20-40% of users (tech-savvy early adopters)</li>
        <li><strong>Week 5-8</strong>: Expand password sync and FastPass to broader population</li>
      </ul>

      <h3>Success Metrics</h3>
      <ul>
        <li>Password sync working bidirectionally with <5 second latency</li>
        <li>60-75% reduction in password reset help desk tickets</li>
        <li>20-40% FastPass enrollment rate</li>
        <li>80%+ user satisfaction with self-service password reset</li>
        <li>Zero password drift incidents</li>
      </ul>

      <h3>Business Value</h3>
      <ul>
        <li><strong>Help Desk Savings</strong>: $80-150K annual savings for 1000-user org</li>
        <li><strong>User Productivity</strong>: 5-10 minutes saved per password reset (self-service vs. ticket)</li>
        <li><strong>Security</strong>: Stronger password policies enforced, FastPass phishing-resistant</li>
        <li><strong>User Experience</strong>: Major UX improvement, user satisfaction increases</li>
      </ul>

      <h3>Typical Timeline</h3>
      <p>4-8 weeks from Level 1 to Level 2 maturity</p>

      <h2>Level 3: Full Passwordless with FIDO2</h2>

      <h3>What It Includes (In Addition to Level 2)</h3>
      <ul>
        <li>FastPass enrollment actively encouraged/required for all users</li>
        <li>70-90% of users using passwordless authentication (biometrics)</li>
        <li>FIDO2 WebAuthn credentials for phishing-resistant authentication</li>
        <li>Passwordless onboarding for new hires</li>
        <li>Recovery procedures for lost/broken devices</li>
        <li>Help desk trained on FastPass support and troubleshooting</li>
      </ul>

      <h3>Advanced Capabilities</h3>
      <ul>
        <li><strong>True Passwordless</strong>: No passwords in authentication flow</li>
        <li><strong>Biometric Authentication</strong>: Fingerprint or face recognition on all devices</li>
        <li><strong>Phishing-Proof</strong>: FIDO2 credentials cannot be phished or stolen</li>
        <li><strong>Faster Logins</strong>: 3-5 second biometric authentication vs. 15-20 second password + MFA</li>
        <li><strong>Zero Password Resets</strong>: No passwords to forget or reset</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Level 2 deployed with high user satisfaction</li>
        <li>Devices support biometric hardware (Windows Hello cameras, Touch ID)</li>
        <li>User training and communication campaign for FastPass</li>
        <li>Executive sponsorship for passwordless initiative</li>
        <li>Help desk prepared for device recovery scenarios</li>
      </ul>

      <h3>Implementation Approach</h3>
      <ul>
        <li><strong>Month 1</strong>: Launch passwordless campaign, incent FastPass enrollment</li>
        <li><strong>Month 2</strong>: Target 50% enrollment, provide training and support</li>
        <li><strong>Month 3</strong>: Target 70-90% enrollment, require for new hires</li>
        <li><strong>Ongoing</strong>: Monitor adoption, support edge cases, maintain enrollment rates</li>
      </ul>

      <h3>Success Metrics</h3>
      <ul>
        <li>70-90% FastPass enrollment and active usage</li>
        <li>Average login time <5 seconds</li>
        <li>Password reset tickets reduced by 80-90% vs. Level 0 baseline</li>
        <li>90%+ user satisfaction with passwordless experience</li>
        <li>Zero successful phishing attacks targeting device authentication</li>
      </ul>

      <h3>User Experience Benefits</h3>
      <ul>
        <li>No passwords to remember or type</li>
        <li>Faster, smoother login experience</li>
        <li>Biometric authentication feels modern and secure</li>
        <li>Consistent experience across devices and applications</li>
        <li>Reduced authentication friction increases productivity</li>
      </ul>

      <h3>Security Benefits</h3>
      <ul>
        <li>FIDO2 credentials are cryptographic keys, not shared secrets</li>
        <li>Phishing attacks cannot steal biometric data or FIDO2 keys</li>
        <li>Device-bound credentials prevent credential replay attacks</li>
        <li>Stronger authentication with lower user friction</li>
      </ul>

      <h3>Typical Timeline</h3>
      <p>8-12 weeks from Level 2 to Level 3 maturity</p>

      <h2>Level 4: Device Trust + Conditional Access</h2>

      <h3>What It Includes (In Addition to Level 3)</h3>
      <ul>
        <li>Device posture signals feeding into conditional access policies</li>
        <li>Integration with Okta Device Trust (device registration and health checks)</li>
        <li>Context-aware authentication policies (location, risk, device state)</li>
        <li>Application access gated by device registration status</li>
        <li>MDM compliance checks integrated with authentication decisions</li>
        <li>Network access control based on device posture</li>
        <li>Zero Trust architecture principles implemented</li>
      </ul>

      <h3>Advanced Policy Examples</h3>
      <ul>
        <li><strong>Sensitive Apps</strong>: Require registered device + FastPass for financial systems</li>
        <li><strong>Location-Based</strong>: Require additional MFA when authenticating from unknown locations</li>
        <li><strong>Risk-Based</strong>: Step-up authentication for high-risk sign-ins (Okta ThreatInsight)</li>
        <li><strong>Compliance-Based</strong>: Block access if device fails MDM compliance check</li>
        <li><strong>Network Segmentation</strong>: Grant VPN/network access only to trusted devices</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Level 3 deployed with high FastPass adoption</li>
        <li>Okta Device Trust add-on licensed and configured</li>
        <li>MDM solution with compliance policies defined</li>
        <li>Security team defines Zero Trust policy requirements</li>
        <li>Network access controls support device posture integration</li>
      </ul>

      <h3>Implementation Approach</h3>
      <ul>
        <li><strong>Month 1</strong>: Define Zero Trust policies and device posture requirements</li>
        <li><strong>Month 2</strong>: Configure Okta Device Trust and conditional access policies</li>
        <li><strong>Month 3</strong>: Pilot policies with select applications and user groups</li>
        <li><strong>Month 4</strong>: Expand policies to all applications and enforce compliance</li>
      </ul>

      <h3>Success Metrics</h3>
      <ul>
        <li>100% of devices registered and reporting posture</li>
        <li>Conditional access policies enforced for sensitive applications</li>
        <li>Zero unauthorized access from unregistered/non-compliant devices</li>
        <li>Measurable reduction in security incidents</li>
        <li>Compliance audit findings reduced or eliminated</li>
      </ul>

      <h3>Security Benefits</h3>
      <ul>
        <li><strong>Zero Trust Foundation</strong>: Never trust, always verify - device posture checked continuously</li>
        <li><strong>Risk-Based Authentication</strong>: Higher security for sensitive resources, lower friction for routine access</li>
        <li><strong>Compliance Enforcement</strong>: Automatic blocking of non-compliant devices</li>
        <li><strong>Threat Prevention</strong>: Compromised devices blocked from accessing corporate resources</li>
        <li><strong>Visibility</strong>: Complete inventory of devices accessing corporate resources</li>
      </ul>

      <h3>Typical Timeline</h3>
      <p>12-16 weeks from Level 3 to Level 4 maturity</p>

      <h2>Level 5: Advanced Automation</h2>

      <h3>What It Includes (In Addition to Level 4)</h3>
      <ul>
        <li>Workflow automation for device lifecycle management</li>
        <li>Just-in-time (JIT) provisioning based on device authentication</li>
        <li>Automated device registration during onboarding</li>
        <li>Self-service device troubleshooting and recovery</li>
        <li>Advanced analytics and ML-driven insights</li>
        <li>API integration with ITSM, SIEM, and other systems</li>
        <li>Custom authentication flows and branding</li>
      </ul>

      <h3>Advanced Use Cases</h3>
      <ul>
        <li><strong>Automated Onboarding</strong>: New hire receives device, signs in with Okta, automatically enrolled in FastPass and provisioned to applications</li>
        <li><strong>JIT Provisioning</strong>: User authenticates to device, application access auto-provisioned based on role and department</li>
        <li><strong>Self-Service Recovery</strong>: User with broken device can self-service recover FastPass to new device via Okta dashboard</li>
        <li><strong>Predictive Support</strong>: ML models identify users likely to have authentication issues, proactive outreach from help desk</li>
        <li><strong>SIEM Integration</strong>: Device authentication events feed into SIEM for correlation with other security events</li>
        <li><strong>Automated Deprovisioning</strong>: Employee leaves, device automatically unenrolled and access revoked via workflow</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Level 4 deployed and stable</li>
        <li>Okta Workflows or other automation platform configured</li>
        <li>API integrations with ITSM, HR systems, SIEM</li>
        <li>Advanced analytics tools (Okta System Log analytics, custom dashboards)</li>
        <li>IT team with automation and scripting expertise</li>
      </ul>

      <h3>Implementation Approach</h3>
      <ul>
        <li><strong>Quarter 1</strong>: Identify high-value automation opportunities</li>
        <li><strong>Quarter 2</strong>: Build and pilot workflows for onboarding, provisioning, deprovisioning</li>
        <li><strong>Quarter 3</strong>: Expand automation to edge cases and advanced scenarios</li>
        <li><strong>Ongoing</strong>: Continuous optimization, ML model tuning, new use case development</li>
      </ul>

      <h3>Success Metrics</h3>
      <ul>
        <li>90%+ of device lifecycle tasks automated (enrollment, recovery, unenrollment)</li>
        <li>Time to provision new hire device access: <1 hour (down from days)</li>
        <li>Help desk ticket volume reduced by 80-90% vs. Level 0 baseline</li>
        <li>IT operations time spent on device management: <2 hours per week</li>
        <li>User satisfaction: 95%+ (frictionless, automated experience)</li>
      </ul>

      <h3>Business Value</h3>
      <ul>
        <li><strong>Operational Efficiency</strong>: Massive reduction in manual IT tasks</li>
        <li><strong>User Productivity</strong>: New hires productive day 1, zero authentication friction</li>
        <li><strong>Cost Savings</strong>: Help desk and IT operations costs reduced by 80-90%</li>
        <li><strong>Scalability</strong>: Can scale to 10x users with same IT team size</li>
        <li><strong>Innovation</strong>: IT team focuses on strategic projects, not reactive support</li>
      </ul>

      <h3>Typical Timeline</h3>
      <p>16+ weeks from Level 4 to Level 5 maturity (ongoing optimization)</p>

      <h2>Maturity Self-Assessment Questionnaire</h2>

      <h3>Current State Assessment</h3>
      <p>Answer these questions to determine your current maturity level:</p>

      <h4>Level 0 → 1 Questions</h4>
      <ul>
        <li>Do you have Okta deployed for SSO and application MFA? (Yes = ready for Level 1)</li>
        <li>Do users have Okta Verify enrolled on mobile devices? (Yes = ready for Level 1)</li>
        <li>Do you have MDM deployed (Intune, Jamf, etc.)? (Yes = accelerates Level 1)</li>
        <li>Is MFA enforced at device login today? (No = Level 0; Yes = at least Level 1)</li>
      </ul>

      <h4>Level 1 → 2 Questions</h4>
      <ul>
        <li>Is Desktop MFA deployed and stable (>95% success rate)? (Yes = ready for Level 2)</li>
        <li>Do users complain about password drift between device and apps? (Yes = strong case for Level 2)</li>
        <li>Is self-service password reset available at device login screen? (No = Level 1; Yes = Level 2)</li>
        <li>Is password sync configured between Okta and device? (No = Level 1; Yes = Level 2)</li>
      </ul>

      <h4>Level 2 → 3 Questions</h4>
      <ul>
        <li>Is FastPass enabled and available to users? (No = Level 2; Yes = at least Level 2)</li>
        <li>What percentage of users have FastPass enrolled? (<20% = Level 2; 70-90% = Level 3)</li>
        <li>Do most devices support biometric authentication? (No = blocker for Level 3)</li>
        <li>Is passwordless authentication the default/encouraged experience? (No = Level 2; Yes = Level 3)</li>
      </ul>

      <h4>Level 3 → 4 Questions</h4>
      <ul>
        <li>Are device posture signals used in conditional access policies? (No = Level 3; Yes = Level 4)</li>
        <li>Is Okta Device Trust configured and enforcing policies? (No = Level 3; Yes = Level 4)</li>
        <li>Do you gate application access based on device registration? (No = Level 3; Yes = Level 4)</li>
        <li>Have you implemented Zero Trust principles for device access? (No = Level 3; Yes = Level 4)</li>
      </ul>

      <h4>Level 4 → 5 Questions</h4>
      <ul>
        <li>Are device lifecycle tasks (enrollment, recovery, unenrollment) automated? (No = Level 4; Yes = Level 5)</li>
        <li>Do you use workflows or APIs to integrate with HR, ITSM, SIEM? (No = Level 4; Yes = Level 5)</li>
        <li>Is JIT provisioning configured based on device authentication? (No = Level 4; Yes = Level 5)</li>
        <li>Do you have advanced analytics and ML-driven insights? (No = Level 4; Yes = Level 5)</li>
      </ul>

      <h2>Gap Analysis Framework</h2>

      <h3>Current State → Desired State Gap Identification</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Capability</th>
          <th>Current State</th>
          <th>Desired State</th>
          <th>Gap</th>
          <th>Effort</th>
        </tr>
        <tr>
          <td>Desktop MFA</td>
          <td>[None/Partial/Full]</td>
          <td>[Target]</td>
          <td>[Description]</td>
          <td>[Low/Med/High]</td>
        </tr>
        <tr>
          <td>Password Sync</td>
          <td>[None/Partial/Full]</td>
          <td>[Target]</td>
          <td>[Description]</td>
          <td>[Low/Med/High]</td>
        </tr>
        <tr>
          <td>FastPass</td>
          <td>[% enrolled]</td>
          <td>[Target %]</td>
          <td>[Description]</td>
          <td>[Low/Med/High]</td>
        </tr>
        <tr>
          <td>Device Trust</td>
          <td>[None/Partial/Full]</td>
          <td>[Target]</td>
          <td>[Description]</td>
          <td>[Low/Med/High]</td>
        </tr>
        <tr>
          <td>Automation</td>
          <td>[None/Partial/Full]</td>
          <td>[Target]</td>
          <td>[Description]</td>
          <td>[Low/Med/High]</td>
        </tr>
      </table>

      <h3>Blockers and Prerequisites</h3>
      <p>Identify blockers preventing progression to next level:</p>
      <ul>
        <li><strong>Technical</strong>: Missing integrations, unsupported OS versions, network constraints</li>
        <li><strong>Organizational</strong>: Lack of executive sponsorship, resource constraints</li>
        <li><strong>User Readiness</strong>: Training needs, change management requirements</li>
        <li><strong>Vendor/Licensing</strong>: Add-on licenses needed, contract negotiations</li>
      </ul>

      <h2>Roadmap Templates for Advancing from Each Level</h2>

      <h3>Level 0 → Level 1 Roadmap (2-4 weeks)</h3>
      <ul>
        <li><strong>Week 1</strong>: Okta Device Access configuration, authentication policy setup, MDM profile creation</li>
        <li><strong>Week 2</strong>: Pilot with IT team (10-20 users), validate Windows and macOS flows</li>
        <li><strong>Week 3</strong>: Expand to 100-200 early adopters, collect feedback, iterate</li>
        <li><strong>Week 4</strong>: Broad rollout in waves, monitor success rate, provide support</li>
      </ul>

      <h3>Level 1 → Level 2 Roadmap (4-8 weeks)</h3>
      <ul>
        <li><strong>Week 1-2</strong>: Configure password sync, AD writeback, test bidirectional flow</li>
        <li><strong>Week 3-4</strong>: Enable self-service password reset, pilot with 50 users</li>
        <li><strong>Week 5-6</strong>: Enable FastPass, pilot with early adopters (20-40% target)</li>
        <li><strong>Week 7-8</strong>: Expand to broader population, monitor help desk ticket reduction</li>
      </ul>

      <h3>Level 2 → Level 3 Roadmap (8-12 weeks)</h3>
      <ul>
        <li><strong>Month 1</strong>: Launch passwordless campaign, user training, communication blitz</li>
        <li><strong>Month 2</strong>: Target 50% FastPass enrollment, provide hands-on support and training</li>
        <li><strong>Month 3</strong>: Target 70-90% enrollment, require for new hires, monitor satisfaction</li>
      </ul>

      <h3>Level 3 → Level 4 Roadmap (12-16 weeks)</h3>
      <ul>
        <li><strong>Month 1</strong>: Define Zero Trust policies, configure Okta Device Trust</li>
        <li><strong>Month 2</strong>: Build conditional access policies, integrate MDM compliance checks</li>
        <li><strong>Month 3</strong>: Pilot policies with select apps and users, validate enforcement</li>
        <li><strong>Month 4</strong>: Expand to all apps and users, full Zero Trust implementation</li>
      </ul>

      <h3>Level 4 → Level 5 Roadmap (16+ weeks, ongoing)</h3>
      <ul>
        <li><strong>Q1</strong>: Identify automation opportunities, build workflows for onboarding/offboarding</li>
        <li><strong>Q2</strong>: JIT provisioning, SIEM integration, API connections to ITSM and HR</li>
        <li><strong>Q3</strong>: Advanced analytics, ML models, self-service troubleshooting</li>
        <li><strong>Ongoing</strong>: Continuous optimization, new use cases, innovation</li>
      </ul>

      <h2>Using This Maturity Model in Sales Conversations</h2>

      <h3>Discovery Questions</h3>
      <ul>
        <li>"Where are you today in terms of device authentication? Local accounts, AD, MFA?"</li>
        <li>"What percentage of your help desk tickets are password-related?"</li>
        <li>"Do you have Okta deployed for application SSO? MDM for device management?"</li>
        <li>"What's your vision for device security over the next 12 months?"</li>
      </ul>

      <h3>Positioning the Journey</h3>
      <p>"Most of our customers follow a maturity journey. They start with Desktop MFA to close the security gap, add password sync to reduce help desk costs, expand to FastPass for passwordless, then integrate with Device Trust for Zero Trust architecture. Where do you see yourself on this journey, and what's the next logical step for your organization?"</p>

      <h3>Creating Urgency</h3>
      <p>"You're currently at Level 0, which means you're experiencing [pain points]. Our Level 1 customers see [benefits] within 2-4 weeks. The gap between where you are and where you could be is costing you [quantified cost] per year. When can we get started?"</p>
    `,
    summary: 'Comprehensive maturity model covering 6 levels from pre-adoption to advanced automation, with detailed descriptions, timelines, business value, self-assessment questionnaire, gap analysis framework, and roadmap templates.',
    category: 'architecture',
    tags: ['maturity model', 'adoption', 'roadmap', 'planning', 'assessment', 'gap analysis', 'progression'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-rollout-strategy',
    title: 'Phased Rollout Strategy for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This comprehensive guide provides proven strategies for rolling out Okta Device Access to your organization. Whether you choose a big bang approach, phased deployment, or pilot-first strategy, this playbook gives you templates, checklists, and best practices to ensure rollout success.</p>

      <h2>Rollout Approach Comparison</h2>

      <h3>Big Bang Rollout</h3>
      <p><strong>Description</strong>: Deploy to entire organization simultaneously, all users enabled at once</p>
      <p><strong>Best For</strong>:</p>
      <ul>
        <li>Small organizations (<500 users)</li>
        <li>Homogeneous environment (single OS, standard configurations)</li>
        <li>Strong IT team with capacity for high support volume</li>
        <li>Urgent security compliance deadline</li>
      </ul>
      <p><strong>Pros</strong>:</p>
      <ul>
        <li>Fastest time to full deployment (1-2 weeks)</li>
        <li>Immediate security and compliance benefits across organization</li>
        <li>Single communication campaign and training push</li>
        <li>Avoid prolonged change management period</li>
      </ul>
      <p><strong>Cons</strong>:</p>
      <ul>
        <li>High risk if issues arise - affects all users simultaneously</li>
        <li>Help desk overwhelmed with high ticket volume in short period</li>
        <li>Limited ability to iterate based on feedback</li>
        <li>Requires extensive upfront testing and preparation</li>
      </ul>
      <p><strong>Success Factors</strong>:</p>
      <ul>
        <li>Thorough POC completed with diverse user scenarios tested</li>
        <li>Help desk fully trained and staffed for high volume</li>
        <li>Executive sponsorship and organization-wide communication</li>
        <li>Rollback plan prepared and tested</li>
      </ul>

      <h3>Phased Rollout (Recommended)</h3>
      <p><strong>Description</strong>: Deploy in waves over 4-12 weeks, starting with small groups and expanding</p>
      <p><strong>Best For</strong>:</p>
      <ul>
        <li>Medium to large organizations (500+ users)</li>
        <li>Diverse environment (multiple OS versions, device types, locations)</li>
        <li>Organizations with lower risk tolerance</li>
        <li>Teams that want to iterate and optimize between waves</li>
      </ul>
      <p><strong>Pros</strong>:</p>
      <ul>
        <li>Controlled risk - issues affect limited users initially</li>
        <li>Ability to iterate and improve between waves</li>
        <li>Manageable help desk ticket volume</li>
        <li>Build internal champions and success stories</li>
        <li>Identify and resolve edge cases early</li>
      </ul>
      <p><strong>Cons</strong>:</p>
      <ul>
        <li>Longer time to full deployment (4-12 weeks)</li>
        <li>Multiple communication campaigns required</li>
        <li>Complexity of managing mixed authentication states</li>
        <li>Requires discipline to maintain wave schedule</li>
      </ul>
      <p><strong>Success Factors</strong>:</p>
      <ul>
        <li>Clear wave definitions and criteria</li>
        <li>Metrics-driven go/no-go decisions between waves</li>
        <li>Strong project management and coordination</li>
        <li>User feedback loop to improve each wave</li>
      </ul>

      <h3>Pilot-First Approach</h3>
      <p><strong>Description</strong>: Extended pilot (2-4 weeks) with 50-200 users before broader rollout</p>
      <p><strong>Best For</strong>:</p>
      <ul>
        <li>Organizations new to Okta Device Access</li>
        <li>Complex environments with many unknowns</li>
        <li>Risk-averse organizations requiring extensive validation</li>
        <li>Building business case for broader investment</li>
      </ul>
      <p><strong>Pros</strong>:</p>
      <ul>
        <li>Lowest risk - validate in production before broad deployment</li>
        <li>Build executive confidence with real user success</li>
        <li>Identify and resolve issues with minimal impact</li>
        <li>Develop internal expertise and champions</li>
        <li>Quantify benefits for business case</li>
      </ul>
      <p><strong>Cons</strong>:</p>
      <ul>
        <li>Longest time to full deployment (8-16 weeks)</li>
        <li>Pilot users may experience inconsistencies</li>
        <li>Momentum can slow between pilot and production</li>
        <li>Two separate communication and training efforts</li>
      </ul>
      <p><strong>Success Factors</strong>:</p>
      <ul>
        <li>Clear pilot success criteria defined upfront</li>
        <li>Diverse pilot group representing edge cases</li>
        <li>Executive readout and production approval process</li>
        <li>Transition plan from pilot to production</li>
      </ul>

      <h3>Recommendation Matrix</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Organization Size</th>
          <th>Environment Complexity</th>
          <th>Risk Tolerance</th>
          <th>Recommended Approach</th>
        </tr>
        <tr>
          <td><500 users</td>
          <td>Low (homogeneous)</td>
          <td>High</td>
          <td>Big Bang</td>
        </tr>
        <tr>
          <td>500-2000 users</td>
          <td>Medium</td>
          <td>Medium</td>
          <td>Phased (4-6 weeks)</td>
        </tr>
        <tr>
          <td>2000-10000 users</td>
          <td>Medium-High</td>
          <td>Medium-Low</td>
          <td>Phased (6-12 weeks)</td>
        </tr>
        <tr>
          <td>10000+ users</td>
          <td>High (diverse)</td>
          <td>Low</td>
          <td>Pilot-First → Phased</td>
        </tr>
        <tr>
          <td>Any size</td>
          <td>High (complex)</td>
          <td>Very Low</td>
          <td>Pilot-First</td>
        </tr>
      </table>

      <h2>Pilot Phase Guide</h2>

      <h3>Pilot Criteria</h3>
      <p><strong>Who to Include</strong>:</p>
      <ul>
        <li><strong>IT Team</strong>: 10-20 IT staff (admins, help desk, security) - they'll support production rollout</li>
        <li><strong>Friendly Departments</strong>: 30-50 users from supportive teams (sales, marketing, HR)</li>
        <li><strong>Executive Sponsors</strong>: 5-10 executives and VPs - builds top-down support</li>
        <li><strong>Edge Case Representatives</strong>: 10-20 users with specific scenarios (remote workers, developers, shared devices)</li>
        <li><strong>Total</strong>: 50-100 pilot users (1-5% of total user base)</li>
      </ul>

      <h3>Pilot Size Guidelines</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Total Organization Size</th>
          <th>Pilot Size</th>
          <th>Pilot Percentage</th>
        </tr>
        <tr>
          <td>500 users</td>
          <td>25-50 users</td>
          <td>5-10%</td>
        </tr>
        <tr>
          <td>1,000 users</td>
          <td>50-100 users</td>
          <td>5-10%</td>
        </tr>
        <tr>
          <td>5,000 users</td>
          <td>100-200 users</td>
          <td>2-4%</td>
        </tr>
        <tr>
          <td>10,000+ users</td>
          <td>200-500 users</td>
          <td>2-5%</td>
        </tr>
      </table>

      <h3>Pilot Duration</h3>
      <ul>
        <li><strong>Week 1</strong>: Enrollment and initial testing (IT team validates functionality)</li>
        <li><strong>Week 2</strong>: Broader pilot user enrollment, daily monitoring and support</li>
        <li><strong>Week 3</strong>: Edge case testing, feedback collection, issue resolution</li>
        <li><strong>Week 4</strong>: Final assessment, metrics analysis, production planning</li>
      </ul>

      <h3>Pilot Success Metrics</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Metric</th>
          <th>Target</th>
          <th>Go/No-Go Threshold</th>
        </tr>
        <tr>
          <td>Authentication Success Rate</td>
          <td>98%</td>
          <td>95% minimum to proceed</td>
        </tr>
        <tr>
          <td>User Satisfaction Score</td>
          <td>85%</td>
          <td>75% minimum to proceed</td>
        </tr>
        <tr>
          <td>Support Tickets per User</td>
          <td><0.2 per week</td>
          <td><0.5 per week to proceed</td>
        </tr>
        <tr>
          <td>FastPass Enrollment Rate</td>
          <td>60%</td>
          <td>40% minimum to proceed</td>
        </tr>
        <tr>
          <td>Critical Issues (P0/P1)</td>
          <td>0</td>
          <td>0 to proceed</td>
        </tr>
      </table>

      <h3>Pilot Communication Templates</h3>

      <h4>Pilot Announcement Email</h4>
      <pre>
Subject: You're invited to pilot Okta Device Access

Hi [Name],

Great news! You've been selected to be among the first to experience Okta Device Access, a new solution that modernizes how we authenticate to our devices.

<strong>What is Okta Device Access?</strong>
- Multi-factor authentication at device login for stronger security
- Passwordless authentication using biometrics (fingerprint or face)
- Self-service password reset right from the login screen
- Unified password across your device and applications

<strong>Why are we piloting this?</strong>
We're starting with a small group to ensure a smooth experience before rolling out company-wide. Your feedback will help us optimize the deployment for everyone.

<strong>What happens next?</strong>
1. <strong>Kickoff Meeting</strong>: [Date/Time] - [Calendar Link]
   We'll walk through what to expect and answer questions

2. <strong>Setup (Week of [Date])</strong>:
   You'll receive a prompt on your device to register with Okta
   Follow the on-screen instructions (takes 5 minutes)

3. <strong>Feedback</strong>:
   Short survey in Week 2 and Week 4
   Report any issues to #okta-pilot-support on Slack

<strong>Need help?</strong>
- Quick Start Guide: [Link]
- FAQ: [Link]
- Support: #okta-pilot-support or helpdesk@company.com

Thank you for being an early adopter and helping us improve security and user experience!

[Your Name]
[Title]
      </pre>

      <h3>Pilot Follow-Up Survey (Week 2)</h3>
      <pre>
<strong>Okta Device Access Pilot - Week 2 Feedback</strong>

Thank you for participating in the Okta Device Access pilot! Your feedback helps us improve before company-wide rollout.

<strong>1. How satisfied are you with Okta Device Access so far?</strong>
○ Very satisfied
○ Satisfied
○ Neutral
○ Dissatisfied
○ Very dissatisfied

<strong>2. How easy was the initial setup and enrollment?</strong>
○ Very easy
○ Easy
○ Neutral
○ Difficult
○ Very difficult

<strong>3. How does the new login experience compare to the old one?</strong>
○ Much better
○ Somewhat better
○ About the same
○ Somewhat worse
○ Much worse

<strong>4. Have you enrolled in FastPass (passwordless with biometrics)?</strong>
○ Yes, and I use it regularly
○ Yes, but I still use password + MFA
○ No, I haven't enrolled yet
○ No, I don't plan to enroll

<strong>5. If you encountered any issues, were they resolved quickly?</strong>
○ Yes, resolved immediately
○ Yes, resolved within a day
○ Partially resolved
○ Not yet resolved
○ I didn't encounter any issues

<strong>6. What do you like most about Okta Device Access?</strong>
[Open text]

<strong>7. What needs improvement?</strong>
[Open text]

<strong>8. Any other feedback or suggestions?</strong>
[Open text]
      </pre>

      <h2>Wave-Based Deployment Approach</h2>

      <h3>Wave Sizing Principles</h3>
      <ul>
        <li><strong>Wave 1 (Pilot)</strong>: 1-5% of users - IT, early adopters, friendly departments</li>
        <li><strong>Wave 2</strong>: 10-15% of users - Expand to additional departments, validate scale</li>
        <li><strong>Wave 3</strong>: 25-35% of users - Major expansion, test help desk capacity</li>
        <li><strong>Wave 4+</strong>: Remaining users - Final waves, edge cases and stragglers</li>
      </ul>

      <h3>Example Wave Plan (5,000 User Organization)</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Wave</th>
          <th>Users</th>
          <th>Departments/Groups</th>
          <th>Timeline</th>
          <th>Focus</th>
        </tr>
        <tr>
          <td>Pilot</td>
          <td>100</td>
          <td>IT, Security, Executive Team</td>
          <td>Week 1-2</td>
          <td>Validation, champions</td>
        </tr>
        <tr>
          <td>Wave 1</td>
          <td>500</td>
          <td>Sales, Marketing, HR</td>
          <td>Week 3-4</td>
          <td>Scale testing</td>
        </tr>
        <tr>
          <td>Wave 2</td>
          <td>1,500</td>
          <td>Engineering, Product, Customer Success</td>
          <td>Week 5-7</td>
          <td>Technical users, edge cases</td>
        </tr>
        <tr>
          <td>Wave 3</td>
          <td>2,000</td>
          <td>Finance, Legal, Operations</td>
          <td>Week 8-10</td>
          <td>Sensitive data teams</td>
        </tr>
        <tr>
          <td>Wave 4</td>
          <td>900</td>
          <td>Remaining users, remote offices</td>
          <td>Week 11-12</td>
          <td>Final deployment</td>
        </tr>
      </table>

      <h3>Wave Sequencing Strategy</h3>
      <p><strong>Early Waves - Low-Risk, High-Value Groups</strong>:</p>
      <ul>
        <li>Tech-savvy departments (IT, Engineering)</li>
        <li>Friendly stakeholders and executive sponsors</li>
        <li>Geographically concentrated teams (easier support)</li>
        <li>Groups that generate champions and success stories</li>
      </ul>

      <p><strong>Middle Waves - Majority of Organization</strong>:</p>
      <ul>
        <li>General user population (Sales, Marketing, Operations)</li>
        <li>Remote and distributed teams</li>
        <li>Departments with moderate technical readiness</li>
      </ul>

      <p><strong>Late Waves - Special Cases</strong>:</p>
      <ul>
        <li>Highly sensitive/regulated teams (Finance, Legal)</li>
        <li>Shared workstations or kiosks (special configuration)</li>
        <li>International offices with different compliance needs</li>
        <li>Contractors, vendors, non-standard configurations</li>
      </ul>

      <h3>Timing Between Waves</h3>
      <ul>
        <li><strong>1-2 weeks between waves</strong>: Allows time to monitor metrics, resolve issues, collect feedback</li>
        <li><strong>Go/No-Go checkpoints</strong>: Review metrics and decide whether to proceed to next wave</li>
        <li><strong>Flexibility</strong>: Pause or slow down if issues emerge, accelerate if going smoothly</li>
      </ul>

      <h2>User Communication Templates</h2>

      <h3>Announcement Email (2 weeks before deployment)</h3>
      <pre>
Subject: Important: New Device Login Experience Coming [Date]

Hi Team,

On [Date], we're launching Okta Device Access to enhance security and improve your device login experience.

<strong>What's Changing?</strong>
When you log into your Windows PC or Mac, you'll be prompted to register with Okta. After one-time setup, you'll enjoy:

✓ <strong>Stronger security</strong>: Multi-factor authentication prevents unauthorized access
✓ <strong>Faster logins</strong>: Use your fingerprint or face instead of typing passwords
✓ <strong>Self-service password reset</strong>: Fix password issues yourself in 2 minutes
✓ <strong>Unified password</strong>: One password for your device and all applications

<strong>What You Need to Do</strong>
1. <strong>Register your device</strong> (5 minutes, one-time setup)
   - Follow the on-screen prompts when you next log in
   - You'll need your phone with Okta Verify for verification

2. <strong>Enroll in passwordless</strong> (optional but recommended)
   - Set up Touch ID or Windows Hello for quick biometric login

3. <strong>Complete brief training</strong>
   - Watch 3-minute video: [Link]
   - Review Quick Start Guide: [Link]

<strong>Timeline</strong>
- <strong>[Date]</strong>: Deployment begins for [Department/Group]
- <strong>[Date]</strong>: Next wave includes [Department/Group]
- <strong>[Date]</strong>: Final rollout complete

<strong>Support</strong>
- Training session: [Date/Time] - [Registration Link]
- Quick Start Guide: [Link]
- FAQ: [Link]
- Help Desk: [Email/Phone/Slack Channel]

Questions? Reply to this email or contact the IT Help Desk.

Thank you for your cooperation as we enhance security and user experience!

[Your Name]
[Title]
      </pre>

      <h3>Training Invitation Email (1 week before deployment)</h3>
      <pre>
Subject: Join Okta Device Access Training - [Date/Time]

Hi [Name],

Your department will begin using Okta Device Access on [Date]. Join our training session to learn how to register your device and use the new passwordless login.

<strong>Training Session Details</strong>
- <strong>Date</strong>: [Date]
- <strong>Time</strong>: [Time] ([Timezone])
- <strong>Duration</strong>: 20 minutes
- <strong>Join Link</strong>: [Video Conference Link]

<strong>What We'll Cover</strong>
1. What Okta Device Access is and why we're deploying it
2. How to register your device (step-by-step walkthrough)
3. How to set up passwordless authentication (Touch ID, Windows Hello)
4. How to use self-service password reset
5. Common questions and troubleshooting
6. Live Q&A

<strong>Can't Attend?</strong>
- Recording will be available: [Link]
- Quick Start Guide: [Link]
- FAQ: [Link]

See you at the training!

[Your Name]
      </pre>

      <h3>Go-Live Email (Day of deployment)</h3>
      <pre>
Subject: Okta Device Access is Live - Action Required

Hi [Name],

<strong>Okta Device Access is now active on your device.</strong> The next time you log in, you'll be prompted to register.

<strong>Quick Steps to Get Started</strong>
1. <strong>Log in to your device</strong> with your current username and password
2. <strong>Complete MFA</strong> verification when prompted (use Okta Verify on your phone)
3. <strong>Follow registration wizard</strong> (takes 5 minutes)
4. <strong>Optional: Enroll in FastPass</strong> for passwordless login with biometrics

<strong>What to Expect</strong>
- First login after registration will take an extra minute for setup
- Subsequent logins will be faster, especially if you use FastPass
- You can reset your password yourself if you forget it

<strong>Resources</strong>
- Quick Start Guide: [Link]
- Video Tutorial: [Link]
- FAQ: [Link]

<strong>Need Help?</strong>
Contact the Help Desk:
- Email: helpdesk@company.com
- Phone: [Phone]
- Slack: #okta-support

We're here to help make this transition smooth!

[Your Name]
      </pre>

      <h3>Follow-Up Email (1 week after deployment)</h3>
      <pre>
Subject: How's Okta Device Access Working for You?

Hi [Name],

It's been a week since we deployed Okta Device Access. We'd love your feedback!

<strong>Quick Survey (2 minutes)</strong>
[Survey Link]

<strong>Haven't Enrolled in FastPass Yet?</strong>
Passwordless login with biometrics is faster and easier than typing passwords. Set it up in 2 minutes:
- [Quick Setup Guide Link]
- [Video Tutorial Link]

<strong>Tips & Tricks</strong>
- Use self-service password reset if you forget your password (no help desk call needed!)
- FastPass works across your device and Okta-connected applications
- Keep Okta Verify on your phone up to date for the best experience

<strong>Still Having Issues?</strong>
Contact the Help Desk: [Email/Phone/Slack]

Thank you for adapting to the new authentication experience!

[Your Name]
      </pre>

      <h2>Training Material Templates</h2>

      <h3>Quick Start Guide Outline</h3>
      <ul>
        <li><strong>Page 1: Welcome</strong>
          <ul>
            <li>What is Okta Device Access?</li>
            <li>Why are we deploying it?</li>
            <li>What changes for you?</li>
          </ul>
        </li>
        <li><strong>Page 2: Initial Registration</strong>
          <ul>
            <li>Step-by-step with screenshots</li>
            <li>What to do when prompted</li>
            <li>Common questions</li>
          </ul>
        </li>
        <li><strong>Page 3: Daily Login</strong>
          <ul>
            <li>Standard login (password + MFA)</li>
            <li>FastPass passwordless login</li>
            <li>Offline scenarios</li>
          </ul>
        </li>
        <li><strong>Page 4: Self-Service Password Reset</strong>
          <ul>
            <li>Step-by-step instructions</li>
            <li>When to use it</li>
            <li>What to do if it doesn't work</li>
          </ul>
        </li>
        <li><strong>Page 5: Troubleshooting & Support</strong>
          <ul>
            <li>Common issues and solutions</li>
            <li>How to contact help desk</li>
            <li>FAQ link and video tutorials</li>
          </ul>
        </li>
      </ul>

      <h3>FAQ Content</h3>
      <pre>
<strong>Frequently Asked Questions: Okta Device Access</strong>

<strong>Q: What is Okta Device Access?</strong>
A: Okta Device Access adds multi-factor authentication to your device login and enables passwordless authentication using biometrics (fingerprint or face). It also allows you to reset your password yourself without calling the help desk.

<strong>Q: Why are we deploying this?</strong>
A: To improve security (MFA prevents unauthorized device access), reduce help desk costs (self-service password reset), and improve user experience (faster login with biometrics).

<strong>Q: What do I need to do?</strong>
A: The next time you log in, follow the on-screen prompts to register your device with Okta. This is a one-time setup that takes about 5 minutes. You'll need your phone with Okta Verify installed.

<strong>Q: What if I don't have Okta Verify on my phone?</strong>
A: Download Okta Verify from the App Store (iOS) or Google Play (Android) before registering your device. Your IT team can help if needed.

<strong>Q: What is FastPass and should I use it?</strong>
A: FastPass allows you to log in with just your fingerprint or face (no password needed). It's faster, easier, and more secure. We highly recommend enrolling - it takes 2 minutes.

<strong>Q: What if I forget my password?</strong>
A: Click "Forgot Password" at the login screen and follow the prompts. You'll verify your identity with MFA and set a new password in about 2 minutes - no help desk call needed!

<strong>Q: What happens if my phone is dead or lost?</strong>
A: You can still authenticate using alternative MFA methods (SMS, backup codes). Contact the help desk if you need assistance.

<strong>Q: Will this work when I'm offline or disconnected from the network?</strong>
A: Yes. Okta Device Access caches your credentials for offline authentication. You can log in even without network connectivity.

<strong>Q: What if I have multiple devices?</strong>
A: Each device must be registered separately. Your Okta Verify app works across all registered devices.

<strong>Q: Who do I contact if I have issues?</strong>
A: Contact the IT Help Desk at [Email/Phone/Slack Channel]. We're here to help!
      </pre>

      <h3>Video Script Outline (3-minute overview)</h3>
      <ul>
        <li><strong>0:00-0:30</strong>: Introduction - what's changing and why</li>
        <li><strong>0:30-1:30</strong>: Device registration walkthrough (screen recording)</li>
        <li><strong>1:30-2:15</strong>: FastPass enrollment demo (biometric setup)</li>
        <li><strong>2:15-2:45</strong>: Self-service password reset demo</li>
        <li><strong>2:45-3:00</strong>: Wrap-up and support resources</li>
      </ul>

      <h2>Support Readiness Checklist</h2>

      <h3>Help Desk Training (Before Rollout)</h3>
      <ul>
        <li><input type="checkbox"> All help desk staff trained on Okta Device Access architecture and user flows</li>
        <li><input type="checkbox"> Training on common issues: enrollment failures, MFA prompts, password sync, FastPass</li>
        <li><input type="checkbox"> Access to Okta admin console for troubleshooting (device status, authentication logs)</li>
        <li><input type="checkbox"> Escalation procedures documented (when to escalate to Level 2, Okta support)</li>
        <li><input type="checkbox"> Knowledge base articles created for common issues</li>
        <li><input type="checkbox"> Scripts and talking points for common user questions</li>
        <li><input type="checkbox"> Test environment access for reproducing user issues</li>
        <li><input type="checkbox"> Contact information for Okta SE and support team</li>
      </ul>

      <h3>Escalation Paths</h3>
      <ul>
        <li><strong>Level 1: Help Desk</strong> - Common issues, password resets, enrollment guidance</li>
        <li><strong>Level 2: IT Systems Team</strong> - Policy configuration, MDM issues, integration problems</li>
        <li><strong>Level 3: Okta SE</strong> - Complex technical issues, product questions, best practices</li>
        <li><strong>Level 4: Okta Support</strong> - Product bugs, service incidents, engineering escalations</li>
      </ul>

      <h3>Known Issues and Workarounds</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Issue</th>
          <th>Symptoms</th>
          <th>Workaround</th>
        </tr>
        <tr>
          <td>Enrollment fails on first attempt</td>
          <td>Registration wizard shows error</td>
          <td>Restart device, try again. If fails twice, escalate to Level 2</td>
        </tr>
        <tr>
          <td>MFA prompt doesn't appear</td>
          <td>User enters password, nothing happens</td>
          <td>Check network connectivity, verify Okta Verify installed, check policy assignment</td>
        </tr>
        <tr>
          <td>Password sync delayed</td>
          <td>New password works in Okta but not on device</td>
          <td>Wait 60 seconds, lock/unlock device. If still fails, check AD agent status</td>
        </tr>
        <tr>
          <td>FastPass not enrolling</td>
          <td>Option grayed out or missing</td>
          <td>Verify device supports biometrics, check policy allows FastPass, ensure Okta Verify up to date</td>
        </tr>
      </table>

      <h2>Change Management Framework</h2>

      <h3>Stakeholder Identification</h3>
      <ul>
        <li><strong>Executive Sponsor</strong>: CIO, CISO, or VP IT - signs off on rollout, provides resources</li>
        <li><strong>Project Lead</strong>: IT Manager or Identity Architect - owns execution and coordination</li>
        <li><strong>Technical Team</strong>: Systems engineers - configuration, integration, troubleshooting</li>
        <li><strong>Security Team</strong>: Security engineers - policy validation, compliance review</li>
        <li><strong>Help Desk</strong>: Support staff - user support, issue resolution</li>
        <li><strong>Communications Lead</strong>: IT comms or corporate comms - user messaging and training</li>
        <li><strong>Department Heads</strong>: Business unit leaders - communicate to their teams, manage change</li>
        <li><strong>End Users</strong>: All employees - adopt new authentication experience</li>
      </ul>

      <h3>RACI Matrix</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Activity</th>
          <th>Executive Sponsor</th>
          <th>Project Lead</th>
          <th>Technical Team</th>
          <th>Help Desk</th>
          <th>Dept Heads</th>
        </tr>
        <tr>
          <td>Project Approval</td>
          <td>A</td>
          <td>R</td>
          <td>C</td>
          <td>I</td>
          <td>C</td>
        </tr>
        <tr>
          <td>Configuration & Setup</td>
          <td>I</td>
          <td>A</td>
          <td>R</td>
          <td>I</td>
          <td>I</td>
        </tr>
        <tr>
          <td>Wave Planning</td>
          <td>C</td>
          <td>A</td>
          <td>R</td>
          <td>C</td>
          <td>C</td>
        </tr>
        <tr>
          <td>User Communication</td>
          <td>I</td>
          <td>A</td>
          <td>C</td>
          <td>C</td>
          <td>R</td>
        </tr>
        <tr>
          <td>Help Desk Training</td>
          <td>I</td>
          <td>A</td>
          <td>R</td>
          <td>C</td>
          <td>I</td>
        </tr>
        <tr>
          <td>User Support</td>
          <td>I</td>
          <td>C</td>
          <td>C</td>
          <td>R</td>
          <td>A</td>
        </tr>
        <tr>
          <td>Issue Escalation</td>
          <td>I</td>
          <td>A</td>
          <td>R</td>
          <td>R</td>
          <td>I</td>
        </tr>
      </table>
      <p><em>R = Responsible, A = Accountable, C = Consulted, I = Informed</em></p>

      <h3>Communication Plan</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Timing</th>
          <th>Audience</th>
          <th>Message</th>
          <th>Channel</th>
        </tr>
        <tr>
          <td>T-4 weeks</td>
          <td>Executive Team</td>
          <td>Project approval, business case, timeline</td>
          <td>Executive briefing</td>
        </tr>
        <tr>
          <td>T-3 weeks</td>
          <td>Department Heads</td>
          <td>Rollout plan, department wave assignments, expectations</td>
          <td>Manager meeting</td>
        </tr>
        <tr>
          <td>T-2 weeks</td>
          <td>All Users</td>
          <td>Announcement, what's changing, timeline, resources</td>
          <td>Email, Slack, Intranet</td>
        </tr>
        <tr>
          <td>T-1 week</td>
          <td>Wave 1 Users</td>
          <td>Training invitation, specific go-live date</td>
          <td>Email, calendar invite</td>
        </tr>
        <tr>
          <td>Go-Live Day</td>
          <td>Wave 1 Users</td>
          <td>Action required, quick steps, support resources</td>
          <td>Email, Slack</td>
        </tr>
        <tr>
          <td>T+1 week</td>
          <td>Wave 1 Users</td>
          <td>Follow-up, feedback survey, tips & tricks</td>
          <td>Email</td>
        </tr>
        <tr>
          <td>Each Wave</td>
          <td>Next Wave Users</td>
          <td>Repeat cycle for each wave</td>
          <td>Email, Slack</td>
        </tr>
      </table>

      <h2>Rollback Procedures</h2>

      <h3>When to Consider Rollback</h3>
      <ul>
        <li>Authentication success rate <90% for >24 hours</li>
        <li>Critical (P0) issue affecting majority of users with no workaround</li>
        <li>Security vulnerability discovered in deployment</li>
        <li>Integration failure causing business disruption</li>
        <li>Executive decision to pause deployment</li>
      </ul>

      <h3>Emergency Rollback Steps (Windows)</h3>
      <ol>
        <li><strong>Immediate</strong>: Disable authentication policy in Okta admin (users fall back to password-only)</li>
        <li><strong>Within 1 hour</strong>: Remove users from Okta Device Access group assignment</li>
        <li><strong>Within 4 hours</strong>: Remove Okta Credential Provider via MDM or manual uninstall script</li>
        <li><strong>Within 24 hours</strong>: Communicate rollback to users, provide status update</li>
      </ol>

      <h3>Emergency Rollback Steps (macOS)</h3>
      <ol>
        <li><strong>Immediate</strong>: Disable authentication policy in Okta admin</li>
        <li><strong>Within 1 hour</strong>: Remove Platform SSO MDM profile via MDM push</li>
        <li><strong>Within 4 hours</strong>: Verify users can authenticate with standard macOS login</li>
        <li><strong>Within 24 hours</strong>: Communicate rollback, plan remediation</li>
      </ol>

      <h3>Profile Removal (MDM)</h3>
      <ul>
        <li><strong>Intune</strong>: Delete configuration profile assignment, push removal</li>
        <li><strong>Jamf</strong>: Remove policy from scope, push removal command</li>
        <li><strong>Workspace ONE</strong>: Delete profile from assignment group</li>
      </ul>

      <h3>User Communication (Rollback)</h3>
      <pre>
Subject: Update: Temporary Change to Device Login

Hi Team,

Due to a technical issue, we've temporarily paused the Okta Device Access rollout. Your device login will return to the previous authentication method.

<strong>What This Means for You</strong>
- Log in with your username and password as you did before
- MFA will not be required at device login (application MFA still active)
- No action required on your part

<strong>What Happens Next</strong>
Our IT team is working to resolve the issue. We'll communicate a new rollout date once the issue is resolved.

We apologize for any inconvenience and appreciate your patience.

[Your Name]
[Title]
      </pre>

      <h2>Post-Deployment Success Metrics</h2>

      <h3>Key Metrics to Track</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Metric</th>
          <th>Target</th>
          <th>Measurement</th>
        </tr>
        <tr>
          <td>Authentication Success Rate</td>
          <td>98%</td>
          <td>Okta System Log - successful vs. failed authentications</td>
        </tr>
        <tr>
          <td>FastPass Enrollment Rate</td>
          <td>70%</td>
          <td>Okta admin console - users with FastPass enrolled</td>
        </tr>
        <tr>
          <td>Password Reset Ticket Reduction</td>
          <td>60-75%</td>
          <td>Help desk ticketing system - compare before/after</td>
        </tr>
        <tr>
          <td>User Satisfaction Score</td>
          <td>85%</td>
          <td>Post-deployment user survey</td>
        </tr>
        <tr>
          <td>Average Login Time</td>
          <td><10 seconds</td>
          <td>User testing or survey</td>
        </tr>
        <tr>
          <td>Help Desk Ticket Volume</td>
          <td><5 per 100 users per week</td>
          <td>Help desk ticketing system</td>
        </tr>
        <tr>
          <td>Device Registration Rate</td>
          <td>95%</td>
          <td>Okta Verify admin console</td>
        </tr>
      </table>

      <h3>Business Value Calculation</h3>
      <pre>
<strong>Help Desk Cost Savings (1,000 user organization)</strong>

Before Okta Device Access:
- 25% of users reset password monthly = 250 resets/month
- $40 cost per reset (help desk time + user downtime)
- Total monthly cost: 250 × $40 = $10,000
- Annual cost: $120,000

After Okta Device Access:
- 70% reduction in password reset tickets
- 75 resets/month (down from 250)
- Total monthly cost: 75 × $40 = $3,000
- Annual cost: $36,000

<strong>Annual Savings: $84,000</strong>

Additional Benefits (not quantified):
- Improved security posture (MFA at device login)
- Better user experience (faster logins, less frustration)
- Productivity gains (5-10 min per password reset × 2,100 resets avoided = 175-350 hours saved)
      </pre>

      <h3>Weekly Metrics Dashboard (During Rollout)</h3>
      <table border="1" cellpadding="8" cellspacing="0">
        <tr>
          <th>Week</th>
          <th>Users Enrolled</th>
          <th>Auth Success Rate</th>
          <th>FastPass %</th>
          <th>Support Tickets</th>
          <th>Status</th>
        </tr>
        <tr>
          <td>1 (Pilot)</td>
          <td>100</td>
          <td>96%</td>
          <td>45%</td>
          <td>12</td>
          <td>🟢 On Track</td>
        </tr>
        <tr>
          <td>2</td>
          <td>500</td>
          <td>97%</td>
          <td>52%</td>
          <td>38</td>
          <td>🟢 On Track</td>
        </tr>
        <tr>
          <td>3</td>
          <td>1,500</td>
          <td>98%</td>
          <td>60%</td>
          <td>85</td>
          <td>🟢 On Track</td>
        </tr>
        <tr>
          <td>4</td>
          <td>3,500</td>
          <td>97%</td>
          <td>65%</td>
          <td>120</td>
          <td>🟢 On Track</td>
        </tr>
        <tr>
          <td>5</td>
          <td>5,000</td>
          <td>98%</td>
          <td>72%</td>
          <td>95</td>
          <td>🟢 Complete</td>
        </tr>
      </table>
    `,
    summary: 'Complete phased rollout strategy covering approach comparison, pilot guide, wave-based deployment, communication templates, training materials, support readiness, change management framework, rollback procedures, and success metrics.',
    category: 'implementation',
    tags: ['rollout', 'deployment', 'phased', 'pilot', 'waves', 'communication', 'training', 'change management', 'support'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-jamf-pro-guide',
    title: 'Complete Jamf Pro Configuration Guide for Okta Device Access',
    content: `
      <h2>Complete Jamf Pro Configuration Guide for Okta Device Access</h2>
      <p>This comprehensive guide walks through deploying Okta Device Access using Jamf Pro, covering Desktop MFA, Platform SSO, Okta Verify deployment, and troubleshooting. Follow these steps to successfully configure and deploy ODA to your macOS fleet.</p>

      <h3>Prerequisites</h3>
      <p>Before starting, ensure you have:</p>
      <ul>
        <li><strong>Jamf Pro version:</strong> 10.39 or later (Platform SSO requires 10.46 or later)</li>
        <li><strong>Okta requirements:</strong>
          <ul>
            <li>Okta Identity Engine (OIE) enabled tenant</li>
            <li>Desktop MFA app created in Okta admin console</li>
            <li>Client ID and Client Secret from Desktop MFA app</li>
            <li>Platform SSO app created (for password sync scenarios)</li>
            <li>Authentication policies configured for device access</li>
          </ul>
        </li>
        <li><strong>macOS requirements:</strong> macOS 13.0 (Ventura) or later for Desktop MFA; macOS 13.0+ for Platform SSO</li>
        <li><strong>Jamf permissions needed:</strong>
          <ul>
            <li>Configuration Profiles: Create, Read, Update</li>
            <li>Packages: Create, Read, Update</li>
            <li>Policies: Create, Read, Update</li>
            <li>Smart Computer Groups: Create, Read, Update</li>
          </ul>
        </li>
        <li><strong>Network access:</strong> Devices must reach Okta endpoints (*.okta.com, *.oktacdn.com)</li>
        <li><strong>Okta Verify package:</strong> Download latest version from Okta downloads page</li>
      </ul>

      <h3>Desktop MFA Configuration</h3>
      <p>Desktop MFA requires a custom configuration profile with specific preference domain settings. The profile must be installed before Okta Verify.</p>

      <h4>Step 1: Create Desktop MFA Configuration Profile</h4>
      <ol>
        <li>In Jamf Pro, navigate to <strong>Configuration Profiles</strong></li>
        <li>Click <strong>+ New</strong></li>
        <li>Configure general settings:
          <ul>
            <li>Name: "Okta Desktop MFA Configuration"</li>
            <li>Distribution Method: Install Automatically</li>
            <li>Level: Computer Level</li>
          </ul>
        </li>
        <li>Add <strong>Application & Custom Settings</strong> payload</li>
        <li>Set Preference Domain: <code>com.okta.deviceaccess.servicedaemon</code></li>
        <li>Upload or paste the complete plist (see example below)</li>
      </ol>

      <h4>Desktop MFA Plist Example</h4>
      <pre><code>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
    &lt;key&gt;OrgUrl&lt;/key&gt;
    &lt;string&gt;https://yourorg.okta.com&lt;/string&gt;

    &lt;key&gt;ClientId&lt;/key&gt;
    &lt;string&gt;0oa1abc2def3GHI4jklm&lt;/string&gt;

    &lt;key&gt;ClientSecret&lt;/key&gt;
    &lt;string&gt;YOUR_CLIENT_SECRET_HERE&lt;/string&gt;

    &lt;key&gt;AllowedFactors&lt;/key&gt;
    &lt;array&gt;
        &lt;string&gt;push&lt;/string&gt;
        &lt;string&gt;totp&lt;/string&gt;
        &lt;string&gt;password&lt;/string&gt;
    &lt;/array&gt;

    &lt;key&gt;OfflineLoginSettings&lt;/key&gt;
    &lt;dict&gt;
        &lt;key&gt;Enabled&lt;/key&gt;
        &lt;true/&gt;
        &lt;key&gt;GracePeriodInHours&lt;/key&gt;
        &lt;integer&gt;72&lt;/integer&gt;
    &lt;/dict&gt;

    &lt;key&gt;RecoveryPIN&lt;/key&gt;
    &lt;dict&gt;
        &lt;key&gt;Enabled&lt;/key&gt;
        &lt;true/&gt;
    &lt;/dict&gt;

    &lt;key&gt;PasswordResetEnabled&lt;/key&gt;
    &lt;true/&gt;
&lt;/dict&gt;
&lt;/plist&gt;</code></pre>

      <h4>Key Plist Explanations</h4>
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>OrgUrl</code></td>
            <td>String</td>
            <td>Your Okta tenant URL (https://yourorg.okta.com)</td>
          </tr>
          <tr>
            <td><code>ClientId</code></td>
            <td>String</td>
            <td>OAuth Client ID from Desktop MFA app in Okta</td>
          </tr>
          <tr>
            <td><code>ClientSecret</code></td>
            <td>String</td>
            <td>OAuth Client Secret from Desktop MFA app (handle securely)</td>
          </tr>
          <tr>
            <td><code>AllowedFactors</code></td>
            <td>Array</td>
            <td>Factors available at login: push, totp, password, webauthn</td>
          </tr>
          <tr>
            <td><code>OfflineLoginSettings</code></td>
            <td>Dictionary</td>
            <td>Controls offline authentication; GracePeriodInHours sets offline window</td>
          </tr>
          <tr>
            <td><code>RecoveryPIN</code></td>
            <td>Dictionary</td>
            <td>Enable self-service recovery PIN option</td>
          </tr>
          <tr>
            <td><code>PasswordResetEnabled</code></td>
            <td>Boolean</td>
            <td>Enable self-service password reset at login screen</td>
          </tr>
        </tbody>
      </table>

      <h4>Step 2: Scope Desktop MFA Profile</h4>
      <ol>
        <li>In the <strong>Scope</strong> tab of the configuration profile:</li>
        <li>Add target computers or smart groups (e.g., "Okta Device Access Pilot")</li>
        <li>Save the profile</li>
        <li><strong>Critical:</strong> Do not deploy Okta Verify yet—profile must install first</li>
      </ol>

      <h3>Platform SSO Configuration</h3>
      <p>Platform SSO enables password sync between macOS and Okta. This requires the Extensible Single Sign-On payload.</p>

      <h4>Step 1: Create Platform SSO Configuration Profile</h4>
      <ol>
        <li>In Jamf Pro, create a new Configuration Profile</li>
        <li>Name: "Okta Platform SSO"</li>
        <li>Add <strong>Single Sign-On Extensions</strong> payload</li>
        <li>Configure SSO extension settings:
          <ul>
            <li>Payload Type: <strong>Redirect</strong></li>
            <li>Extension Identifier: <code>com.okta.macOSExtension</code></li>
            <li>Team Identifier: <code>5G8K6A7738</code> (Okta's Team ID)</li>
            <li>Sign-On Type: Redirect</li>
          </ul>
        </li>
      </ol>

      <h4>Step 2: Configure Extension Settings</h4>
      <p>Add custom extension configuration keys:</p>
      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Type</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>organization</code></td>
            <td>String</td>
            <td>yourorg (subdomain only, not full URL)</td>
          </tr>
          <tr>
            <td><code>client_id</code></td>
            <td>String</td>
            <td>Client ID from Platform SSO app in Okta</td>
          </tr>
          <tr>
            <td><code>redirect_uri</code></td>
            <td>String</td>
            <td>com.okta.sso.macos:/callback</td>
          </tr>
          <tr>
            <td><code>registration_token</code></td>
            <td>String</td>
            <td>Registration token from Okta Platform SSO app (optional)</td>
          </tr>
          <tr>
            <td><code>enable_password_sync</code></td>
            <td>Boolean</td>
            <td>true</td>
          </tr>
        </tbody>
      </table>

      <h4>Step 3: Configure URLs</h4>
      <p>In the SSO extension payload, add required URLs:</p>
      <ul>
        <li><code>https://yourorg.okta.com</code></li>
        <li><code>https://yourorg.okta.com/*</code></li>
        <li><code>https://yourorg.okta-emea.com</code> (if using EMEA cell)</li>
      </ul>

      <h4>Step 4: Scope Platform SSO Profile</h4>
      <ol>
        <li>Target the same smart group as Desktop MFA (or a subset)</li>
        <li>Save and deploy the profile</li>
        <li>Verify profile installation before proceeding to Okta Verify deployment</li>
      </ol>

      <h3>Okta Verify Deployment</h3>
      <p>Okta Verify must be deployed after configuration profiles are installed.</p>

      <h4>Step 1: Upload Okta Verify Package</h4>
      <ol>
        <li>Download the latest Okta Verify PKG from Okta downloads</li>
        <li>In Jamf Pro, navigate to <strong>Settings > Computer Management > Packages</strong></li>
        <li>Click <strong>+ New</strong></li>
        <li>Upload the Okta Verify PKG file</li>
        <li>Set display name: "Okta Verify for macOS"</li>
        <li>Category: Security</li>
        <li>Priority: 10 (standard)</li>
        <li>Save the package</li>
      </ol>

      <h4>Step 2: Create Okta Verify Policy</h4>
      <ol>
        <li>Navigate to <strong>Computers > Policies</strong></li>
        <li>Click <strong>+ New</strong></li>
        <li>General settings:
          <ul>
            <li>Display Name: "Deploy Okta Verify"</li>
            <li>Trigger: Recurring Check-In</li>
            <li>Execution Frequency: Once per computer</li>
          </ul>
        </li>
        <li>Add <strong>Packages</strong> payload</li>
        <li>Select "Okta Verify for macOS"</li>
        <li>Action: Install</li>
      </ol>

      <h4>Step 3: Scope Okta Verify Policy</h4>
      <ol>
        <li>In the <strong>Scope</strong> tab:</li>
        <li>Add the same target groups as Desktop MFA profile</li>
        <li><strong>Critical:</strong> Add exclusion criteria:
          <ul>
            <li>Exclude computers where Desktop MFA profile is not installed</li>
            <li>Use smart group: "Desktop MFA Profile Installed"</li>
          </ul>
        </li>
        <li>Save and enable the policy</li>
      </ol>

      <h3>Smart Group Strategies</h3>
      <p>Smart groups ensure proper sequencing and targeting. Create these groups for effective deployment.</p>

      <h4>1. Okta Device Access Pilot Group</h4>
      <pre><code>Criteria:
- Department is "IT"
OR
- User is member of "ODA-Pilot-Users"
AND
- macOS version greater than or equal to 13.0</code></pre>

      <h4>2. Desktop MFA Profile Installed</h4>
      <pre><code>Criteria:
- Configuration Profile "Okta Desktop MFA Configuration" is Installed</code></pre>

      <h4>3. Platform SSO Profile Installed</h4>
      <pre><code>Criteria:
- Configuration Profile "Okta Platform SSO" is Installed</code></pre>

      <h4>4. Okta Verify Not Installed</h4>
      <pre><code>Criteria:
- Application Title is not "Okta Verify"</code></pre>

      <h4>5. Ready for Okta Verify Deployment</h4>
      <pre><code>Criteria:
- Member of "Desktop MFA Profile Installed"
AND
- Member of "Okta Verify Not Installed"
AND
- Member of "Okta Device Access Pilot Group"</code></pre>

      <h3>Configuration Deployment Sequence</h3>
      <p>Follow this exact order to avoid deployment failures:</p>
      <ol>
        <li><strong>Day 1:</strong> Deploy Desktop MFA configuration profile to pilot group</li>
        <li><strong>Day 1:</strong> Deploy Platform SSO profile to pilot group (if using password sync)</li>
        <li><strong>Day 2:</strong> Verify profiles installed successfully via Jamf inventory update</li>
        <li><strong>Day 2:</strong> Deploy Okta Verify policy (scoped to "Ready for Okta Verify Deployment" group)</li>
        <li><strong>Day 3:</strong> Verify Okta Verify installation and test user sign-in</li>
        <li><strong>Ongoing:</strong> Expand pilot group incrementally</li>
      </ol>

      <h3>Testing and Validation</h3>
      <p>After deployment, validate each component:</p>

      <h4>1. Verify Profile Installation</h4>
      <pre><code># On managed Mac, check profiles
sudo profiles show | grep -A 10 "com.okta.deviceaccess"

# Verify configuration values
defaults read /Library/Managed\ Preferences/com.okta.deviceaccess.servicedaemon

# Check Platform SSO profile
sudo profiles show | grep -A 10 "com.apple.extensiblesso"</code></pre>

      <h4>2. Verify Okta Verify Installation</h4>
      <pre><code># Check if Okta Verify is installed
ls -la "/Applications/Okta Verify.app"

# Check running processes
ps aux | grep -i okta

# Check launch agents
launchctl list | grep -i okta</code></pre>

      <h4>3. Test User Sign-In</h4>
      <ol>
        <li>Log out of the test Mac</li>
        <li>At login screen, enter username and password</li>
        <li>Verify MFA prompt appears (push notification or TOTP)</li>
        <li>Complete authentication</li>
        <li>Verify successful login</li>
      </ol>

      <h4>4. Test Platform SSO Registration (if deployed)</h4>
      <ol>
        <li>Log in to macOS with local credentials</li>
        <li>Platform SSO should prompt for Okta authentication</li>
        <li>Complete Okta sign-in with MFA</li>
        <li>Device registers to Okta Verify account</li>
        <li>Verify FastPass enrollment in Okta admin console</li>
      </ol>

      <h3>Common Pitfalls and Solutions</h3>

      <h4>1. Installation Order Issues</h4>
      <p><strong>Problem:</strong> Okta Verify installed before Desktop MFA profile</p>
      <p><strong>Symptoms:</strong> Login prompt doesn't appear; standard macOS login only</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Remove Okta Verify: <code>sudo rm -rf "/Applications/Okta Verify.app"</code></li>
          <li>Verify profile is installed: <code>sudo profiles show</code></li>
          <li>Reinstall Okta Verify via Jamf policy</li>
        </ul>
      </p>

      <h4>2. Scope Misalignment</h4>
      <p><strong>Problem:</strong> Configuration profile and Okta Verify deployed to different groups</p>
      <p><strong>Symptoms:</strong> Inconsistent behavior across fleet</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Review scope of configuration profile and Okta Verify policy</li>
          <li>Ensure both target the same smart groups</li>
          <li>Use "Ready for Okta Verify Deployment" smart group to enforce dependencies</li>
        </ul>
      </p>

      <h4>3. Profile Conflicts</h4>
      <p><strong>Problem:</strong> Multiple profiles with overlapping preference domains</p>
      <p><strong>Symptoms:</strong> Configuration values not applied; unexpected behavior</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Audit existing profiles: <code>sudo profiles show</code></li>
          <li>Remove conflicting profiles</li>
          <li>Consolidate settings into single Desktop MFA profile</li>
        </ul>
      </p>

      <h4>4. Client Secret Typos</h4>
      <p><strong>Problem:</strong> Client ID or Client Secret contains typos or extra characters</p>
      <p><strong>Symptoms:</strong> Authentication fails; "Invalid client" error</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Verify Client ID and Secret in Okta admin console</li>
          <li>Copy values directly (avoid manual typing)</li>
          <li>Update configuration profile with correct values</li>
          <li>Redeploy profile to affected devices</li>
        </ul>
      </p>

      <h4>5. Network Connectivity Issues</h4>
      <p><strong>Problem:</strong> Devices cannot reach Okta endpoints</p>
      <p><strong>Symptoms:</strong> Timeout errors; "Unable to contact Okta" message</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Verify firewall/proxy allows *.okta.com and *.oktacdn.com</li>
          <li>Test connectivity: <code>curl https://yourorg.okta.com</code></li>
          <li>Check proxy settings: <code>scutil --proxy</code></li>
          <li>Enable offline login settings if intermittent connectivity expected</li>
        </ul>
      </p>

      <h3>Advanced Configurations</h3>

      <h4>Offline Login Settings</h4>
      <p>Configure offline authentication for disconnected scenarios:</p>
      <pre><code>&lt;key&gt;OfflineLoginSettings&lt;/key&gt;
&lt;dict&gt;
    &lt;key&gt;Enabled&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;GracePeriodInHours&lt;/key&gt;
    &lt;integer&gt;168&lt;/integer&gt;  &lt;!-- 7 days --&gt;

    &lt;key&gt;RequireOnlineAuthenticationAfterGracePeriod&lt;/key&gt;
    &lt;true/&gt;
&lt;/dict&gt;</code></pre>

      <h4>Recovery PIN Configuration</h4>
      <p>Enable self-service recovery when users cannot complete MFA:</p>
      <pre><code>&lt;key&gt;RecoveryPIN&lt;/key&gt;
&lt;dict&gt;
    &lt;key&gt;Enabled&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;MinimumLength&lt;/key&gt;
    &lt;integer&gt;8&lt;/integer&gt;

    &lt;key&gt;RequireAlphanumeric&lt;/key&gt;
    &lt;true/&gt;
&lt;/dict&gt;</code></pre>

      <h4>Custom Factor List</h4>
      <p>Restrict available factors at device login:</p>
      <pre><code>&lt;key&gt;AllowedFactors&lt;/key&gt;
&lt;array&gt;
    &lt;string&gt;push&lt;/string&gt;
    &lt;string&gt;totp&lt;/string&gt;
    &lt;string&gt;webauthn&lt;/string&gt;
    &lt;!-- Omit 'password' to require MFA --&gt;
&lt;/array&gt;</code></pre>

      <h3>Troubleshooting Guide</h3>

      <h4>Essential Log Locations</h4>
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Log Location</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Desktop MFA Service</td>
            <td><code>/Library/Logs/Okta/DesktopAccess/</code></td>
          </tr>
          <tr>
            <td>Okta Verify</td>
            <td><code>~/Library/Logs/Okta/OktaVerify.log</code></td>
          </tr>
          <tr>
            <td>Platform SSO Extension</td>
            <td><code>/var/log/install.log</code> and Console.app (filter: subsystem:com.okta)</td>
          </tr>
          <tr>
            <td>Jamf Policy Execution</td>
            <td><code>/var/log/jamf.log</code></td>
          </tr>
        </tbody>
      </table>

      <h4>Diagnostic Commands</h4>
      <pre><code># Check Desktop MFA service status
sudo launchctl list | grep com.okta.deviceaccess

# View Desktop MFA logs
sudo tail -f /Library/Logs/Okta/DesktopAccess/service.log

# Check configuration profile values
defaults read /Library/Managed\ Preferences/com.okta.deviceaccess.servicedaemon

# Verify Platform SSO registration
sfltool dumpbtm

# Force Jamf inventory update
sudo jamf recon

# Test Okta connectivity
curl -v https://yourorg.okta.com/.well-known/okta-organization</code></pre>

      <h4>Common Error Messages</h4>
      <table>
        <thead>
          <tr>
            <th>Error</th>
            <th>Cause</th>
            <th>Resolution</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>"Configuration not found"</td>
            <td>Desktop MFA profile not installed</td>
            <td>Verify profile installation; redeploy if missing</td>
          </tr>
          <tr>
            <td>"Invalid client credentials"</td>
            <td>Client ID or Secret incorrect</td>
            <td>Verify values in Okta admin; update profile</td>
          </tr>
          <tr>
            <td>"Unable to contact Okta"</td>
            <td>Network connectivity issue</td>
            <td>Check firewall/proxy; verify DNS resolution</td>
          </tr>
          <tr>
            <td>"User not found"</td>
            <td>Username doesn't match Okta user</td>
            <td>Verify username format; check Okta user directory</td>
          </tr>
          <tr>
            <td>"MFA required but no factors available"</td>
            <td>User has no enrolled factors</td>
            <td>Enroll factors in Okta; update authentication policy</td>
          </tr>
        </tbody>
      </table>

      <h3>Support Resources</h3>
      <ul>
        <li><strong>Okta Help Center:</strong> <a href="https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm">Device Access Documentation</a></li>
        <li><strong>Jamf Documentation:</strong> <a href="https://docs.jamf.com">Jamf Pro Administrator Guide</a></li>
        <li><strong>Okta Community:</strong> <a href="https://support.okta.com/help/s/">Okta Support Portal</a></li>
        <li><strong>Apple Platform SSO:</strong> <a href="https://support.apple.com/guide/deployment/extensible-single-sign-on-dep6e7be8cb0/web">Apple Deployment Guide</a></li>
      </ul>
    `,
    summary: 'Comprehensive Jamf Pro deployment guide covering prerequisites, Desktop MFA configuration, Platform SSO setup, Okta Verify deployment, smart groups, testing procedures, common pitfalls, advanced configurations, and troubleshooting for Okta Device Access.',
    category: 'integration',
    tags: ['jamf pro', 'mdm', 'deployment', 'configuration', 'desktop mfa', 'platform sso', 'okta verify', 'smart groups', 'troubleshooting'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-intune-guide',
    title: 'Complete Microsoft Intune Configuration Guide for Okta Device Access',
    content: `
      <h2>Complete Microsoft Intune Configuration Guide for Okta Device Access</h2>
      <p>This comprehensive guide covers deploying Okta Device Access using Microsoft Intune for both Windows and macOS endpoints. Learn how to configure Desktop MFA, Platform SSO, deploy Okta Verify, and troubleshoot common deployment scenarios.</p>

      <h3>Prerequisites</h3>
      <p>Before starting, ensure you have:</p>
      <ul>
        <li><strong>Intune licensing:</strong>
          <ul>
            <li>Microsoft Intune Plan 1 or higher</li>
            <li>Microsoft Entra ID (Azure AD) Premium P1 or P2</li>
            <li>Valid licenses assigned to target users</li>
          </ul>
        </li>
        <li><strong>Azure AD requirements:</strong>
          <ul>
            <li>Devices enrolled in Intune (Azure AD joined or Hybrid joined)</li>
            <li>User accounts synchronized to Azure AD</li>
            <li>Conditional Access policies configured (optional but recommended)</li>
          </ul>
        </li>
        <li><strong>Okta requirements:</strong>
          <ul>
            <li>Okta Identity Engine (OIE) enabled tenant</li>
            <li>Desktop MFA app created in Okta admin console</li>
            <li>Client ID and Client Secret from Desktop MFA app</li>
            <li>Platform SSO app created (for macOS password sync)</li>
            <li>Authentication policies configured for device access</li>
          </ul>
        </li>
        <li><strong>Windows requirements:</strong> Windows 10 version 1903 or later; Windows 11 recommended</li>
        <li><strong>macOS requirements:</strong> macOS 13.0 (Ventura) or later</li>
        <li><strong>Intune permissions needed:</strong>
          <ul>
            <li>Device Configuration: Create, Read, Update, Assign</li>
            <li>Mobile Applications: Create, Read, Update, Assign</li>
            <li>Device Enrollment: Read</li>
          </ul>
        </li>
        <li><strong>Network access:</strong> Devices must reach Okta endpoints (*.okta.com, *.oktacdn.com)</li>
        <li><strong>Okta Verify installers:</strong> MSI for Windows, PKG for macOS</li>
      </ul>

      <h3>Windows Desktop MFA Configuration</h3>
      <p>Windows Desktop MFA uses a credential provider to intercept and enhance the standard Windows login experience.</p>

      <h4>Step 1: Create Windows Desktop MFA Configuration Profile</h4>
      <ol>
        <li>Sign in to <strong>Microsoft Intune admin center</strong> (https://intune.microsoft.com)</li>
        <li>Navigate to <strong>Devices > Configuration profiles</strong></li>
        <li>Click <strong>+ Create profile</strong></li>
        <li>Platform: <strong>Windows 10 and later</strong></li>
        <li>Profile type: <strong>Settings catalog</strong></li>
        <li>Click <strong>Create</strong></li>
        <li>Name: "Okta Desktop MFA - Windows"</li>
        <li>Description: "Desktop MFA configuration for Windows devices"</li>
      </ol>

      <h4>Step 2: Add Configuration Settings</h4>
      <p>In the Settings Catalog, add custom OMA-URI settings:</p>

      <table>
        <thead>
          <tr>
            <th>Setting</th>
            <th>OMA-URI Path</th>
            <th>Data Type</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Okta Org URL</td>
            <td>./Device/Vendor/MSFT/Policy/Config/OktaDeviceAccess/OrgUrl</td>
            <td>String</td>
            <td>https://yourorg.okta.com</td>
          </tr>
          <tr>
            <td>Client ID</td>
            <td>./Device/Vendor/MSFT/Policy/Config/OktaDeviceAccess/ClientId</td>
            <td>String</td>
            <td>0oa1abc2def3GHI4jklm</td>
          </tr>
          <tr>
            <td>Client Secret</td>
            <td>./Device/Vendor/MSFT/Policy/Config/OktaDeviceAccess/ClientSecret</td>
            <td>String</td>
            <td>YOUR_CLIENT_SECRET</td>
          </tr>
          <tr>
            <td>Offline Login Enabled</td>
            <td>./Device/Vendor/MSFT/Policy/Config/OktaDeviceAccess/OfflineLoginEnabled</td>
            <td>Boolean</td>
            <td>true</td>
          </tr>
          <tr>
            <td>Grace Period Hours</td>
            <td>./Device/Vendor/MSFT/Policy/Config/OktaDeviceAccess/GracePeriodHours</td>
            <td>Integer</td>
            <td>72</td>
          </tr>
        </tbody>
      </table>

      <p><strong>Note:</strong> If custom OMA-URI paths are not available, use Administrative Templates or Registry settings delivered via PowerShell script.</p>

      <h4>Step 3: Alternative - PowerShell Script Deployment</h4>
      <p>If OMA-URI settings are unavailable, deploy configuration via PowerShell script:</p>

      <pre><code># Set Okta Desktop MFA registry keys
$regPath = "HKLM:\\SOFTWARE\\Okta\\DeviceAccess"

New-Item -Path $regPath -Force | Out-Null

Set-ItemProperty -Path $regPath -Name "OrgUrl" -Value "https://yourorg.okta.com"
Set-ItemProperty -Path $regPath -Name "ClientId" -Value "0oa1abc2def3GHI4jklm"
Set-ItemProperty -Path $regPath -Name "ClientSecret" -Value "YOUR_CLIENT_SECRET"
Set-ItemProperty -Path $regPath -Name "OfflineLoginEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name "GracePeriodHours" -Value 72 -Type DWord
Set-ItemProperty -Path $regPath -Name "RecoveryPINEnabled" -Value 1 -Type DWord

Write-Host "Okta Desktop MFA configuration applied successfully"</code></pre>

      <p>Deploy this script via Intune:</p>
      <ol>
        <li>Navigate to <strong>Devices > Scripts</strong></li>
        <li>Click <strong>+ Add</strong> > <strong>Windows 10 and later</strong></li>
        <li>Upload the PowerShell script</li>
        <li>Run this script using the system context: <strong>Yes</strong></li>
        <li>Run script in 64-bit PowerShell: <strong>Yes</strong></li>
        <li>Assign to target device groups</li>
      </ol>

      <h4>Step 4: Assign Configuration Profile</h4>
      <ol>
        <li>In the <strong>Assignments</strong> tab:</li>
        <li>Add target groups (e.g., "Okta-DesktopMFA-Windows-Pilot")</li>
        <li>Review and create the profile</li>
      </ol>

      <h3>macOS Desktop MFA Configuration</h3>
      <p>macOS Desktop MFA requires a custom configuration profile with specific preference domain settings.</p>

      <h4>Step 1: Create macOS Desktop MFA Configuration Profile</h4>
      <ol>
        <li>In Intune admin center, navigate to <strong>Devices > Configuration profiles</strong></li>
        <li>Click <strong>+ Create profile</strong></li>
        <li>Platform: <strong>macOS</strong></li>
        <li>Profile type: <strong>Templates</strong> > <strong>Custom</strong></li>
        <li>Click <strong>Create</strong></li>
        <li>Name: "Okta Desktop MFA - macOS"</li>
        <li>Description: "Desktop MFA configuration for macOS devices"</li>
      </ol>

      <h4>Step 2: Upload Custom Configuration Profile</h4>
      <p>Create a .mobileconfig file with the following content:</p>

      <pre><code>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
    &lt;key&gt;PayloadContent&lt;/key&gt;
    &lt;array&gt;
        &lt;dict&gt;
            &lt;key&gt;PayloadType&lt;/key&gt;
            &lt;string&gt;com.okta.deviceaccess.servicedaemon&lt;/string&gt;

            &lt;key&gt;PayloadVersion&lt;/key&gt;
            &lt;integer&gt;1&lt;/integer&gt;

            &lt;key&gt;PayloadIdentifier&lt;/key&gt;
            &lt;string&gt;com.okta.deviceaccess.servicedaemon&lt;/string&gt;

            &lt;key&gt;PayloadUUID&lt;/key&gt;
            &lt;string&gt;GENERATE-NEW-UUID-HERE&lt;/string&gt;

            &lt;key&gt;PayloadDisplayName&lt;/key&gt;
            &lt;string&gt;Okta Desktop MFA Configuration&lt;/string&gt;

            &lt;key&gt;OrgUrl&lt;/key&gt;
            &lt;string&gt;https://yourorg.okta.com&lt;/string&gt;

            &lt;key&gt;ClientId&lt;/key&gt;
            &lt;string&gt;0oa1abc2def3GHI4jklm&lt;/string&gt;

            &lt;key&gt;ClientSecret&lt;/key&gt;
            &lt;string&gt;YOUR_CLIENT_SECRET_HERE&lt;/string&gt;

            &lt;key&gt;AllowedFactors&lt;/key&gt;
            &lt;array&gt;
                &lt;string&gt;push&lt;/string&gt;
                &lt;string&gt;totp&lt;/string&gt;
                &lt;string&gt;password&lt;/string&gt;
            &lt;/array&gt;

            &lt;key&gt;OfflineLoginSettings&lt;/key&gt;
            &lt;dict&gt;
                &lt;key&gt;Enabled&lt;/key&gt;
                &lt;true/&gt;
                &lt;key&gt;GracePeriodInHours&lt;/key&gt;
                &lt;integer&gt;72&lt;/integer&gt;
            &lt;/dict&gt;

            &lt;key&gt;RecoveryPIN&lt;/key&gt;
            &lt;dict&gt;
                &lt;key&gt;Enabled&lt;/key&gt;
                &lt;true/&gt;
            &lt;/dict&gt;

            &lt;key&gt;PasswordResetEnabled&lt;/key&gt;
            &lt;true/&gt;
        &lt;/dict&gt;
    &lt;/array&gt;

    &lt;key&gt;PayloadDisplayName&lt;/key&gt;
    &lt;string&gt;Okta Desktop MFA&lt;/string&gt;

    &lt;key&gt;PayloadIdentifier&lt;/key&gt;
    &lt;string&gt;com.company.okta.desktopMFA&lt;/string&gt;

    &lt;key&gt;PayloadUUID&lt;/key&gt;
    &lt;string&gt;GENERATE-NEW-UUID-HERE&lt;/string&gt;

    &lt;key&gt;PayloadType&lt;/key&gt;
    &lt;string&gt;Configuration&lt;/string&gt;

    &lt;key&gt;PayloadVersion&lt;/key&gt;
    &lt;integer&gt;1&lt;/integer&gt;
&lt;/dict&gt;
&lt;/plist&gt;</code></pre>

      <p>Upload this .mobileconfig file to the custom configuration profile and assign to target groups.</p>

      <h3>macOS Platform SSO Configuration</h3>
      <p>Platform SSO enables password sync between macOS and Okta.</p>

      <h4>Step 1: Create Platform SSO Profile</h4>
      <ol>
        <li>Navigate to <strong>Devices > Configuration profiles</strong></li>
        <li>Click <strong>+ Create profile</strong></li>
        <li>Platform: <strong>macOS</strong></li>
        <li>Profile type: <strong>Templates</strong> > <strong>Device features</strong></li>
        <li>Click <strong>Create</strong></li>
        <li>Name: "Okta Platform SSO - macOS"</li>
      </ol>

      <h4>Step 2: Configure Single Sign-On Extension</h4>
      <ol>
        <li>In the <strong>Single sign-on app extension</strong> section:</li>
        <li>SSO app extension type: <strong>Redirect</strong></li>
        <li>SSO app extension team identifier: <code>5G8K6A7738</code></li>
        <li>SSO app extension bundle ID: <code>com.okta.macOSExtension</code></li>
        <li>SSO app extension URLs:
          <ul>
            <li><code>https://yourorg.okta.com</code></li>
            <li><code>https://yourorg.okta.com/*</code></li>
          </ul>
        </li>
      </ol>

      <h4>Step 3: Add Extension Configuration</h4>
      <p>Add custom key-value pairs for Platform SSO configuration:</p>

      <table>
        <thead>
          <tr>
            <th>Key</th>
            <th>Type</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>organization</td>
            <td>String</td>
            <td>yourorg (subdomain only)</td>
          </tr>
          <tr>
            <td>client_id</td>
            <td>String</td>
            <td>Client ID from Platform SSO app</td>
          </tr>
          <tr>
            <td>redirect_uri</td>
            <td>String</td>
            <td>com.okta.sso.macos:/callback</td>
          </tr>
          <tr>
            <td>enable_password_sync</td>
            <td>Boolean</td>
            <td>true</td>
          </tr>
        </tbody>
      </table>

      <h4>Step 4: Assign Platform SSO Profile</h4>
      <ol>
        <li>Assign to the same groups as Desktop MFA configuration</li>
        <li>Review and create the profile</li>
      </ol>

      <h3>Okta Verify Deployment for Windows</h3>
      <p>Deploy Okta Verify as a Line-of-Business (LOB) app in Intune.</p>

      <h4>Step 1: Prepare Okta Verify MSI</h4>
      <ol>
        <li>Download the latest Okta Verify MSI from Okta downloads page</li>
        <li>Convert MSI to .intunewin format using Microsoft Win32 Content Prep Tool:
          <pre><code>IntuneWinAppUtil.exe -c "C:\\Source" -s "OktaVerify.msi" -o "C:\\Output"</code></pre>
        </li>
      </ol>

      <h4>Step 2: Create Win32 App in Intune</h4>
      <ol>
        <li>Navigate to <strong>Apps > All apps</strong></li>
        <li>Click <strong>+ Add</strong></li>
        <li>App type: <strong>Windows app (Win32)</strong></li>
        <li>Upload the .intunewin package</li>
        <li>Configure app information:
          <ul>
            <li>Name: "Okta Verify for Windows"</li>
            <li>Description: "Okta Verify authenticator for Desktop MFA"</li>
            <li>Publisher: Okta, Inc.</li>
          </ul>
        </li>
      </ol>

      <h4>Step 3: Configure Installation Settings</h4>
      <pre><code>Install command:
msiexec /i "OktaVerify.msi" /qn ALLUSERS=1

Uninstall command:
msiexec /x "{PRODUCT-CODE-GUID}" /qn

Device restart behavior: No specific action</code></pre>

      <h4>Step 4: Detection Rules</h4>
      <p>Configure detection rule to verify installation:</p>
      <ul>
        <li>Rules format: <strong>Manually configure detection rules</strong></li>
        <li>Rule type: <strong>File</strong></li>
        <li>Path: <code>C:\\Program Files\\Okta\\Okta Verify</code></li>
        <li>File or folder: <code>OktaVerify.exe</code></li>
        <li>Detection method: <strong>File or folder exists</strong></li>
      </ul>

      <h4>Step 5: Assign to Devices</h4>
      <ol>
        <li>Assign app to target groups</li>
        <li>Assignment type: <strong>Required</strong> (recommended)</li>
        <li>Add filter: Only devices where Desktop MFA configuration is applied</li>
      </ol>

      <h3>Okta Verify Deployment for macOS</h3>
      <p>Deploy Okta Verify PKG as a macOS LOB app.</p>

      <h4>Step 1: Prepare Okta Verify PKG</h4>
      <ol>
        <li>Download the latest Okta Verify PKG from Okta downloads page</li>
        <li>Convert PKG to .intunemac format (if required by your Intune configuration)</li>
      </ol>

      <h4>Step 2: Create macOS LOB App</h4>
      <ol>
        <li>Navigate to <strong>Apps > All apps</strong></li>
        <li>Click <strong>+ Add</strong></li>
        <li>App type: <strong>macOS app (PKG)</strong></li>
        <li>Upload the Okta Verify PKG file</li>
        <li>Configure app information:
          <ul>
            <li>Name: "Okta Verify for macOS"</li>
            <li>Description: "Okta Verify authenticator for Desktop MFA and Platform SSO"</li>
            <li>Publisher: Okta, Inc.</li>
          </ul>
        </li>
      </ol>

      <h4>Step 3: Detection Rules</h4>
      <p>Set detection criteria:</p>
      <ul>
        <li>Detection rule: <strong>App is installed</strong></li>
        <li>Bundle ID: <code>com.okta.OktaVerify</code></li>
        <li>Minimum version: (optional, specify if version enforcement needed)</li>
      </ul>

      <h4>Step 4: Assign to Devices</h4>
      <ol>
        <li>Assign app to target macOS groups</li>
        <li>Assignment type: <strong>Required</strong></li>
        <li>Add assignment filter: Devices with Desktop MFA or Platform SSO profile installed</li>
      </ol>

      <h3>Policy Templates</h3>

      <h4>Windows Desktop MFA - Complete Registry Configuration</h4>
      <pre><code>Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Okta\\DeviceAccess]
"OrgUrl"="https://yourorg.okta.com"
"ClientId"="0oa1abc2def3GHI4jklm"
"ClientSecret"="YOUR_CLIENT_SECRET"
"OfflineLoginEnabled"=dword:00000001
"GracePeriodHours"=dword:00000048
"RecoveryPINEnabled"=dword:00000001
"PasswordResetEnabled"=dword:00000001
"AllowedFactors"="push,totp,webauthn"</code></pre>

      <h4>macOS Complete Configuration Example</h4>
      <p>Reference the .mobileconfig example provided in the macOS Desktop MFA Configuration section above.</p>

      <h3>Device Compliance Integration</h3>
      <p>Combine Okta Device Access with Intune compliance policies for layered security.</p>

      <h4>Create Compliance Policy</h4>
      <ol>
        <li>Navigate to <strong>Devices > Compliance policies</strong></li>
        <li>Click <strong>+ Create Policy</strong></li>
        <li>Platform: <strong>Windows 10 and later</strong> or <strong>macOS</strong></li>
        <li>Add compliance settings:
          <ul>
            <li>Require device encryption: <strong>Yes</strong></li>
            <li>Require firewall: <strong>Yes</strong></li>
            <li>Minimum OS version: <strong>Specify version</strong></li>
          </ul>
        </li>
        <li>Actions for noncompliance: Mark device as noncompliant after 1 day</li>
      </ol>

      <h4>Conditional Access Integration</h4>
      <ol>
        <li>In Azure AD, navigate to <strong>Security > Conditional Access</strong></li>
        <li>Create new policy:
          <ul>
            <li>Users: Target specific groups requiring Desktop MFA</li>
            <li>Cloud apps: All apps (or specific apps)</li>
            <li>Conditions: Device platforms (Windows, macOS)</li>
            <li>Grant controls: Require device to be marked as compliant</li>
          </ul>
        </li>
        <li>This ensures devices with Desktop MFA are also compliant before accessing resources</li>
      </ol>

      <h3>Co-Management Scenarios (Intune + Configuration Manager)</h3>
      <p>For hybrid environments managing devices with both Intune and Configuration Manager:</p>

      <h4>Workload Assignment</h4>
      <ol>
        <li>In Configuration Manager, navigate to <strong>Cloud Attach</strong></li>
        <li>Enable co-management</li>
        <li>Assign workloads:
          <ul>
            <li>Device Configuration: <strong>Intune</strong> (for Desktop MFA profiles)</li>
            <li>Client Apps: <strong>Intune</strong> (for Okta Verify deployment)</li>
            <li>Compliance Policies: <strong>Intune</strong></li>
          </ul>
        </li>
      </ol>

      <h4>Deployment Strategy</h4>
      <ol>
        <li>Use Intune for configuration profiles and Okta Verify app deployment</li>
        <li>Use Configuration Manager for initial device provisioning and OS updates</li>
        <li>Monitor deployment status in both consoles</li>
      </ol>

      <h3>Testing and Validation</h3>

      <h4>Windows Validation</h4>
      <pre><code># Check registry configuration
Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Okta\\DeviceAccess"

# Verify Okta Verify installation
Get-Package -Name "Okta Verify"

# Check credential provider registration
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers"

# Test Okta connectivity
Test-NetConnection -ComputerName yourorg.okta.com -Port 443</code></pre>

      <h4>macOS Validation</h4>
      <pre><code># Check configuration profile
sudo profiles show | grep -A 10 "com.okta.deviceaccess"

# Verify configuration values
defaults read /Library/Managed\ Preferences/com.okta.deviceaccess.servicedaemon

# Check Okta Verify installation
ls -la "/Applications/Okta Verify.app"

# Verify Platform SSO profile
sudo profiles show | grep -A 10 "com.apple.extensiblesso"</code></pre>

      <h4>End-User Testing</h4>
      <ol>
        <li><strong>Windows:</strong> Log out and test credential provider at Ctrl+Alt+Del screen</li>
        <li><strong>macOS:</strong> Log out and verify MFA prompt appears at login window</li>
        <li>Complete MFA challenge with push notification or TOTP</li>
        <li>Verify successful authentication and desktop access</li>
      </ol>

      <h3>Common Issues and Resolutions</h3>

      <h4>1. Profile Installation Delays</h4>
      <p><strong>Problem:</strong> Configuration profiles take hours to apply</p>
      <p><strong>Symptoms:</strong> Devices don't receive profiles; Intune portal shows "Pending"</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Force device sync from Intune portal or device settings</li>
          <li>Windows: Settings > Accounts > Access work or school > Sync</li>
          <li>macOS: Open Company Portal app > Sync device</li>
          <li>Check device compliance and enrollment status</li>
        </ul>
      </p>

      <h4>2. App Deployment Failures</h4>
      <p><strong>Problem:</strong> Okta Verify fails to install</p>
      <p><strong>Symptoms:</strong> Installation error in Intune logs; app not present on device</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Verify device has sufficient disk space</li>
          <li>Check installation command syntax</li>
          <li>Review Intune Management Extension logs (Windows)</li>
          <li>Verify detection rules are correct</li>
          <li>Test manual installation on test device</li>
        </ul>
      </p>

      <h4>3. Sync Delays Between Azure AD and Intune</h4>
      <p><strong>Problem:</strong> Group membership changes don't reflect in policy assignments</p>
      <p><strong>Symptoms:</strong> Devices in target groups don't receive profiles</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Azure AD sync can take up to 24 hours</li>
          <li>Use dynamic device groups for faster targeting</li>
          <li>Force sync from Azure AD Connect (if using hybrid join)</li>
          <li>Verify group membership in Azure AD portal</li>
        </ul>
      </p>

      <h4>4. macOS Installation Order Issues</h4>
      <p><strong>Problem:</strong> Okta Verify installed before configuration profile</p>
      <p><strong>Symptoms:</strong> Desktop MFA doesn't activate; standard login only</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Use assignment filters to enforce deployment order</li>
          <li>Create dynamic group: "Desktop MFA Profile Installed"</li>
          <li>Assign Okta Verify app only to devices in this group</li>
          <li>Uninstall and reinstall Okta Verify if already installed</li>
        </ul>
      </p>

      <h4>5. Windows Credential Provider Not Appearing</h4>
      <p><strong>Problem:</strong> Standard Windows login shown; no Okta option</p>
      <p><strong>Symptoms:</strong> Registry keys present but credential provider inactive</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Verify Okta Verify service is running: <code>Get-Service OktaVerify*</code></li>
          <li>Check Event Viewer for credential provider errors</li>
          <li>Ensure registry permissions allow system read access</li>
          <li>Restart device after Okta Verify installation</li>
        </ul>
      </p>

      <h3>Troubleshooting Resources</h3>

      <h4>Windows Diagnostic Logs</h4>
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Log Location</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Okta Verify</td>
            <td><code>C:\\ProgramData\\Okta\\OktaVerify\\Logs</code></td>
          </tr>
          <tr>
            <td>Credential Provider</td>
            <td>Event Viewer > Windows Logs > System (filter for Okta)</td>
          </tr>
          <tr>
            <td>Intune Management Extension</td>
            <td><code>C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs</code></td>
          </tr>
          <tr>
            <td>App Installation</td>
            <td>Event Viewer > Applications and Services > Microsoft > Windows > AppXDeployment</td>
          </tr>
        </tbody>
      </table>

      <h4>macOS Diagnostic Logs</h4>
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Log Location</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Desktop MFA Service</td>
            <td><code>/Library/Logs/Okta/DesktopAccess/</code></td>
          </tr>
          <tr>
            <td>Okta Verify</td>
            <td><code>~/Library/Logs/Okta/OktaVerify.log</code></td>
          </tr>
          <tr>
            <td>Intune Management</td>
            <td><code>/Library/Logs/Microsoft/Intune/</code></td>
          </tr>
          <tr>
            <td>Platform SSO Extension</td>
            <td>Console.app (filter: subsystem:com.okta)</td>
          </tr>
        </tbody>
      </table>

      <h4>Intune Portal Diagnostics</h4>
      <ol>
        <li>Navigate to <strong>Devices > All devices</strong></li>
        <li>Select target device</li>
        <li>Check <strong>Device configuration</strong> status for profile deployment</li>
        <li>Check <strong>Managed Apps</strong> status for Okta Verify installation</li>
        <li>Use <strong>Collect diagnostics</strong> to gather device logs</li>
      </ol>

      <h3>Support Resources</h3>
      <ul>
        <li><strong>Okta Help Center:</strong> <a href="https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm">Device Access Documentation</a></li>
        <li><strong>Microsoft Intune Documentation:</strong> <a href="https://learn.microsoft.com/en-us/mem/intune/">Intune Admin Guide</a></li>
        <li><strong>Okta Community:</strong> <a href="https://support.okta.com/help/s/">Okta Support Portal</a></li>
        <li><strong>Microsoft Endpoint Manager Admin Center:</strong> <a href="https://intune.microsoft.com">Intune Portal</a></li>
      </ul>
    `,
    summary: 'Comprehensive Microsoft Intune deployment guide covering prerequisites, Windows Desktop MFA, macOS Desktop MFA, Platform SSO setup, Okta Verify deployment for both platforms, compliance integration, co-management scenarios, testing procedures, and troubleshooting for Okta Device Access.',
    category: 'integration',
    tags: ['intune', 'microsoft', 'mdm', 'deployment', 'configuration', 'desktop mfa', 'platform sso', 'windows', 'macos', 'azure ad', 'troubleshooting'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-kandji-guide',
    title: 'Complete Kandji Configuration Guide for Okta Device Access',
    content: `
      <h2>Complete Kandji Configuration Guide for Okta Device Access</h2>
      <p>This comprehensive guide walks through deploying Okta Device Access using Kandji, Apple's modern device management platform. Learn how to use Blueprints, Library Items, and Kandji's automation features to successfully deploy Desktop MFA, Platform SSO, and Okta Verify to your macOS fleet.</p>

      <h3>Prerequisites</h3>
      <p>Before starting, ensure you have:</p>
      <ul>
        <li><strong>Kandji setup:</strong>
          <ul>
            <li>Active Kandji tenant</li>
            <li>Devices enrolled in Kandji via Automated Device Enrollment (ADE) or User-Initiated Enrollment</li>
            <li>Kandji admin access with Library and Blueprint permissions</li>
          </ul>
        </li>
        <li><strong>Okta requirements:</strong>
          <ul>
            <li>Okta Identity Engine (OIE) enabled tenant</li>
            <li>Desktop MFA app created in Okta admin console</li>
            <li>Client ID and Client Secret from Desktop MFA app</li>
            <li>Platform SSO app created (for password sync)</li>
            <li>Authentication policies configured for device access</li>
          </ul>
        </li>
        <li><strong>macOS requirements:</strong> macOS 13.0 (Ventura) or later</li>
        <li><strong>Network access:</strong> Devices must reach Okta endpoints (*.okta.com, *.oktacdn.com)</li>
        <li><strong>Okta Verify package:</strong> Download latest PKG from Okta downloads page</li>
      </ul>

      <h3>Blueprint Strategy</h3>
      <p>Kandji uses Blueprints to assign configurations and apps to devices. Decide on your blueprint approach before deployment.</p>

      <h4>Option 1: Dedicated Okta Device Access Blueprint</h4>
      <p><strong>When to use:</strong> Phased rollout; pilot groups; separate policies for different departments</p>
      <p><strong>Advantages:</strong>
        <ul>
          <li>Isolated configuration for testing</li>
          <li>Easy to remove or modify without affecting other settings</li>
          <li>Clear assignment for pilot users</li>
        </ul>
      </p>
      <p><strong>Setup:</strong>
        <ol>
          <li>Navigate to <strong>Blueprints</strong></li>
          <li>Click <strong>+ New Blueprint</strong></li>
          <li>Name: "Okta Device Access - Pilot"</li>
          <li>Description: "Desktop MFA and Platform SSO for pilot group"</li>
          <li>Assign pilot devices to this blueprint</li>
        </ol>
      </p>

      <h4>Option 2: Shared Blueprint with All Configurations</h4>
      <p><strong>When to use:</strong> Company-wide deployment; all devices receive same configuration</p>
      <p><strong>Advantages:</strong>
        <ul>
          <li>Single blueprint to manage</li>
          <li>Consistent configuration across all devices</li>
          <li>Easier to maintain and update</li>
        </ul>
      </p>
      <p><strong>Setup:</strong>
        <ol>
          <li>Use your existing standard blueprint</li>
          <li>Add Okta Device Access Library Items to this blueprint</li>
          <li>All devices in blueprint receive Okta configuration</li>
        </ol>
      </p>

      <h3>Desktop MFA Library Item Creation</h3>
      <p>Create a Custom Profile Library Item for Desktop MFA configuration.</p>

      <h4>Step 1: Create Custom Profile Library Item</h4>
      <ol>
        <li>Navigate to <strong>Library</strong></li>
        <li>Click <strong>+ Add New</strong></li>
        <li>Select <strong>Custom Profile</strong></li>
        <li>Name: "Okta Desktop MFA Configuration"</li>
        <li>Description: "Configures Desktop MFA for macOS devices"</li>
      </ol>

      <h4>Step 2: Configure Custom Settings</h4>
      <p>In the Custom Profile editor, set the preference domain and upload the complete plist:</p>

      <p><strong>Preference Domain:</strong> <code>com.okta.deviceaccess.servicedaemon</code></p>

      <p><strong>Custom Settings (plist format):</strong></p>
      <pre><code>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
    &lt;key&gt;OrgUrl&lt;/key&gt;
    &lt;string&gt;https://yourorg.okta.com&lt;/string&gt;

    &lt;key&gt;ClientId&lt;/key&gt;
    &lt;string&gt;0oa1abc2def3GHI4jklm&lt;/string&gt;

    &lt;key&gt;ClientSecret&lt;/key&gt;
    &lt;string&gt;YOUR_CLIENT_SECRET_HERE&lt;/string&gt;

    &lt;key&gt;AllowedFactors&lt;/key&gt;
    &lt;array&gt;
        &lt;string&gt;push&lt;/string&gt;
        &lt;string&gt;totp&lt;/string&gt;
        &lt;string&gt;password&lt;/string&gt;
        &lt;string&gt;webauthn&lt;/string&gt;
    &lt;/array&gt;

    &lt;key&gt;OfflineLoginSettings&lt;/key&gt;
    &lt;dict&gt;
        &lt;key&gt;Enabled&lt;/key&gt;
        &lt;true/&gt;
        &lt;key&gt;GracePeriodInHours&lt;/key&gt;
        &lt;integer&gt;72&lt;/integer&gt;
    &lt;/dict&gt;

    &lt;key&gt;RecoveryPIN&lt;/key&gt;
    &lt;dict&gt;
        &lt;key&gt;Enabled&lt;/key&gt;
        &lt;true/&gt;
        &lt;key&gt;MinimumLength&lt;/key&gt;
        &lt;integer&gt;8&lt;/integer&gt;
    &lt;/dict&gt;

    &lt;key&gt;PasswordResetEnabled&lt;/key&gt;
    &lt;true/&gt;
&lt;/dict&gt;
&lt;/plist&gt;</code></pre>

      <h4>Step 3: Configure Audit and Enforce</h4>
      <p>Kandji's Audit and Enforce ensures configuration compliance:</p>
      <ul>
        <li><strong>Audit:</strong> Enabled (checks device for profile presence)</li>
        <li><strong>Enforce:</strong> Enabled (reinstalls profile if removed or modified)</li>
        <li><strong>Frequency:</strong> Every 15 minutes (Kandji default)</li>
      </ul>

      <h4>Step 4: Save and Add to Blueprint</h4>
      <ol>
        <li>Click <strong>Save</strong></li>
        <li>Navigate to your target Blueprint</li>
        <li>Click <strong>Add Library Item</strong></li>
        <li>Search for "Okta Desktop MFA Configuration"</li>
        <li>Add the Library Item to the blueprint</li>
      </ol>

      <h3>Platform SSO Library Item Creation</h3>
      <p>Create a Custom Profile Library Item for Platform SSO configuration.</p>

      <h4>Step 1: Create Custom Profile Library Item</h4>
      <ol>
        <li>Navigate to <strong>Library</strong></li>
        <li>Click <strong>+ Add New</strong></li>
        <li>Select <strong>Custom Profile</strong></li>
        <li>Name: "Okta Platform SSO Configuration"</li>
        <li>Description: "Configures Platform SSO for password sync"</li>
      </ol>

      <h4>Step 2: Upload Platform SSO Profile</h4>
      <p>Create a .mobileconfig file with the following content:</p>

      <pre><code>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
    &lt;key&gt;PayloadContent&lt;/key&gt;
    &lt;array&gt;
        &lt;dict&gt;
            &lt;key&gt;PayloadType&lt;/key&gt;
            &lt;string&gt;com.apple.extensiblesso&lt;/string&gt;

            &lt;key&gt;PayloadVersion&lt;/key&gt;
            &lt;integer&gt;1&lt;/integer&gt;

            &lt;key&gt;PayloadIdentifier&lt;/key&gt;
            &lt;string&gt;com.okta.platformsso&lt;/string&gt;

            &lt;key&gt;PayloadUUID&lt;/key&gt;
            &lt;string&gt;GENERATE-NEW-UUID-HERE&lt;/string&gt;

            &lt;key&gt;PayloadDisplayName&lt;/key&gt;
            &lt;string&gt;Okta Platform SSO&lt;/string&gt;

            &lt;key&gt;ExtensionIdentifier&lt;/key&gt;
            &lt;string&gt;com.okta.macOSExtension&lt;/string&gt;

            &lt;key&gt;TeamIdentifier&lt;/key&gt;
            &lt;string&gt;5G8K6A7738&lt;/string&gt;

            &lt;key&gt;Type&lt;/key&gt;
            &lt;string&gt;Redirect&lt;/string&gt;

            &lt;key&gt;URLs&lt;/key&gt;
            &lt;array&gt;
                &lt;string&gt;https://yourorg.okta.com&lt;/string&gt;
                &lt;string&gt;https://yourorg.okta.com/*&lt;/string&gt;
            &lt;/array&gt;

            &lt;key&gt;ExtensionData&lt;/key&gt;
            &lt;dict&gt;
                &lt;key&gt;organization&lt;/key&gt;
                &lt;string&gt;yourorg&lt;/string&gt;

                &lt;key&gt;client_id&lt;/key&gt;
                &lt;string&gt;0oa1xyz2abc3DEF4ghij&lt;/string&gt;

                &lt;key&gt;redirect_uri&lt;/key&gt;
                &lt;string&gt;com.okta.sso.macos:/callback&lt;/string&gt;

                &lt;key&gt;enable_password_sync&lt;/key&gt;
                &lt;true/&gt;
            &lt;/dict&gt;
        &lt;/dict&gt;
    &lt;/array&gt;

    &lt;key&gt;PayloadDisplayName&lt;/key&gt;
    &lt;string&gt;Okta Platform SSO&lt;/string&gt;

    &lt;key&gt;PayloadIdentifier&lt;/key&gt;
    &lt;string&gt;com.company.okta.platformsso&lt;/string&gt;

    &lt;key&gt;PayloadUUID&lt;/key&gt;
    &lt;string&gt;GENERATE-NEW-UUID-HERE&lt;/string&gt;

    &lt;key&gt;PayloadType&lt;/key&gt;
    &lt;string&gt;Configuration&lt;/string&gt;

    &lt;key&gt;PayloadVersion&lt;/key&gt;
    &lt;integer&gt;1&lt;/integer&gt;
&lt;/dict&gt;
&lt;/plist&gt;</code></pre>

      <p>Upload this .mobileconfig file to the Custom Profile Library Item.</p>

      <h4>Step 3: Configure Audit and Enforce</h4>
      <ul>
        <li><strong>Audit:</strong> Enabled</li>
        <li><strong>Enforce:</strong> Enabled</li>
      </ul>

      <h4>Step 4: Save and Add to Blueprint</h4>
      <ol>
        <li>Click <strong>Save</strong></li>
        <li>Add to the same blueprint as Desktop MFA configuration</li>
      </ol>

      <h3>Okta Verify Deployment</h3>
      <p>Deploy Okta Verify using Kandji's App Catalog or Custom App feature.</p>

      <h4>Option 1: Using Kandji App Catalog (if available)</h4>
      <ol>
        <li>Navigate to <strong>Library</strong></li>
        <li>Search for "Okta Verify" in the App Catalog</li>
        <li>If available, add to your blueprint</li>
        <li>Configure deployment method (Auto Apps or Self Service)</li>
      </ol>

      <h4>Option 2: Custom App Upload</h4>
      <ol>
        <li>Navigate to <strong>Library</strong></li>
        <li>Click <strong>+ Add New</strong></li>
        <li>Select <strong>Custom App</strong></li>
        <li>Name: "Okta Verify"</li>
        <li>Upload the Okta Verify PKG file</li>
      </ol>

      <h4>Step 1: Configure Custom App Settings</h4>
      <ul>
        <li><strong>Install Type:</strong> Package (.pkg)</li>
        <li><strong>Self Service:</strong> No (deploy automatically)</li>
        <li><strong>Self Heal:</strong> Enabled (reinstalls if removed)</li>
      </ul>

      <h4>Step 2: Set Installation Requirements</h4>
      <p>Configure installation prerequisites to ensure proper deployment order:</p>
      <ul>
        <li><strong>Dependencies:</strong> Add "Okta Desktop MFA Configuration" profile as prerequisite</li>
        <li><strong>Installation Context:</strong> System (install for all users)</li>
        <li><strong>Restart Required:</strong> No</li>
      </ul>

      <h4>Step 3: Save and Add to Blueprint</h4>
      <ol>
        <li>Click <strong>Save</strong></li>
        <li>Navigate to your target Blueprint</li>
        <li>Add the Okta Verify Custom App to the blueprint</li>
        <li><strong>Critical:</strong> Ensure Okta Verify Library Item appears AFTER Desktop MFA profile in blueprint order</li>
      </ol>

      <h3>Configuration Sequence</h3>
      <p>Proper deployment sequence is critical. Kandji processes Library Items in blueprint order.</p>

      <h4>Recommended Blueprint Order</h4>
      <ol>
        <li><strong>Position 1:</strong> Okta Desktop MFA Configuration (Custom Profile)</li>
        <li><strong>Position 2:</strong> Okta Platform SSO Configuration (Custom Profile) - optional</li>
        <li><strong>Position 3:</strong> Okta Verify (Custom App or App Catalog)</li>
      </ol>

      <h4>Adjusting Library Item Order</h4>
      <ol>
        <li>Navigate to Blueprint</li>
        <li>Click <strong>Edit</strong></li>
        <li>Drag Library Items to reorder them</li>
        <li>Ensure profiles are before Okta Verify</li>
        <li>Save blueprint changes</li>
      </ol>

      <h3>Auto Apps vs Self Service Deployment</h3>
      <p>Kandji offers two deployment methods for applications:</p>

      <h4>Auto Apps (Recommended for ODA)</h4>
      <p><strong>How it works:</strong> Apps install automatically when device checks in</p>
      <p><strong>Advantages:</strong>
        <ul>
          <li>No user interaction required</li>
          <li>Guaranteed deployment for all devices in blueprint</li>
          <li>Consistent rollout timing</li>
        </ul>
      </p>
      <p><strong>Use for:</strong> Desktop MFA profiles, Platform SSO profiles, Okta Verify app</p>

      <h4>Self Service</h4>
      <p><strong>How it works:</strong> Users install from Self Service app</p>
      <p><strong>Advantages:</strong>
        <ul>
          <li>User controls installation timing</li>
          <li>Reduces helpdesk calls if users have issues</li>
        </ul>
      </p>
      <p><strong>Use for:</strong> Optional tools, user-facing apps not critical for security</p>
      <p><strong>Not recommended for ODA:</strong> Desktop MFA should deploy automatically to ensure security compliance</p>

      <h3>Device Assignment and Scoping</h3>
      <p>Control which devices receive Okta Device Access configuration using blueprint assignment.</p>

      <h4>Assignment by Device Name</h4>
      <ol>
        <li>Navigate to <strong>Devices</strong></li>
        <li>Select target devices</li>
        <li>Click <strong>Actions > Assign Blueprint</strong></li>
        <li>Choose "Okta Device Access - Pilot"</li>
      </ol>

      <h4>Assignment by Blueprint Rules</h4>
      <ol>
        <li>Navigate to Blueprint</li>
        <li>Click <strong>Assignment Rules</strong></li>
        <li>Configure automatic assignment criteria:
          <ul>
            <li>Device name contains "LAPTOP"</li>
            <li>User email contains "@company.com"</li>
            <li>macOS version is 13.0 or later</li>
          </ul>
        </li>
        <li>Save assignment rules</li>
      </ol>

      <h4>Pilot Group Strategy</h4>
      <p>For phased rollout, use multiple blueprints:</p>
      <ol>
        <li><strong>Blueprint 1:</strong> "Okta Device Access - IT Pilot" (IT department devices)</li>
        <li><strong>Blueprint 2:</strong> "Okta Device Access - Wave 1" (early adopters)</li>
        <li><strong>Blueprint 3:</strong> "Okta Device Access - Production" (company-wide)</li>
        <li>Migrate devices between blueprints as rollout progresses</li>
      </ol>

      <h3>Testing and Validation</h3>
      <p>After deployment, validate each component on pilot devices.</p>

      <h4>1. Verify Profile Installation in Kandji Portal</h4>
      <ol>
        <li>Navigate to <strong>Devices</strong></li>
        <li>Select a pilot device</li>
        <li>Click <strong>Details</strong> tab</li>
        <li>Scroll to <strong>Configuration Profiles</strong></li>
        <li>Verify "Okta Desktop MFA Configuration" shows status: <strong>Installed</strong></li>
        <li>Verify "Okta Platform SSO Configuration" shows status: <strong>Installed</strong></li>
      </ol>

      <h4>2. Verify Okta Verify Installation</h4>
      <ol>
        <li>In device details, check <strong>Applications</strong> section</li>
        <li>Verify "Okta Verify" appears with version number</li>
        <li>Status should show: <strong>Installed</strong></li>
      </ol>

      <h4>3. Device-Side Validation</h4>
      <pre><code># On managed Mac, check profiles
sudo profiles show | grep -A 10 "com.okta.deviceaccess"

# Verify configuration values
defaults read /Library/Managed\ Preferences/com.okta.deviceaccess.servicedaemon

# Check Okta Verify installation
ls -la "/Applications/Okta Verify.app"

# Check Platform SSO profile
sudo profiles show | grep -A 10 "com.apple.extensiblesso"

# Verify Kandji agent status
sudo launchctl list | grep io.kandji</code></pre>

      <h4>4. Test User Sign-In</h4>
      <ol>
        <li>Log out of test Mac</li>
        <li>At login screen, enter username and password</li>
        <li>Verify MFA prompt appears (push or TOTP)</li>
        <li>Complete authentication</li>
        <li>Verify successful login</li>
      </ol>

      <h4>5. Test Platform SSO Registration (if deployed)</h4>
      <ol>
        <li>Log in to macOS with local credentials</li>
        <li>Platform SSO should prompt for Okta authentication</li>
        <li>Complete Okta sign-in with MFA</li>
        <li>Device registers to Okta Verify account</li>
        <li>Verify FastPass enrollment in Okta admin console</li>
      </ol>

      <h3>Common Pitfalls and Solutions</h3>

      <h4>1. Blueprint Scope Too Broad</h4>
      <p><strong>Problem:</strong> Okta Device Access deployed to entire fleet before testing complete</p>
      <p><strong>Symptoms:</strong> Widespread login issues; helpdesk overwhelmed</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Create dedicated pilot blueprint</li>
          <li>Assign only test devices initially</li>
          <li>Use assignment rules to limit scope</li>
          <li>Gradually expand after successful testing</li>
        </ul>
      </p>

      <h4>2. Install Timing Issues</h4>
      <p><strong>Problem:</strong> Okta Verify installs before configuration profile</p>
      <p><strong>Symptoms:</strong> Desktop MFA doesn't activate; standard login only</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Reorder Library Items in blueprint (profiles first)</li>
          <li>Use Dependencies feature on Okta Verify Custom App</li>
          <li>Enable Self Heal to reinstall if removed</li>
          <li>Force device check-in to retry installation sequence</li>
        </ul>
      </p>

      <h4>3. Version Conflicts</h4>
      <p><strong>Problem:</strong> Older version of Okta Verify installed; new features not available</p>
      <p><strong>Symptoms:</strong> Platform SSO doesn't work; missing functionality</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Update Custom App in Library with latest Okta Verify PKG</li>
          <li>Increment version number in Library Item</li>
          <li>Kandji will automatically update installed apps</li>
          <li>Monitor deployment status in device details</li>
        </ul>
      </p>

      <h4>4. Audit and Enforce Too Aggressive</h4>
      <p><strong>Problem:</strong> Users experiencing repeated profile installations during testing</p>
      <p><strong>Symptoms:</strong> Notifications about profile updates; login disruptions</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>During pilot, set Enforce frequency to longer intervals (e.g., daily)</li>
          <li>After stable deployment, increase frequency to 15 minutes</li>
          <li>Communicate expected behavior to pilot users</li>
        </ul>
      </p>

      <h4>5. Missing Preferences Domain</h4>
      <p><strong>Problem:</strong> Custom profile created without specifying preference domain</p>
      <p><strong>Symptoms:</strong> Configuration not applied; Okta can't read settings</p>
      <p><strong>Solution:</strong>
        <ul>
          <li>Edit Custom Profile Library Item</li>
          <li>Verify Preference Domain field shows: <code>com.okta.deviceaccess.servicedaemon</code></li>
          <li>Re-save and redeploy profile</li>
        </ul>
      </p>

      <h3>Troubleshooting Guide</h3>

      <h4>Kandji Agent Status Check</h4>
      <pre><code># Check Kandji agent running status
sudo launchctl list | grep io.kandji

# Force Kandji agent check-in
sudo kandji check-in

# View Kandji agent logs
sudo log show --predicate 'subsystem == "io.kandji.kandji"' --last 1h</code></pre>

      <h4>Deployment Status Verification</h4>
      <ol>
        <li>In Kandji portal, navigate to <strong>Devices > [Target Device]</strong></li>
        <li>Click <strong>Activity</strong> tab</li>
        <li>Review recent deployment events:
          <ul>
            <li>"Profile installed: Okta Desktop MFA Configuration"</li>
            <li>"App installed: Okta Verify"</li>
          </ul>
        </li>
        <li>Check for errors or warnings in activity log</li>
      </ol>

      <h4>Profile Verification Commands</h4>
      <pre><code># List all installed profiles
sudo profiles show

# Check specific Okta profiles
sudo profiles show | grep -i okta

# Verify configuration values
defaults read /Library/Managed\ Preferences/com.okta.deviceaccess.servicedaemon

# Check Platform SSO registration
sfltool dumpbtm</code></pre>

      <h4>Common Error Messages</h4>
      <table>
        <thead>
          <tr>
            <th>Error</th>
            <th>Cause</th>
            <th>Resolution</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>"Profile installation failed"</td>
            <td>Malformed plist or missing keys</td>
            <td>Validate plist syntax; verify all required keys present</td>
          </tr>
          <tr>
            <td>"App installation pending"</td>
            <td>Device hasn't checked in yet</td>
            <td>Force check-in with <code>sudo kandji check-in</code></td>
          </tr>
          <tr>
            <td>"Configuration not found"</td>
            <td>Desktop MFA profile not installed or missing preference domain</td>
            <td>Verify profile installation; check preference domain setting</td>
          </tr>
          <tr>
            <td>"Dependency not met"</td>
            <td>Prerequisite Library Item not installed</td>
            <td>Check blueprint order; verify dependencies configured correctly</td>
          </tr>
        </tbody>
      </table>

      <h4>Kandji Diagnostic Logs</h4>
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Log Location / Command</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Kandji Agent</td>
            <td><code>sudo log show --predicate 'subsystem == "io.kandji.kandji"' --last 2h</code></td>
          </tr>
          <tr>
            <td>Profile Installation</td>
            <td><code>/var/log/install.log</code></td>
          </tr>
          <tr>
            <td>Okta Desktop MFA</td>
            <td><code>/Library/Logs/Okta/DesktopAccess/</code></td>
          </tr>
          <tr>
            <td>Okta Verify</td>
            <td><code>~/Library/Logs/Okta/OktaVerify.log</code></td>
          </tr>
        </tbody>
      </table>

      <h4>Force Reinstallation</h4>
      <p>If configuration or app deployment fails, force reinstallation:</p>
      <ol>
        <li>In Kandji portal, navigate to device</li>
        <li>Click <strong>Actions > Reinstall Library Item</strong></li>
        <li>Select the failing Library Item</li>
        <li>Confirm reinstallation</li>
        <li>Monitor Activity tab for completion</li>
      </ol>

      <h3>Advanced Configurations</h3>

      <h4>Custom Recovery PIN Settings</h4>
      <p>Enhance recovery options by configuring advanced PIN settings:</p>
      <pre><code>&lt;key&gt;RecoveryPIN&lt;/key&gt;
&lt;dict&gt;
    &lt;key&gt;Enabled&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;MinimumLength&lt;/key&gt;
    &lt;integer&gt;8&lt;/integer&gt;

    &lt;key&gt;RequireAlphanumeric&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;RequireSpecialCharacter&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;ExpirationDays&lt;/key&gt;
    &lt;integer&gt;90&lt;/integer&gt;
&lt;/dict&gt;</code></pre>

      <h4>Offline Login with Extended Grace Period</h4>
      <pre><code>&lt;key&gt;OfflineLoginSettings&lt;/key&gt;
&lt;dict&gt;
    &lt;key&gt;Enabled&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;GracePeriodInHours&lt;/key&gt;
    &lt;integer&gt;168&lt;/integer&gt;  &lt;!-- 7 days for remote workers --&gt;

    &lt;key&gt;RequireOnlineAuthenticationAfterGracePeriod&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;AllowOfflineFactors&lt;/key&gt;
    &lt;array&gt;
        &lt;string&gt;totp&lt;/string&gt;
        &lt;string&gt;password&lt;/string&gt;
    &lt;/array&gt;
&lt;/dict&gt;</code></pre>

      <h4>Restricted Factor List for High-Security Environments</h4>
      <pre><code>&lt;key&gt;AllowedFactors&lt;/key&gt;
&lt;array&gt;
    &lt;string&gt;push&lt;/string&gt;
    &lt;string&gt;webauthn&lt;/string&gt;
    &lt;!-- Only push and FIDO2; no password or TOTP --&gt;
&lt;/array&gt;</code></pre>

      <h3>Support Resources</h3>
      <ul>
        <li><strong>Okta Help Center:</strong> <a href="https://help.okta.com/oie/en-us/content/topics/oda/oda-overview.htm">Device Access Documentation</a></li>
        <li><strong>Kandji Documentation:</strong> <a href="https://support.kandji.io">Kandji Support Portal</a></li>
        <li><strong>Kandji Community:</strong> <a href="https://community.kandji.io">Kandji Community Forums</a></li>
        <li><strong>Okta Community:</strong> <a href="https://support.okta.com/help/s/">Okta Support Portal</a></li>
      </ul>
    `,
    summary: 'Comprehensive Kandji deployment guide covering prerequisites, blueprint strategies, Desktop MFA configuration, Platform SSO setup, Okta Verify deployment, configuration sequencing, Auto Apps vs Self Service, device assignment, testing procedures, common pitfalls, and troubleshooting for Okta Device Access.',
    category: 'integration',
    tags: ['kandji', 'mdm', 'deployment', 'configuration', 'desktop mfa', 'platform sso', 'okta verify', 'blueprints', 'library items', 'troubleshooting'],
    source: 'internal',
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
