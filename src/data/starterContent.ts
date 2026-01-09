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
  {
    id: 'se-integration-patterns',
    title: 'Integration Patterns and Architecture for Okta Device Access',
    content: `
      <h2>Overview</h2>
      <p>This guide covers integration patterns and architectural considerations for deploying Okta Device Access in complex enterprise environments.</p>

      <h2>Active Directory Integration Patterns</h2>

      <h3>Single Forest Architecture</h3>
      <p>The simplest AD integration pattern for Okta Device Access.</p>
      <ul>
        <li><strong>Components:</strong> Single AD forest, Okta AD agent, password writeback</li>
        <li><strong>User flow:</strong> Users authenticate to Okta, password syncs to AD, device auth uses synced credentials</li>
        <li><strong>Best for:</strong> Single-domain organizations, simple AD structures</li>
        <li><strong>Considerations:</strong> Ensure AD agent has write permissions, configure password policies</li>
      </ul>

      <h3>Multi-Forest Architecture</h3>
      <p>Handling multiple AD forests with different trust relationships.</p>
      <ul>
        <li><strong>Forest trusts:</strong> Configure Okta AD agents in each forest</li>
        <li><strong>User matching:</strong> Use UPN or email for cross-forest user resolution</li>
        <li><strong>Password sync:</strong> Each forest requires separate writeback configuration</li>
        <li><strong>Policy considerations:</strong> Different policies per forest if needed</li>
        <li><strong>Best practices:</strong> Test cross-forest authentication flows thoroughly</li>
      </ul>

      <h3>Azure AD Hybrid Architecture</h3>
      <p>Combining on-prem AD with Azure AD (Entra ID).</p>
      <ul>
        <li><strong>Azure AD Connect:</strong> Syncs identities between on-prem and cloud</li>
        <li><strong>Password hash sync:</strong> Options for password sync vs pass-through auth</li>
        <li><strong>Okta integration:</strong> Can federate with Azure AD or sync directly from AD</li>
        <li><strong>Device join:</strong> Consider Azure AD join vs hybrid join scenarios</li>
        <li><strong>Recommendation:</strong> Okta as primary IdP, sync to both AD and Azure AD</li>
      </ul>

      <h3>No Active Directory (Cloud-Only)</h3>
      <p>Modern approach without traditional AD dependency.</p>
      <ul>
        <li><strong>Okta as source of truth:</strong> User identities mastered in Okta</li>
        <li><strong>Local account mapping:</strong> JIT account creation for macOS</li>
        <li><strong>Windows considerations:</strong> Azure AD join or local accounts</li>
        <li><strong>Benefits:</strong> Simplified architecture, cloud-native approach</li>
        <li><strong>Migration path:</strong> Gradual reduction of AD dependency</li>
      </ul>

      <h2>Network Architecture Patterns</h2>

      <h3>Standard Corporate Network</h3>
      <p>Traditional on-premise network with internet access.</p>
      <ul>
        <li><strong>Firewall rules:</strong> Allow outbound HTTPS to *.okta.com, *.oktacdn.com</li>
        <li><strong>Proxy configuration:</strong> Configure Okta Verify to use corporate proxy</li>
        <li><strong>DNS:</strong> Ensure proper resolution of Okta endpoints</li>
        <li><strong>Certificate trust:</strong> Trust Okta CA certificates if using SSL inspection</li>
      </ul>

      <h3>Split-Tunnel VPN Architecture</h3>
      <p>VPN with selective traffic routing.</p>
      <ul>
        <li><strong>Okta traffic:</strong> Route Okta endpoints through direct internet, not VPN tunnel</li>
        <li><strong>Benefits:</strong> Reduced VPN bandwidth, faster authentication</li>
        <li><strong>Configuration:</strong> Add Okta domains to VPN split-tunnel exclusions</li>
        <li><strong>Security:</strong> Ensures device authentication works before VPN connects</li>
      </ul>

      <h3>Full-Tunnel VPN with Device Access</h3>
      <p>All traffic routes through VPN, including Okta.</p>
      <ul>
        <li><strong>Challenge:</strong> Need device auth before VPN connects</li>
        <li><strong>Solution:</strong> Configure offline authentication with grace periods</li>
        <li><strong>Alternative:</strong> Use split-tunnel for Okta endpoints only</li>
        <li><strong>Offline factors:</strong> Enable TOTP or offline PIN for connectivity loss</li>
      </ul>

      <h3>Multi-Region Global Deployment</h3>
      <p>Distributed workforce across multiple geographic regions.</p>
      <ul>
        <li><strong>Okta cells:</strong> Use Okta's global infrastructure for low latency</li>
        <li><strong>Data residency:</strong> Consider EMEA, APAC, or US-based Okta orgs if required</li>
        <li><strong>MDM distribution:</strong> Deploy MDM servers regionally if possible</li>
        <li><strong>Network paths:</strong> Optimize routes to nearest Okta POP</li>
        <li><strong>Offline support:</strong> Critical for users traveling between regions</li>
      </ul>

      <h2>Okta Workflows Integration</h2>

      <h3>Automated Device Provisioning</h3>
      <p>Use Workflows to automate device onboarding.</p>
      <ul>
        <li><strong>Trigger:</strong> New device registration in Okta</li>
        <li><strong>Actions:</strong> Create ServiceNow ticket, send welcome email, add to groups</li>
        <li><strong>Use case:</strong> Track new device activations, automate provisioning tasks</li>
      </ul>

      <h3>Password Sync Notifications</h3>
      <p>Alert users when password sync events occur.</p>
      <ul>
        <li><strong>Trigger:</strong> Password change detected</li>
        <li><strong>Actions:</strong> Send Slack/email notification, log to SIEM</li>
        <li><strong>Use case:</strong> Security monitoring, user communication</li>
      </ul>

      <h3>Device Compliance Automation</h3>
      <p>Enforce device compliance with automated workflows.</p>
      <ul>
        <li><strong>Trigger:</strong> Device fails compliance check</li>
        <li><strong>Actions:</strong> Remove from privileged groups, alert IT, create ticket</li>
        <li><strong>Use case:</strong> Automated security posture management</li>
      </ul>

      <h2>API Integration Patterns</h2>

      <h3>Device Registration API</h3>
      <p>Programmatically manage device registrations.</p>
      <pre><code>GET /api/v1/devices
POST /api/v1/devices/{deviceId}/lifecycle/activate
DELETE /api/v1/devices/{deviceId}</code></pre>
      <ul>
        <li><strong>Use cases:</strong> Custom device inventory, bulk device management</li>
        <li><strong>Authentication:</strong> API token with device management permissions</li>
      </ul>

      <h3>Authentication Policy API</h3>
      <p>Manage device authentication policies programmatically.</p>
      <pre><code>GET /api/v1/policies
PUT /api/v1/policies/{policyId}
POST /api/v1/policies/{policyId}/rules</code></pre>
      <ul>
        <li><strong>Use cases:</strong> Dynamic policy updates, compliance enforcement</li>
        <li><strong>Automation:</strong> Change policies based on threat intelligence</li>
      </ul>

      <h3>Event Hooks for Device Events</h3>
      <p>Real-time notifications for device authentication events.</p>
      <ul>
        <li><strong>Events:</strong> device.enrollment, device.authentication, device.deactivation</li>
        <li><strong>Webhook endpoint:</strong> Send events to SIEM, logging platform</li>
        <li><strong>Use cases:</strong> Security monitoring, compliance reporting</li>
      </ul>

      <h2>High Availability Architecture</h2>

      <h3>Okta Service Availability</h3>
      <ul>
        <li><strong>SLA:</strong> 99.99% uptime guarantee</li>
        <li><strong>Redundancy:</strong> Multi-region redundant infrastructure</li>
        <li><strong>Failover:</strong> Automatic failover between availability zones</li>
        <li><strong>Status:</strong> Monitor at trust.okta.com</li>
      </ul>

      <h3>On-Premise Component HA</h3>
      <ul>
        <li><strong>AD Agents:</strong> Deploy multiple agents for redundancy</li>
        <li><strong>Load balancing:</strong> Agents automatically load balance</li>
        <li><strong>Health monitoring:</strong> Monitor agent health in Okta admin console</li>
      </ul>

      <h3>MDM High Availability</h3>
      <ul>
        <li><strong>Jamf Pro:</strong> Clustered deployment with load balancer</li>
        <li><strong>Intune:</strong> Microsoft-managed, globally redundant</li>
        <li><strong>Kandji:</strong> Cloud-hosted with built-in redundancy</li>
      </ul>

      <h2>Disaster Recovery Patterns</h2>

      <h3>Offline Access During Outages</h3>
      <ul>
        <li><strong>Cached credentials:</strong> Users can sign in during Okta outage</li>
        <li><strong>Grace periods:</strong> Configure appropriate offline windows</li>
        <li><strong>Offline factors:</strong> TOTP continues to work without connectivity</li>
        <li><strong>Recovery:</strong> Automatic sync when service restored</li>
      </ul>

      <h3>Backup Authentication Methods</h3>
      <ul>
        <li><strong>Local admin accounts:</strong> Maintain break-glass accounts</li>
        <li><strong>Recovery PINs:</strong> Generate before extended travel</li>
        <li><strong>Multiple factors:</strong> Enroll backup factors for redundancy</li>
      </ul>

      <h3>Data Backup and Recovery</h3>
      <ul>
        <li><strong>Okta config:</strong> Use Terraform or API to backup policies</li>
        <li><strong>User data:</strong> Regular exports of user and device data</li>
        <li><strong>MDM profiles:</strong> Version control configuration profiles</li>
      </ul>

      <h2>Security Architecture Patterns</h2>

      <h3>Zero Trust Architecture Integration</h3>
      <ul>
        <li><strong>Device trust:</strong> Okta Device Access provides device identity</li>
        <li><strong>Conditional access:</strong> Use device signals in access policies</li>
        <li><strong>Continuous verification:</strong> Re-authenticate at device and app level</li>
        <li><strong>Least privilege:</strong> Grant access based on device+user+context</li>
      </ul>

      <h3>Defense in Depth</h3>
      <ul>
        <li><strong>Layer 1:</strong> Device-level MFA (Okta Device Access)</li>
        <li><strong>Layer 2:</strong> Network access controls (VPN, firewall)</li>
        <li><strong>Layer 3:</strong> Application-level MFA (Okta SSO)</li>
        <li><strong>Layer 4:</strong> Data encryption (FileVault, BitLocker)</li>
        <li><strong>Layer 5:</strong> Monitoring and detection (SIEM, EDR)</li>
      </ul>

      <h3>Compliance Architecture</h3>
      <ul>
        <li><strong>Audit logging:</strong> All device auth events to Okta System Log</li>
        <li><strong>SIEM integration:</strong> Forward logs to Splunk, Azure Sentinel, etc.</li>
        <li><strong>Retention:</strong> Configure log retention per compliance requirements</li>
        <li><strong>Reporting:</strong> Build compliance dashboards from Okta data</li>
      </ul>

      <h2>Best Practices</h2>

      <h3>Architecture Planning</h3>
      <ul>
        <li>Document current state before designing future state</li>
        <li>Consider scalability and growth in design</li>
        <li>Plan for failure scenarios and disaster recovery</li>
        <li>Involve security, networking, and identity teams early</li>
      </ul>

      <h3>Integration Sequencing</h3>
      <ol>
        <li>Set up identity source integration (AD, Azure AD)</li>
        <li>Configure MDM and enroll test devices</li>
        <li>Deploy Okta Verify to test devices</li>
        <li>Configure and test Desktop MFA policies</li>
        <li>Configure and test Platform SSO (macOS)</li>
        <li>Validate authentication flows end-to-end</li>
        <li>Test failure scenarios and offline access</li>
        <li>Deploy to pilot group</li>
      </ol>

      <h3>Performance Optimization</h3>
      <ul>
        <li>Use split-tunnel VPN for Okta traffic</li>
        <li>Deploy AD agents close to domain controllers</li>
        <li>Configure appropriate offline grace periods</li>
        <li>Monitor authentication latency in Okta logs</li>
        <li>Optimize network paths to Okta endpoints</li>
      </ul>
    `,
    summary: 'Comprehensive integration patterns and architecture guide covering Active Directory integration (single/multi-forest, hybrid, cloud-only), network architectures (VPN, multi-region, HA/DR), Okta Workflows automation, API integrations, security patterns, and best practices for Okta Device Access.',
    category: 'architecture',
    tags: ['integration', 'architecture', 'active directory', 'azure ad', 'network', 'workflows', 'api', 'high availability', 'disaster recovery', 'zero trust'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-hands-on-labs',
    title: 'Hands-On Labs for Okta Device Access',
    category: 'labs',
    content: `
      <h1>Hands-On Labs for Okta Device Access</h1>

      <div class="info-box">
        <h3>About These Labs</h3>
        <p>These hands-on labs provide practical experience with Okta Device Access features. Each lab includes learning objectives, prerequisites, step-by-step instructions, and validation procedures. Complete these labs in sequence for the best learning experience.</p>
      </div>

      <h2>Sandbox Environment Setup</h2>

      <h3>Required Components</h3>

      <h4>1. Okta Trial Organization</h4>
      <ul>
        <li><strong>Sign up:</strong> Visit <code>developer.okta.com</code> and create a free developer account</li>
        <li><strong>Required licenses:</strong> Ensure Okta Identity Governance (OIG) and Okta Verify are enabled</li>
        <li><strong>Admin access:</strong> You'll need Super Administrator privileges</li>
        <li><strong>Domain:</strong> Note your Okta domain (e.g., <code>dev-123456.okta.com</code>)</li>
      </ul>

      <h4>2. Test Devices</h4>
      <ul>
        <li><strong>macOS:</strong> macOS 13+ (Ventura or later) for Platform SSO support</li>
        <li><strong>Windows:</strong> Windows 10/11 Professional or Enterprise edition</li>
        <li><strong>Virtual machines:</strong> Can use VMware Fusion, Parallels, or VirtualBox</li>
        <li><strong>Clean state:</strong> Fresh OS installs recommended to avoid conflicts</li>
      </ul>

      <h4>3. MDM Trial Accounts</h4>
      <ul>
        <li><strong>Jamf Pro:</strong> Sign up for Jamf Now trial at <code>jamf.com/products/jamf-now/</code></li>
        <li><strong>Microsoft Intune:</strong> Get trial through Microsoft 365 Business Premium trial</li>
        <li><strong>Alternative:</strong> Use Kandji or Workspace ONE free trials</li>
        <li><strong>Device enrollment:</strong> Enroll test devices in your chosen MDM</li>
      </ul>

      <h4>4. Sample Users</h4>
      <ul>
        <li><strong>Test users:</strong> Create 3-5 test users in Okta (e.g., <code>testuser1@yourdomain.com</code>)</li>
        <li><strong>Groups:</strong> Create groups for phased rollout testing</li>
        <li><strong>Credentials:</strong> Document usernames and passwords securely</li>
        <li><strong>Mobile devices:</strong> Each test user needs a mobile device for Okta Verify enrollment</li>
      </ul>

      <h3>Environment Preparation Checklist</h3>
      <div class="checklist">
        <ul>
          <li>☐ Okta org created and accessible</li>
          <li>☐ Okta Verify license enabled in org</li>
          <li>☐ Test macOS device available (physical or VM)</li>
          <li>☐ Test Windows device available (physical or VM)</li>
          <li>☐ MDM solution selected and trial activated</li>
          <li>☐ Test devices enrolled in MDM</li>
          <li>☐ 3+ test users created in Okta</li>
          <li>☐ Test users have mobile devices for Okta Verify</li>
          <li>☐ Network connectivity confirmed (devices can reach Okta)</li>
          <li>☐ Admin credentials documented securely</li>
        </ul>
      </div>

      <h2>Lab 1: Configure Desktop MFA in Jamf Pro</h2>

      <div class="lab-header">
        <p><strong>Estimated Time:</strong> 45 minutes</p>
        <p><strong>Difficulty:</strong> Beginner</p>
        <p><strong>Platform:</strong> macOS with Jamf Pro</p>
      </div>

      <h3>Learning Objectives</h3>
      <ul>
        <li>Create and deploy a Desktop MFA configuration profile in Jamf Pro</li>
        <li>Configure Okta Verify settings for macOS endpoints</li>
        <li>Test Desktop MFA authentication flow</li>
        <li>Validate successful deployment and functionality</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Completed sandbox environment setup</li>
        <li>macOS device enrolled in Jamf Pro</li>
        <li>Jamf Pro administrator access</li>
        <li>Okta administrator access</li>
        <li>Test user with Okta Verify enrolled on mobile device</li>
      </ul>

      <h3>Materials Needed</h3>
      <ul>
        <li>Okta domain URL</li>
        <li>Jamf Pro admin console access</li>
        <li>macOS test device (physical or VM)</li>
        <li>Mobile device with Okta Verify installed</li>
        <li>Test user credentials</li>
      </ul>

      <h3>Step-by-Step Instructions</h3>

      <h4>Part 1: Configure Okta</h4>

      <div class="step">
        <strong>Step 1.1:</strong> Enable Desktop MFA in Okta
        <ul>
          <li>Log into Okta Admin Console as Super Admin</li>
          <li>Navigate to <strong>Security → Authenticators</strong></li>
          <li>Click <strong>Okta Verify</strong></li>
          <li>Click <strong>Edit</strong> on the configuration</li>
          <li>Ensure <strong>Desktop authentication</strong> is enabled</li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.2:</strong> Create Authentication Policy
        <ul>
          <li>Navigate to <strong>Security → Authentication Policies</strong></li>
          <li>Click <strong>Add a Policy</strong></li>
          <li>Name: "Desktop MFA Policy"</li>
          <li>Assign to: Select your test user group</li>
          <li>Add rule requiring Okta Verify for desktop authentication</li>
          <li>Click <strong>Create Policy</strong></li>
        </ul>
      </div>

      <h4>Part 2: Create Configuration Profile in Jamf</h4>

      <div class="step">
        <strong>Step 2.1:</strong> Access Jamf Pro Configuration Profiles
        <ul>
          <li>Log into Jamf Pro admin console</li>
          <li>Navigate to <strong>Computers → Configuration Profiles</strong></li>
          <li>Click <strong>+ New</strong></li>
          <li>Name: "Okta Desktop MFA Configuration"</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.2:</strong> Add Custom Settings Payload
        <ul>
          <li>Click <strong>Application & Custom Settings</strong></li>
          <li>Click <strong>Configure</strong></li>
          <li>Preference Domain: <code>com.okta.OktaVerify</code></li>
          <li>Click <strong>Add</strong> to upload plist or configure manually</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.3:</strong> Configure Desktop MFA Settings
        <p>Add the following key-value pairs:</p>
        <pre><code>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
    &lt;key&gt;OrgUrl&lt;/key&gt;
    &lt;string&gt;https://your-domain.okta.com&lt;/string&gt;
    &lt;key&gt;EnableDesktopAuth&lt;/key&gt;
    &lt;true/&gt;
    &lt;key&gt;EnabledFactors&lt;/key&gt;
    &lt;array&gt;
        &lt;string&gt;push&lt;/string&gt;
        &lt;string&gt;totp&lt;/string&gt;
    &lt;/array&gt;
    &lt;key&gt;GracePeriodMinutes&lt;/key&gt;
    &lt;integer&gt;60&lt;/integer&gt;
    &lt;key&gt;EnablePasswordSync&lt;/key&gt;
    &lt;false/&gt;
&lt;/dict&gt;
&lt;/plist&gt;</code></pre>
        <p><strong>Note:</strong> Replace <code>your-domain.okta.com</code> with your actual Okta domain</p>
      </div>

      <div class="step">
        <strong>Step 2.4:</strong> Configure Scope
        <ul>
          <li>Click <strong>Scope</strong> tab</li>
          <li>Under <strong>Computers</strong>, add your test device or test device group</li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <h4>Part 3: Deploy and Test</h4>

      <div class="step">
        <strong>Step 3.1:</strong> Verify Profile Installation
        <ul>
          <li>On the test Mac, open <strong>Terminal</strong></li>
          <li>Run: <code>sudo profiles -L</code></li>
          <li>Verify "Okta Desktop MFA Configuration" appears in the list</li>
          <li>Run: <code>sudo profiles show</code> to view full profile details</li>
          <li>Confirm OrgUrl and other settings are correct</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.2:</strong> Install Okta Verify
        <ul>
          <li>Download Okta Verify for macOS from Okta Downloads page</li>
          <li>Install the application</li>
          <li>Launch Okta Verify</li>
          <li>It should auto-detect the org URL from the profile</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.3:</strong> Enroll Device
        <ul>
          <li>In Okta Verify, click <strong>Add Account</strong></li>
          <li>Sign in with test user credentials</li>
          <li>Approve the push notification on the mobile device</li>
          <li>Complete biometric setup if prompted</li>
          <li>Verify device appears as enrolled in Okta Verify</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.4:</strong> Test Desktop MFA
        <ul>
          <li>Lock the Mac (Cmd+Ctrl+Q)</li>
          <li>At login screen, enter test user's local username</li>
          <li>Enter the local password</li>
          <li>Observe Okta Verify challenge (push or TOTP)</li>
          <li>Approve the push notification or enter TOTP code</li>
          <li>Verify successful login to macOS</li>
        </ul>
      </div>

      <h3>Expected Outcomes</h3>
      <ul>
        <li>Configuration profile successfully deployed to test Mac</li>
        <li>Okta Verify installed and device enrolled</li>
        <li>Desktop MFA challenge appears at macOS login</li>
        <li>User can authenticate with push or TOTP</li>
        <li>Successful login after MFA approval</li>
      </ul>

      <h3>Validation Steps</h3>

      <div class="validation">
        <h4>1. Verify Profile Installation</h4>
        <pre><code>sudo profiles -L | grep -i okta</code></pre>
        <p><strong>Expected:</strong> Profile name appears in output</p>

        <h4>2. Check Okta Verify Status</h4>
        <pre><code>defaults read com.okta.OktaVerify</code></pre>
        <p><strong>Expected:</strong> Configuration keys visible with correct values</p>

        <h4>3. View Okta Verify Logs</h4>
        <pre><code>log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 5m</code></pre>
        <p><strong>Expected:</strong> No error messages; enrollment successful</p>

        <h4>4. Confirm in Okta Admin Console</h4>
        <ul>
          <li>Navigate to <strong>Directory → People</strong></li>
          <li>Find test user and click their name</li>
          <li>Click <strong>Okta Verify</strong> tab</li>
          <li>Verify macOS device is listed and enrolled</li>
        </ul>
      </div>

      <h3>Common Issues and Troubleshooting</h3>

      <div class="troubleshooting">
        <h4>Issue: Profile Not Installing</h4>
        <p><strong>Symptoms:</strong> Profile doesn't appear on device after deployment</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Device not checking in with Jamf</li>
          <li>Scope not configured correctly</li>
          <li>MDM enrollment issues</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Force device check-in: <code>sudo jamf policy</code></li>
          <li>Verify device is in the profile's scope in Jamf</li>
          <li>Check MDM enrollment: <code>sudo profiles status</code></li>
          <li>Review Jamf policy logs in Jamf Pro</li>
        </ul>

        <h4>Issue: Okta Verify Not Detecting Org</h4>
        <p><strong>Symptoms:</strong> Okta Verify prompts for manual org URL entry</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>OrgUrl key missing or incorrect in profile</li>
          <li>Profile not applied before Okta Verify launch</li>
          <li>Case sensitivity in domain name</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify OrgUrl in profile: <code>defaults read com.okta.OktaVerify OrgUrl</code></li>
          <li>Quit and relaunch Okta Verify</li>
          <li>Ensure OrgUrl includes https:// and correct domain</li>
          <li>Reinstall profile if necessary</li>
        </ul>

        <h4>Issue: Desktop MFA Not Triggering</h4>
        <p><strong>Symptoms:</strong> Login succeeds with just password, no MFA challenge</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Desktop authentication not enabled in Okta</li>
          <li>User within grace period</li>
          <li>Authentication policy not applied to user</li>
          <li>EnableDesktopAuth set to false</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify EnableDesktopAuth is true in profile</li>
          <li>Check authentication policy in Okta admin console</li>
          <li>Wait for grace period to expire or set to 0 for testing</li>
          <li>Verify user is in correct group for policy</li>
          <li>Check Okta Verify logs for errors</li>
        </ul>

        <h4>Issue: Push Notifications Not Received</h4>
        <p><strong>Symptoms:</strong> Desktop MFA challenge appears but no push on mobile</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Mobile device offline</li>
          <li>Push notifications disabled in mobile Okta Verify</li>
          <li>Network connectivity issues</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify mobile device has network connectivity</li>
          <li>Check push notification settings on mobile device</li>
          <li>Use TOTP as alternative factor</li>
          <li>Re-enroll Okta Verify on mobile device</li>
        </ul>
      </div>

      <h2>Lab 2: Set Up Platform SSO for macOS</h2>

      <div class="lab-header">
        <p><strong>Estimated Time:</strong> 60 minutes</p>
        <p><strong>Difficulty:</strong> Intermediate</p>
        <p><strong>Platform:</strong> macOS 13+ with Jamf Pro or Intune</p>
      </div>

      <h3>Learning Objectives</h3>
      <ul>
        <li>Understand Platform SSO architecture and benefits</li>
        <li>Configure an Extensible SSO profile for Okta</li>
        <li>Deploy Platform SSO configuration to macOS devices</li>
        <li>Test user enrollment and SSO experience</li>
        <li>Validate Secure Enclave key storage</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>macOS 13 (Ventura) or later</li>
        <li>Okta org with Okta Verify and OIE enabled</li>
        <li>MDM solution (Jamf Pro or Intune)</li>
        <li>Understanding of SSO and public key cryptography basics</li>
        <li>Test user with admin rights on test Mac</li>
      </ul>

      <h3>Materials Needed</h3>
      <ul>
        <li>Okta domain URL</li>
        <li>Okta Verify Team ID: <code>4WE73L84WQ</code></li>
        <li>Extension Identifier: <code>com.okta.OktaVerify.OktaVerifyPlatformSSO</code></li>
        <li>MDM admin console access</li>
        <li>macOS test device (physical or VM)</li>
      </ul>

      <h3>Step-by-Step Instructions</h3>

      <h4>Part 1: Configure Platform SSO Profile</h4>

      <div class="step">
        <strong>Step 1.1:</strong> Create Extensible SSO Profile in Jamf
        <ul>
          <li>Log into Jamf Pro</li>
          <li>Navigate to <strong>Computers → Configuration Profiles</strong></li>
          <li>Click <strong>+ New</strong></li>
          <li>Name: "Okta Platform SSO"</li>
          <li>Select <strong>Extensible Single Sign On (SSO)</strong> from the left sidebar</li>
          <li>Click <strong>Configure</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.2:</strong> Configure SSO Extension Settings
        <p>Enter the following values:</p>
        <ul>
          <li><strong>Payload Type:</strong> Redirect</li>
          <li><strong>Extension Identifier:</strong> <code>com.okta.OktaVerify.OktaVerifyPlatformSSO</code></li>
          <li><strong>Team Identifier:</strong> <code>4WE73L84WQ</code></li>
          <li><strong>Sign-In Frequency:</strong> 0 (always challenge at login)</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.3:</strong> Add URLs Configuration
        <p>Under <strong>URLs</strong>, add the following:</p>
        <ul>
          <li><code>https://your-domain.okta.com</code></li>
          <li><code>https://your-domain.okta-emea.com</code> (if applicable)</li>
          <li><code>https://your-domain.okta.com.au</code> (if applicable)</li>
        </ul>
        <p><strong>Note:</strong> Add all Okta domains your organization uses</p>
      </div>

      <div class="step">
        <strong>Step 1.4:</strong> Configure Extension Data
        <p>Add custom configuration keys under <strong>Extension Data</strong>:</p>
        <ul>
          <li><strong>Key:</strong> <code>oktaURL</code>, <strong>Value:</strong> <code>https://your-domain.okta.com</code></li>
          <li><strong>Key:</strong> <code>registrationMode</code>, <strong>Value:</strong> <code>userInitiated</code></li>
          <li><strong>Key:</strong> <code>enableSecureEnclaveKeys</code>, <strong>Value:</strong> <code>true</code></li>
          <li><strong>Key:</strong> <code>accountDisplayName</code>, <strong>Value:</strong> <code>Okta SSO Account</code></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.5:</strong> Set Profile Scope
        <ul>
          <li>Click <strong>Scope</strong> tab</li>
          <li>Add test devices or pilot group</li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <h4>Part 2: Deploy Okta Verify</h4>

      <div class="step">
        <strong>Step 2.1:</strong> Package Okta Verify for Deployment
        <ul>
          <li>Download latest Okta Verify PKG from Okta Downloads</li>
          <li>In Jamf Pro, go to <strong>Computer Management → Packages</strong></li>
          <li>Click <strong>+ New</strong></li>
          <li>Upload the Okta Verify PKG file</li>
          <li>Name: "Okta Verify"</li>
          <li>Category: "Security"</li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.2:</strong> Create Installation Policy
        <ul>
          <li>Go to <strong>Computers → Policies</strong></li>
          <li>Click <strong>+ New</strong></li>
          <li>Name: "Install Okta Verify"</li>
          <li>Under <strong>Packages</strong>, add the Okta Verify package</li>
          <li>Set trigger: "Recurring Check-In" or "Enrollment Complete"</li>
          <li>Set frequency: "Once per computer"</li>
          <li>Scope to test devices</li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <h4>Part 3: User Enrollment</h4>

      <div class="step">
        <strong>Step 3.1:</strong> Verify Profile and App Installation
        <ul>
          <li>On test Mac, open Terminal</li>
          <li>Check profile: <code>sudo profiles -L | grep -i sso</code></li>
          <li>Verify Okta Verify installed: <code>ls /Applications | grep Okta</code></li>
          <li>Check SSO extension: <code>app-sso platform -s</code></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.2:</strong> Initiate Platform SSO Registration
        <ul>
          <li>Launch Okta Verify application</li>
          <li>Click <strong>Add Account</strong></li>
          <li>Select <strong>Work Account (SSO)</strong></li>
          <li>App will detect Platform SSO configuration</li>
          <li>Click <strong>Continue</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.3:</strong> Complete Registration Flow
        <ul>
          <li>Enter Okta credentials when prompted</li>
          <li>Complete MFA challenge (if required by policy)</li>
          <li>Grant permission for Okta Verify to use SSO extension</li>
          <li>Complete biometric setup for Okta Verify</li>
          <li>Confirm "Registration Successful" message</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.4:</strong> Test macOS Login with Platform SSO
        <ul>
          <li>Log out of macOS (Shift+Cmd+Q)</li>
          <li>At login screen, select test user</li>
          <li>Enter Okta password (not local password)</li>
          <li>Observe SSO authentication flow</li>
          <li>Complete any MFA challenges</li>
          <li>Verify successful login</li>
        </ul>
      </div>

      <h3>Expected Outcomes</h3>
      <ul>
        <li>Platform SSO profile successfully deployed</li>
        <li>Okta Verify installed on test Mac</li>
        <li>User successfully enrolled in Platform SSO</li>
        <li>User can log into macOS with Okta credentials</li>
        <li>Private key stored in Secure Enclave</li>
        <li>SSO works for Okta-integrated apps</li>
      </ul>

      <h3>Validation Steps</h3>

      <div class="validation">
        <h4>1. Verify SSO Extension Registration</h4>
        <pre><code>app-sso platform -s</code></pre>
        <p><strong>Expected:</strong> Shows "Registered" status with Okta account</p>

        <h4>2. Check Secure Enclave Key</h4>
        <pre><code>app-sso platform -l</code></pre>
        <p><strong>Expected:</strong> Lists SSO keys stored in Secure Enclave</p>

        <h4>3. View Platform SSO Logs</h4>
        <pre><code>log show --predicate 'subsystem == "com.apple.AppSSO"' --last 10m</code></pre>
        <p><strong>Expected:</strong> Shows successful authentication events</p>

        <h4>4. Test SSO to Okta Dashboard</h4>
        <ul>
          <li>Open Safari (or default browser)</li>
          <li>Navigate to your Okta dashboard URL</li>
          <li>Should automatically sign in without credentials prompt</li>
          <li>Verify user is logged in</li>
        </ul>

        <h4>5. Confirm in Okta Admin Console</h4>
        <ul>
          <li>Log into Okta Admin Console</li>
          <li>Navigate to <strong>Reports → System Log</strong></li>
          <li>Filter for user's authentication events</li>
          <li>Verify "user.authentication.auth_via_mfa" with Platform SSO</li>
        </ul>
      </div>

      <h3>Common Issues and Troubleshooting</h3>

      <div class="troubleshooting">
        <h4>Issue: SSO Extension Not Loading</h4>
        <p><strong>Symptoms:</strong> <code>app-sso platform -s</code> shows "Not Registered"</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Profile not installed correctly</li>
          <li>Incorrect Extension Identifier or Team ID</li>
          <li>macOS version too old (needs 13+)</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify profile: <code>sudo profiles show | grep -A 20 "Extensible"</code></li>
          <li>Confirm Extension Identifier: <code>com.okta.OktaVerify.OktaVerifyPlatformSSO</code></li>
          <li>Confirm Team ID: <code>4WE73L84WQ</code></li>
          <li>Reinstall profile if incorrect</li>
          <li>Verify macOS version: <code>sw_vers</code></li>
        </ul>

        <h4>Issue: Registration Fails with Error</h4>
        <p><strong>Symptoms:</strong> Error message during Okta Verify registration</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Network connectivity issues</li>
          <li>Incorrect Okta URL in configuration</li>
          <li>Okta Verify version outdated</li>
          <li>User doesn't have permission for Platform SSO in Okta</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Check network: <code>ping your-domain.okta.com</code></li>
          <li>Verify oktaURL in profile extension data</li>
          <li>Update Okta Verify to latest version</li>
          <li>Check Okta authentication policy allows Platform SSO</li>
          <li>Review Okta Verify logs: <code>log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 5m</code></li>
        </ul>

        <h4>Issue: Can't Login with Okta Password</h4>
        <p><strong>Symptoms:</strong> macOS login screen doesn't accept Okta password</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Platform SSO not fully registered</li>
          <li>User account not linked</li>
          <li>SSO extension disabled</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Login with local password first</li>
          <li>Complete Platform SSO registration from within macOS</li>
          <li>Verify registration status: <code>app-sso platform -s</code></li>
          <li>Restart Mac after successful registration</li>
          <li>Try logout/login again</li>
        </ul>

        <h4>Issue: SSO Not Working in Browsers</h4>
        <p><strong>Symptoms:</strong> Still prompted for credentials when visiting Okta apps</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>URLs not configured in profile</li>
          <li>Browser not supporting Platform SSO</li>
          <li>Cookie/cache issues</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify URLs list in SSO profile includes your Okta domain</li>
          <li>Use Safari (best support) or Chrome for testing</li>
          <li>Clear browser cookies and cache</li>
          <li>Close and reopen browser</li>
          <li>Test in private/incognito window</li>
        </ul>
      </div>

      <h2>Lab 3: Troubleshoot a Failed Registration</h2>

      <div class="lab-header">
        <p><strong>Estimated Time:</strong> 30 minutes</p>
        <p><strong>Difficulty:</strong> Intermediate</p>
        <p><strong>Platform:</strong> macOS or Windows</p>
      </div>

      <h3>Learning Objectives</h3>
      <ul>
        <li>Identify common registration failure scenarios</li>
        <li>Use diagnostic commands to gather troubleshooting data</li>
        <li>Analyze Okta Verify and system logs</li>
        <li>Resolve registration issues systematically</li>
        <li>Document findings and solutions</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Completed Lab 1 or Lab 2</li>
        <li>Understanding of Okta Verify architecture</li>
        <li>Access to test device with admin privileges</li>
        <li>Familiarity with command line tools</li>
      </ul>

      <h3>Simulated Failure Scenarios</h3>

      <h4>Scenario A: Missing Configuration Profile</h4>
      <p>Simulate this by removing or misconfiguring the MDM profile</p>

      <h4>Scenario B: Network Connectivity Issues</h4>
      <p>Simulate by blocking access to Okta domains in firewall/hosts file</p>

      <h4>Scenario C: Incorrect Org URL</h4>
      <p>Simulate by deploying profile with wrong Okta domain</p>

      <h3>Step-by-Step Diagnostic Process</h3>

      <h4>Part 1: Initial Assessment</h4>

      <div class="step">
        <strong>Step 1.1:</strong> Gather Error Information
        <ul>
          <li>Note exact error message from Okta Verify</li>
          <li>Screenshot error if possible</li>
          <li>Record timestamp of failure</li>
          <li>Document user account and device name</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.2:</strong> Verify Basic Prerequisites

        <p><strong>On macOS:</strong></p>
        <pre><code># Check Okta Verify installation
ls -la /Applications/Okta\ Verify.app

# Check configuration profile
sudo profiles -L | grep -i okta

# Check network connectivity
ping your-domain.okta.com
curl -I https://your-domain.okta.com</code></pre>

        <p><strong>On Windows:</strong></p>
        <pre><code># Check Okta Verify installation
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" | Where-Object { $_.DisplayName -like "*Okta*" }

# Check Okta Verify service
Get-Service OktaVerify

# Check network connectivity
Test-NetConnection your-domain.okta.com -Port 443</code></pre>
      </div>

      <h4>Part 2: Log Analysis</h4>

      <div class="step">
        <strong>Step 2.1:</strong> Collect Okta Verify Logs

        <p><strong>On macOS:</strong></p>
        <pre><code># View recent Okta Verify logs
log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 30m --info

# Export logs to file
log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 30m > ~/Desktop/okta-verify-logs.txt

# Check for errors specifically
log show --predicate 'subsystem == "com.okta.OktaVerify" AND messageType == "Error"' --last 30m</code></pre>

        <p><strong>On Windows:</strong></p>
        <pre><code># View Okta Verify logs in Event Viewer
Get-WinEvent -LogName "Okta Verify" -MaxEvents 50 | Format-List

# Check for errors
Get-WinEvent -LogName "Okta Verify" | Where-Object {$_.LevelDisplayName -eq "Error"} | Select-Object TimeCreated, Message

# Export to file
Get-WinEvent -LogName "Okta Verify" -MaxEvents 100 | Export-Csv C:\\Users\\Public\\okta-logs.csv</code></pre>
      </div>

      <div class="step">
        <strong>Step 2.2:</strong> Analyze Log Patterns
        <p>Look for these common error patterns:</p>
        <ul>
          <li><strong>Network errors:</strong> "connection timeout", "unreachable", "DNS"</li>
          <li><strong>Configuration errors:</strong> "invalid URL", "missing parameter", "malformed"</li>
          <li><strong>Authentication errors:</strong> "invalid credentials", "MFA failed", "token expired"</li>
          <li><strong>Permission errors:</strong> "access denied", "unauthorized", "insufficient privileges"</li>
        </ul>
      </div>

      <h4>Part 3: Configuration Validation</h4>

      <div class="step">
        <strong>Step 3.1:</strong> Validate Profile Configuration

        <p><strong>On macOS:</strong></p>
        <pre><code># View full profile configuration
sudo profiles show

# Check Okta-specific settings
defaults read com.okta.OktaVerify

# Verify specific keys
defaults read com.okta.OktaVerify OrgUrl
defaults read com.okta.OktaVerify EnableDesktopAuth</code></pre>

        <p><strong>On Windows:</strong></p>
        <pre><code># Check registry settings
Get-ItemProperty "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -ErrorAction SilentlyContinue

# Verify OrgUrl
Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "OrgUrl" -ErrorAction SilentlyContinue</code></pre>
      </div>

      <div class="step">
        <strong>Step 3.2:</strong> Verify Network Connectivity
        <pre><code># Test Okta domain reachability
nslookup your-domain.okta.com

# Test HTTPS connectivity
curl -v https://your-domain.okta.com/.well-known/okta-organization

# Check for proxy issues
curl -v --proxy-insecure https://your-domain.okta.com</code></pre>
      </div>

      <h4>Part 4: Resolution Steps</h4>

      <div class="step">
        <strong>Step 4.1:</strong> Fix Common Issues

        <p><strong>For Missing/Incorrect Configuration:</strong></p>
        <ul>
          <li>Redeploy MDM profile from admin console</li>
          <li>Force device check-in: <code>sudo jamf policy</code> (macOS) or <code>Get-ScheduledTask | Where-Object {$_.TaskName -like "*Intune*"} | Start-ScheduledTask</code> (Windows)</li>
          <li>Verify profile installation</li>
          <li>Restart device if needed</li>
        </ul>

        <p><strong>For Network Issues:</strong></p>
        <ul>
          <li>Check firewall rules allow Okta domains</li>
          <li>Verify proxy configuration if applicable</li>
          <li>Test from different network if possible</li>
          <li>Check hosts file for blocking entries: <code>cat /etc/hosts | grep okta</code></li>
        </ul>

        <p><strong>For Okta Verify Issues:</strong></p>
        <ul>
          <li>Quit Okta Verify completely</li>
          <li>Clear app cache/preferences</li>
          <li>Restart Okta Verify</li>
          <li>Reinstall Okta Verify if necessary</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.2:</strong> Re-attempt Registration
        <ul>
          <li>Open Okta Verify</li>
          <li>Remove failed account if present</li>
          <li>Click <strong>Add Account</strong></li>
          <li>Follow enrollment process</li>
          <li>Monitor logs in real-time during attempt</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.3:</strong> Validate Success
        <ul>
          <li>Confirm device appears enrolled in Okta Verify</li>
          <li>Check Okta Admin Console for device registration</li>
          <li>Test authentication flow</li>
          <li>Verify no errors in logs</li>
        </ul>
      </div>

      <h3>Expected Outcomes</h3>
      <ul>
        <li>Successfully identified root cause of registration failure</li>
        <li>Applied appropriate troubleshooting methodology</li>
        <li>Resolved issue and completed successful registration</li>
        <li>Documented diagnostic process and solution</li>
        <li>Gained proficiency with diagnostic commands</li>
      </ul>

      <h3>Troubleshooting Decision Tree</h3>

      <div class="decision-tree">
        <pre><code>Registration Fails
│
├─→ Error: "Cannot find organization"
│   ├─→ Check: Profile installed? → No → Deploy profile
│   ├─→ Check: OrgUrl correct? → No → Fix profile config
│   └─→ Check: Network access? → No → Fix connectivity
│
├─→ Error: "Authentication failed"
│   ├─→ Check: Credentials correct? → No → Reset password
│   ├─→ Check: MFA enrolled? → No → Enroll MFA first
│   └─→ Check: User active in Okta? → No → Activate user
│
├─→ Error: "Service unavailable"
│   ├─→ Check: Okta status page → Down → Wait for resolution
│   ├─→ Check: Network connectivity → Failed → Fix network
│   └─→ Check: Proxy settings → Wrong → Configure proxy
│
└─→ No error, but fails silently
    ├─→ Check: Logs for errors → Found → Analyze error
    ├─→ Check: Okta Verify version → Outdated → Update app
    └─→ Check: Device meeting requirements? → No → Upgrade OS</code></pre>
      </div>

      <h3>Documentation Template</h3>

      <div class="documentation">
        <h4>Incident Report Template</h4>
        <pre><code>Date/Time: [timestamp]
Device: [hostname/serial]
User: [username]
Platform: [macOS/Windows + version]
Okta Verify Version: [version]

Symptom:
[Describe what user experienced]

Error Message:
[Exact error text or screenshot]

Diagnostic Steps Taken:
1. [Step 1 and result]
2. [Step 2 and result]
3. [Step 3 and result]

Root Cause:
[What caused the issue]

Resolution:
[What fixed the issue]

Prevention:
[How to prevent in future]

Time to Resolve: [minutes]</code></pre>
      </div>

      <div class="info-box">
        <h3>Key Takeaways</h3>
        <ul>
          <li>Always gather error messages and timestamps first</li>
          <li>Follow systematic diagnostic process</li>
          <li>Logs are your best friend for root cause analysis</li>
          <li>Validate configuration before and after changes</li>
          <li>Document findings for future reference</li>
          <li>Most issues are configuration or network related</li>
        </ul>
      </div>

      <h2>Lab 4: Implement FastPass</h2>

      <div class="lab-header">
        <p><strong>Estimated Time:</strong> 50 minutes</p>
        <p><strong>Difficulty:</strong> Advanced</p>
        <p><strong>Platform:</strong> macOS or Windows</p>
      </div>

      <h3>Learning Objectives</h3>
      <ul>
        <li>Understand FastPass architecture and passwordless authentication</li>
        <li>Configure authentication policies for FastPass</li>
        <li>Register devices with FastPass</li>
        <li>Test passwordless login flows</li>
        <li>Understand the difference between Desktop MFA and FastPass</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Completed Lab 1 (Desktop MFA configuration)</li>
        <li>Okta OIE tenant (required for FastPass)</li>
        <li>Understanding of phishing-resistant authentication</li>
        <li>MDM with configuration profiles deployed</li>
        <li>Test user and device ready</li>
      </ul>

      <h3>Materials Needed</h3>
      <ul>
        <li>Okta OIE tenant</li>
        <li>Okta Verify latest version (v4.0+)</li>
        <li>macOS 11+ or Windows 10/11 device</li>
        <li>Mobile device for backup authentication</li>
        <li>MDM administrative access</li>
      </ul>

      <h3>Understanding FastPass vs Desktop MFA</h3>

      <div class="comparison-box">
        <table style="width: 100%; border-collapse: collapse;">
          <tr style="background: #f0f0f0;">
            <th style="padding: 10px; border: 1px solid #ddd;">Feature</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Desktop MFA</th>
            <th style="padding: 10px; border: 1px solid #ddd;">FastPass</th>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Password Required</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Yes (local + Okta)</td>
            <td style="padding: 10px; border: 1px solid #ddd;">No (passwordless)</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Authentication Method</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Password + MFA</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Biometric + cryptographic key</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Phishing Resistance</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Moderate</td>
            <td style="padding: 10px; border: 1px solid #ddd;">High (FIDO2 compliant)</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>User Experience</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Password + approval</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Biometric only</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Tenant</strong></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Classic or OIE</td>
            <td style="padding: 10px; border: 1px solid #ddd;">OIE only</td>
          </tr>
        </table>
      </div>

      <h3>Step-by-Step Instructions</h3>

      <h4>Part 1: Configure Okta for FastPass</h4>

      <div class="step">
        <strong>Step 1.1:</strong> Enable FastPass in Okta Verify Settings
        <ul>
          <li>Log into Okta Admin Console</li>
          <li>Navigate to <strong>Security → Authenticators</strong></li>
          <li>Click <strong>Okta Verify</strong></li>
          <li>Click <strong>Edit</strong></li>
          <li>Under <strong>Device-based user verification</strong>, ensure enabled</li>
          <li>Enable <strong>FastPass</strong></li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.2:</strong> Configure Authentication Policy
        <ul>
          <li>Navigate to <strong>Security → Authentication Policies</strong></li>
          <li>Create new policy or edit existing: "FastPass Policy"</li>
          <li>Click <strong>Add Rule</strong></li>
          <li>Name: "FastPass for Test Users"</li>
          <li>Under <strong>AND User's authenticator</strong>:</li>
          <ul>
            <li>Select <strong>Okta Verify</strong></li>
            <li>Choose <strong>FastPass</strong></li>
            <li>Set as primary authenticator</li>
          </ul>
          <li>Under <strong>THEN Access is</strong>: "Allowed after successful authentication"</li>
          <li>Click <strong>Create Rule</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.3:</strong> Assign Policy to Test Users
        <ul>
          <li>In the policy settings, click <strong>Assignments</strong></li>
          <li>Add test user group</li>
          <li>Ensure policy has higher priority than other policies</li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <h4>Part 2: Deploy FastPass Configuration Profile</h4>

      <div class="step">
        <strong>Step 2.1:</strong> Update MDM Configuration Profile
        <p><strong>For macOS (Jamf Pro):</strong></p>
        <ul>
          <li>Edit existing Okta Verify configuration profile</li>
          <li>Update the plist to include FastPass settings:</li>
        </ul>
        <pre><code>&lt;key&gt;EnableFastPass&lt;/key&gt;
&lt;true/&gt;
&lt;key&gt;EnableUserVerification&lt;/key&gt;
&lt;true/&gt;
&lt;key&gt;RequireUserVerification&lt;/key&gt;
&lt;true/&gt;</code></pre>

        <p><strong>For Windows (Intune):</strong></p>
        <ul>
          <li>Navigate to Intune admin center</li>
          <li>Go to <strong>Devices → Configuration profiles</strong></li>
          <li>Edit Okta Verify profile</li>
          <li>Add custom OMA-URI settings:</li>
        </ul>
        <pre><code>OMA-URI: ./Device/Vendor/MSFT/Okta/EnableFastPass
Data type: Boolean
Value: True

OMA-URI: ./Device/Vendor/MSFT/Okta/RequireUserVerification
Data type: Boolean
Value: True</code></pre>
      </div>

      <div class="step">
        <strong>Step 2.2:</strong> Deploy Updated Profile
        <ul>
          <li>Save the configuration profile changes</li>
          <li>Force device check-in or wait for auto-sync</li>
          <li>Verify profile updates on test device</li>
        </ul>
      </div>

      <h4>Part 3: Register Device with FastPass</h4>

      <div class="step">
        <strong>Step 3.1:</strong> Update Okta Verify
        <ul>
          <li>Ensure Okta Verify is version 4.0 or later</li>
          <li>On the test device, open Okta Verify</li>
          <li>If outdated, download latest from Okta Downloads</li>
          <li>Install/update the application</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.2:</strong> Re-enroll Device for FastPass
        <ul>
          <li>In Okta Verify, if device already enrolled with Desktop MFA:</li>
          <ul>
            <li>Click account → <strong>Settings</strong></li>
            <li>Look for <strong>Enable FastPass</strong> option</li>
            <li>Click <strong>Enable</strong></li>
            <li>Complete biometric verification</li>
          </ul>
          <li>For new enrollment:</li>
          <ul>
            <li>Click <strong>Add Account</strong></li>
            <li>Sign in with test user credentials</li>
            <li>When prompted, choose <strong>FastPass</strong> enrollment</li>
            <li>Set up biometric authentication (Touch ID, Face ID, Windows Hello)</li>
            <li>Complete enrollment</li>
          </ul>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.3:</strong> Verify FastPass Registration
        <ul>
          <li>In Okta Admin Console, navigate to <strong>Directory → People</strong></li>
          <li>Find test user, click their name</li>
          <li>Click <strong>Okta Verify</strong> tab</li>
          <li>Verify device shows <strong>FastPass</strong> badge/indicator</li>
          <li>Confirm <strong>User Verification</strong> is enabled</li>
        </ul>
      </div>

      <h4>Part 4: Test Passwordless Authentication</h4>

      <div class="step">
        <strong>Step 4.1:</strong> Test Browser-Based Login
        <ul>
          <li>Open a browser in incognito/private mode</li>
          <li>Navigate to your Okta org URL</li>
          <li>Enter test user's username</li>
          <li>Instead of password prompt, observe FastPass challenge</li>
          <li>Notification appears on device</li>
          <li>Complete biometric verification (Touch ID/Face ID/Windows Hello)</li>
          <li>Verify automatic login without password</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.2:</strong> Test Desktop Login (if Platform SSO enabled)
        <ul>
          <li>Log out of the operating system</li>
          <li>At login screen, select test user</li>
          <li>Enter any placeholder (FastPass overrides password)</li>
          <li>Complete biometric verification</li>
          <li>Verify successful passwordless login to OS</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.3:</strong> Test Application SSO
        <ul>
          <li>Access Okta-integrated SaaS application</li>
          <li>Should redirect to Okta</li>
          <li>FastPass challenge appears automatically</li>
          <li>Complete biometric verification</li>
          <li>Verify automatic login to application</li>
          <li>No password entry required</li>
        </ul>
      </div>

      <h3>Expected Outcomes</h3>
      <ul>
        <li>FastPass enabled in Okta Verify authenticator settings</li>
        <li>Authentication policy configured for FastPass</li>
        <li>Device registered with FastPass capability</li>
        <li>User can authenticate without passwords</li>
        <li>Biometric verification works consistently</li>
        <li>Seamless SSO across applications</li>
      </ul>

      <h3>Validation Steps</h3>

      <div class="validation">
        <h4>1. Verify FastPass Enrollment in Okta</h4>
        <ul>
          <li>Admin Console → Directory → People → [User]</li>
          <li>Check <strong>Okta Verify</strong> tab</li>
          <li>Confirm FastPass badge on device</li>
          <li>Verify "User Verification: Enabled"</li>
        </ul>

        <h4>2. Check Device Configuration</h4>
        <p><strong>macOS:</strong></p>
        <pre><code>defaults read com.okta.OktaVerify EnableFastPass
defaults read com.okta.OktaVerify EnableUserVerification</code></pre>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "EnableFastPass"</code></pre>

        <h4>3. Test Authentication Flow</h4>
        <ul>
          <li>Attempt login to Okta dashboard</li>
          <li>Should NOT prompt for password</li>
          <li>Should show FastPass biometric challenge</li>
          <li>Login completes after biometric verification</li>
        </ul>

        <h4>4. Review System Logs</h4>
        <p><strong>macOS:</strong></p>
        <pre><code>log show --predicate 'subsystem == "com.okta.OktaVerify" AND message CONTAINS "FastPass"' --last 10m</code></pre>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-WinEvent -LogName "Okta Verify" | Where-Object {$_.Message -like "*FastPass*"} | Select-Object -First 10</code></pre>
      </div>

      <h3>Common Issues and Troubleshooting</h3>

      <div class="troubleshooting">
        <h4>Issue: FastPass Option Not Available</h4>
        <p><strong>Symptoms:</strong> Can't enable FastPass in Okta Verify</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Okta tenant is Classic (not OIE)</li>
          <li>Okta Verify version outdated</li>
          <li>FastPass not enabled in authenticator settings</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify OIE: Admin Console → Settings → Account → check for "Identity Engine"</li>
          <li>Update Okta Verify to v4.0 or later</li>
          <li>Enable FastPass in Security → Authenticators → Okta Verify</li>
        </ul>

        <h4>Issue: Biometric Verification Fails</h4>
        <p><strong>Symptoms:</strong> Touch ID/Face ID/Windows Hello not working</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Biometric not set up on device</li>
          <li>Hardware doesn't support required biometric</li>
          <li>User verification settings incorrect</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li><strong>macOS:</strong> System Settings → Touch ID & Password → verify fingerprints enrolled</li>
          <li><strong>Windows:</strong> Settings → Accounts → Sign-in options → verify Windows Hello configured</li>
          <li>Test biometric with other apps to verify hardware works</li>
          <li>Re-enroll biometric if necessary</li>
        </ul>

        <h4>Issue: Still Prompted for Password</h4>
        <p><strong>Symptoms:</strong> Login flow requests password instead of FastPass</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Authentication policy not applied correctly</li>
          <li>User not in FastPass policy scope</li>
          <li>Device not registered with FastPass</li>
          <li>Browser not detecting device</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify user is in group assigned to FastPass policy</li>
          <li>Check policy priority (FastPass policy should be higher)</li>
          <li>Confirm device shows FastPass in Admin Console</li>
          <li>Clear browser cache and cookies</li>
          <li>Try different browser</li>
        </ul>

        <h4>Issue: "This device doesn't meet requirements"</h4>
        <p><strong>Symptoms:</strong> Error during FastPass enrollment</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Missing biometric hardware</li>
          <li>OS version too old</li>
          <li>TPM/Secure Enclave not available</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Verify device has Touch ID, Face ID, or Windows Hello compatible hardware</li>
          <li>Check OS version: macOS 11+ or Windows 10 1809+</li>
          <li>For Windows: Verify TPM 2.0: <code>Get-Tpm</code></li>
          <li>For macOS: Verify T2 or Apple Silicon chip</li>
        </ul>
      </div>

      <h2>Lab 5: Configure Desktop MFA for Windows in Intune</h2>

      <div class="lab-header">
        <p><strong>Estimated Time:</strong> 40 minutes</p>
        <p><strong>Difficulty:</strong> Beginner</p>
        <p><strong>Platform:</strong> Windows 10/11 with Microsoft Intune</p>
      </div>

      <h3>Learning Objectives</h3>
      <ul>
        <li>Create a Windows configuration profile in Intune</li>
        <li>Configure Okta Verify Credential Provider settings</li>
        <li>Deploy configuration to Windows devices</li>
        <li>Test Desktop MFA on Windows login</li>
        <li>Validate successful deployment</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Microsoft Intune subscription and admin access</li>
        <li>Windows 10 (1809+) or Windows 11 device</li>
        <li>Device enrolled in Intune</li>
        <li>Okta admin access</li>
        <li>Test user with mobile Okta Verify enrolled</li>
      </ul>

      <h3>Materials Needed</h3>
      <ul>
        <li>Okta domain URL</li>
        <li>Microsoft Endpoint Manager admin center access</li>
        <li>Windows 10/11 test device</li>
        <li>Mobile device with Okta Verify</li>
        <li>Test user credentials</li>
      </ul>

      <h3>Step-by-Step Instructions</h3>

      <h4>Part 1: Configure Okta (Same as Lab 1)</h4>

      <div class="step">
        <strong>Step 1.1:</strong> Enable Desktop MFA
        <ul>
          <li>Log into Okta Admin Console</li>
          <li>Navigate to <strong>Security → Authenticators</strong></li>
          <li>Click <strong>Okta Verify</strong> → <strong>Edit</strong></li>
          <li>Enable <strong>Desktop authentication</strong></li>
          <li>Click <strong>Save</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.2:</strong> Create or Update Authentication Policy
        <ul>
          <li>Security → Authentication Policies</li>
          <li>Create or edit policy for Windows devices</li>
          <li>Add rule requiring Okta Verify for desktop auth</li>
          <li>Assign to test user group</li>
        </ul>
      </div>

      <h4>Part 2: Create Configuration Profile in Intune</h4>

      <div class="step">
        <strong>Step 2.1:</strong> Access Intune Configuration Profiles
        <ul>
          <li>Log into <strong>Microsoft Endpoint Manager admin center</strong></li>
          <li>Navigate to <strong>Devices → Configuration profiles</strong></li>
          <li>Click <strong>+ Create profile</strong></li>
          <li>Platform: <strong>Windows 10 and later</strong></li>
          <li>Profile type: <strong>Templates → Custom</strong></li>
          <li>Click <strong>Create</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.2:</strong> Configure Basic Settings
        <ul>
          <li>Name: "Okta Desktop MFA for Windows"</li>
          <li>Description: "Enables Okta Verify Desktop MFA on Windows devices"</li>
          <li>Click <strong>Next</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.3:</strong> Add OMA-URI Settings
        <p>Add the following OMA-URI configurations (click <strong>Add</strong> for each):</p>

        <p><strong>1. Organization URL:</strong></p>
        <pre><code>Name: Okta Organization URL
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/OrgUrl
Data type: String
Value: https://your-domain.okta.com</code></pre>

        <p><strong>2. Enable Desktop Authentication:</strong></p>
        <pre><code>Name: Enable Desktop Authentication
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/EnableDesktopAuth
Data type: Integer
Value: 1</code></pre>

        <p><strong>3. Enabled Factors:</strong></p>
        <pre><code>Name: Enabled Factors
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/EnabledFactors
Data type: String
Value: push,totp</code></pre>

        <p><strong>4. Grace Period:</strong></p>
        <pre><code>Name: Grace Period Minutes
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/GracePeriodMinutes
Data type: Integer
Value: 60</code></pre>

        <p><strong>5. Enable Password Sync (optional):</strong></p>
        <pre><code>Name: Enable Password Sync
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/EnablePasswordSync
Data type: Integer
Value: 0</code></pre>

        <p><strong>Note:</strong> Replace <code>your-domain.okta.com</code> with your actual Okta domain</p>
      </div>

      <div class="step">
        <strong>Step 2.4:</strong> Configure Assignments
        <ul>
          <li>Click <strong>Next</strong> to Assignments</li>
          <li>Under <strong>Included groups</strong>, add test device group or test users</li>
          <li>Click <strong>Next</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.5:</strong> Review and Create
        <ul>
          <li>Review all settings</li>
          <li>Click <strong>Create</strong></li>
          <li>Profile will begin deploying to assigned devices</li>
        </ul>
      </div>

      <h4>Part 3: Deploy Okta Verify Application</h4>

      <div class="step">
        <strong>Step 3.1:</strong> Add Okta Verify as Win32 App
        <ul>
          <li>In Endpoint Manager, go to <strong>Apps → All apps</strong></li>
          <li>Click <strong>+ Add</strong></li>
          <li>App type: <strong>Windows app (Win32)</strong></li>
          <li>Upload Okta Verify installer (.intunewin format)</li>
        </ul>
        <p><strong>Note:</strong> Download Okta Verify MSI from Okta Downloads, then package as .intunewin using Microsoft Win32 Content Prep Tool</p>
      </div>

      <div class="step">
        <strong>Step 3.2:</strong> Configure App Settings
        <ul>
          <li>Name: "Okta Verify"</li>
          <li>Publisher: "Okta, Inc."</li>
          <li>Install command: <code>msiexec /i OktaVerify.msi /qn</code></li>
          <li>Uninstall command: <code>msiexec /x OktaVerify.msi /qn</code></li>
          <li>Install behavior: <strong>System</strong></li>
          <li>Device restart behavior: <strong>Determine based on return codes</strong></li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.3:</strong> Set Requirements and Detection Rules
        <ul>
          <li>Operating system: <strong>Windows 10 1809+</strong></li>
          <li>Architecture: <strong>64-bit</strong></li>
          <li>Detection rule type: <strong>MSI</strong></li>
          <li>MSI product code: (auto-detected from installer)</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.4:</strong> Assign and Deploy
        <ul>
          <li>Under <strong>Assignments</strong>, add device group</li>
          <li>Set as <strong>Required</strong> for automatic installation</li>
          <li>Click <strong>Create</strong></li>
        </ul>
      </div>

      <h4>Part 4: Test Desktop MFA on Windows</h4>

      <div class="step">
        <strong>Step 4.1:</strong> Verify Profile and App Installation
        <ul>
          <li>On Windows test device, sync with Intune:</li>
          <ul>
            <li>Settings → Accounts → Access work or school</li>
            <li>Click your org account → <strong>Info</strong></li>
            <li>Click <strong>Sync</strong></li>
          </ul>
          <li>Wait 5-10 minutes for profile and app to deploy</li>
          <li>Verify Okta Verify installed: Check Start menu or Programs list</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.2:</strong> Verify Registry Settings
        <ul>
          <li>Open Registry Editor (regedit.exe) as admin</li>
          <li>Navigate to: <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Okta\\Okta Verify</code></li>
          <li>Verify keys exist: OrgUrl, EnableDesktopAuth, EnabledFactors, etc.</li>
          <li>Confirm values are correct</li>
        </ul>
        <p><strong>Alternative (PowerShell):</strong></p>
        <pre><code>Get-ItemProperty "HKLM:\\SOFTWARE\\Okta\\Okta Verify"</code></pre>
      </div>

      <div class="step">
        <strong>Step 4.3:</strong> Enroll Device in Okta Verify
        <ul>
          <li>Launch Okta Verify from Start menu</li>
          <li>Should auto-detect org URL from registry</li>
          <li>Click <strong>Add Account</strong></li>
          <li>Sign in with test user credentials</li>
          <li>Approve push notification on mobile device</li>
          <li>Complete enrollment</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.4:</strong> Test Desktop MFA Login
        <ul>
          <li>Lock Windows (Win+L) or sign out</li>
          <li>At login screen, select test user</li>
          <li>Enter local Windows password</li>
          <li>Observe Okta Verify Credential Provider screen</li>
          <li>Complete MFA challenge (push or TOTP)</li>
          <li>Verify successful login</li>
        </ul>
      </div>

      <h3>Expected Outcomes</h3>
      <ul>
        <li>Configuration profile successfully deployed via Intune</li>
        <li>Registry keys correctly set on Windows device</li>
        <li>Okta Verify installed automatically</li>
        <li>Device enrolled in Okta</li>
        <li>Desktop MFA triggers at Windows login</li>
        <li>User can authenticate with MFA</li>
      </ul>

      <h3>Validation Steps</h3>

      <div class="validation">
        <h4>1. Verify Intune Profile Deployment</h4>
        <ul>
          <li>Endpoint Manager → Devices → All devices → [Device name]</li>
          <li>Click <strong>Device configuration</strong></li>
          <li>Confirm "Okta Desktop MFA for Windows" shows as <strong>Succeeded</strong></li>
        </ul>

        <h4>2. Check Registry Settings</h4>
        <pre><code>Get-ItemProperty "HKLM:\\SOFTWARE\\Okta\\Okta Verify" | Format-List</code></pre>
        <p><strong>Expected:</strong> All configured keys present with correct values</p>

        <h4>3. Verify Okta Verify Service</h4>
        <pre><code>Get-Service OktaVerify</code></pre>
        <p><strong>Expected:</strong> Status = Running</p>

        <h4>4. Check Credential Provider Registration</h4>
        <pre><code>Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers" | Where-Object {$_ -like "*Okta*"}</code></pre>
        <p><strong>Expected:</strong> Okta Credential Provider GUID present</p>

        <h4>5. View Event Logs</h4>
        <pre><code>Get-WinEvent -LogName "Okta Verify" -MaxEvents 10 | Format-List</code></pre>
        <p><strong>Expected:</strong> Recent enrollment and authentication events</p>
      </div>

      <h3>Common Issues and Troubleshooting</h3>

      <div class="troubleshooting">
        <h4>Issue: Profile Not Applying</h4>
        <p><strong>Symptoms:</strong> Registry keys not created on device</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Device not syncing with Intune</li>
          <li>Device not in assigned group</li>
          <li>OMA-URI syntax errors</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Force sync: Settings → Accounts → Access work or school → Sync</li>
          <li>Verify device is in correct Azure AD group</li>
          <li>Check Intune profile status for errors</li>
          <li>Review OMA-URI paths for typos</li>
        </ul>

        <h4>Issue: Okta Verify Not Installing</h4>
        <p><strong>Symptoms:</strong> App doesn't appear after Intune deployment</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>App not assigned as Required</li>
          <li>Detection rule failing</li>
          <li>Installation command errors</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Check app assignment: must be Required, not Available</li>
          <li>Review Intune app installation logs</li>
          <li>Manually test MSI installation</li>
          <li>Check Event Viewer → Application logs for MSI errors</li>
        </ul>

        <h4>Issue: Credential Provider Not Appearing</h4>
        <p><strong>Symptoms:</strong> No Okta challenge at Windows login</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Okta Verify service not running</li>
          <li>Device not enrolled in Okta</li>
          <li>EnableDesktopAuth set to 0</li>
          <li>Grace period still active</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Start service: <code>Start-Service OktaVerify</code></li>
          <li>Complete device enrollment in Okta Verify app</li>
          <li>Verify EnableDesktopAuth = 1 in registry</li>
          <li>Set GracePeriodMinutes to 0 for testing</li>
          <li>Restart Windows after enrollment</li>
        </ul>

        <h4>Issue: "The Okta Verify service is not available"</h4>
        <p><strong>Symptoms:</strong> Error at login screen</p>
        <p><strong>Causes:</strong></p>
        <ul>
          <li>Okta Verify service crashed or disabled</li>
          <li>Network connectivity issues</li>
          <li>Okta org unreachable</li>
        </ul>
        <p><strong>Solutions:</strong></p>
        <ul>
          <li>Check service status: <code>Get-Service OktaVerify</code></li>
          <li>Restart service: <code>Restart-Service OktaVerify</code></li>
          <li>Set service to Automatic: <code>Set-Service OktaVerify -StartupType Automatic</code></li>
          <li>Test network: <code>Test-NetConnection your-domain.okta.com -Port 443</code></li>
          <li>Check Event Viewer for service errors</li>
        </ul>
      </div>

      <h2>Lab 6: Multi-Factor Recovery Scenarios</h2>

      <div class="lab-header">
        <p><strong>Estimated Time:</strong> 35 minutes</p>
        <p><strong>Difficulty:</strong> Intermediate</p>
        <p><strong>Platform:</strong> macOS and Windows</p>
      </div>

      <h3>Learning Objectives</h3>
      <ul>
        <li>Understand recovery scenarios for Desktop MFA</li>
        <li>Configure and test recovery PIN functionality</li>
        <li>Execute self-service MFA reset procedures</li>
        <li>Perform admin-initiated device unlock</li>
        <li>Document recovery processes for end users</li>
      </ul>

      <h3>Prerequisites</h3>
      <ul>
        <li>Completed Lab 1 or Lab 5 (Desktop MFA configured)</li>
        <li>Enrolled device with Desktop MFA active</li>
        <li>Okta admin access</li>
        <li>Understanding of MFA concepts</li>
      </ul>

      <h3>Common Recovery Scenarios</h3>

      <div class="scenario-box">
        <p><strong>Scenario 1:</strong> User lost mobile device with Okta Verify</p>
        <p><strong>Scenario 2:</strong> Mobile device offline/out of battery</p>
        <p><strong>Scenario 3:</strong> User can't receive push notifications</p>
        <p><strong>Scenario 4:</strong> Device enrollment corrupted or failed</p>
        <p><strong>Scenario 5:</strong> User locked out after multiple failed attempts</p>
      </div>

      <h3>Step-by-Step Instructions</h3>

      <h4>Part 1: Recovery PIN Setup and Usage</h4>

      <div class="step">
        <strong>Step 1.1:</strong> Generate Recovery PIN in Okta Verify
        <ul>
          <li>On enrolled device, open Okta Verify</li>
          <li>Click account → <strong>Settings</strong></li>
          <li>Look for <strong>Recovery</strong> or <strong>Offline Access</strong> section</li>
          <li>Click <strong>Generate Recovery PIN</strong></li>
          <li>Note: PIN format is typically 6-8 digits</li>
          <li>Save PIN securely (password manager, encrypted note)</li>
        </ul>
        <p><strong>Important:</strong> Recovery PIN should be stored separately from device</p>
      </div>

      <div class="step">
        <strong>Step 1.2:</strong> Test Recovery PIN
        <ul>
          <li>Simulate scenario: Put mobile device in airplane mode</li>
          <li>Lock computer and attempt login</li>
          <li>Enter local password</li>
          <li>When Okta MFA challenge appears, look for "Use Recovery PIN" or "Can't access your device?"</li>
          <li>Click the option and enter recovery PIN</li>
          <li>Verify successful login</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 1.3:</strong> Recovery PIN Limitations
        <p>Understand and document these limitations:</p>
        <ul>
          <li>PIN typically valid for limited time (e.g., 7-30 days)</li>
          <li>Limited number of uses (e.g., 5-10 times)</li>
          <li>New PIN must be generated periodically</li>
          <li>PIN tied to specific device enrollment</li>
          <li>Not available for all authentication policies</li>
        </ul>
      </div>

      <h4>Part 2: Self-Service MFA Reset</h4>

      <div class="step">
        <strong>Step 2.1:</strong> Access Self-Service Recovery
        <ul>
          <li>From desktop login screen, click "Need help signing in?"</li>
          <li>Or navigate to: <code>https://your-domain.okta.com/signin/forgot-password</code></li>
          <li>Enter username</li>
          <li>Select recovery method (email or SMS if configured)</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.2:</strong> Complete Identity Verification
        <ul>
          <li>Receive recovery code via email or SMS</li>
          <li>Enter verification code</li>
          <li>Answer security questions if configured</li>
          <li>Proceed to MFA reset options</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.3:</strong> Re-enroll MFA Factor
        <ul>
          <li>After identity verification, access MFA settings</li>
          <li>Remove old Okta Verify enrollment</li>
          <li>Add new Okta Verify enrollment</li>
          <li>Scan QR code with new/replacement mobile device</li>
          <li>Complete setup</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 2.4:</strong> Validate Desktop MFA After Reset
        <ul>
          <li>On desktop, open Okta Verify application</li>
          <li>May need to re-enroll desktop device</li>
          <li>Sign in with updated credentials</li>
          <li>Test desktop login with new MFA setup</li>
        </ul>
      </div>

      <h4>Part 3: Admin-Initiated Recovery</h4>

      <div class="step">
        <strong>Step 3.1:</strong> Locate User in Admin Console
        <ul>
          <li>Log into Okta Admin Console</li>
          <li>Navigate to <strong>Directory → People</strong></li>
          <li>Search for affected user</li>
          <li>Click username to view profile</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.2:</strong> Reset MFA Factors
        <ul>
          <li>In user profile, click <strong>Security</strong> tab</li>
          <li>Scroll to <strong>Factor Enrollments</strong> section</li>
          <li>Find Okta Verify enrollment</li>
          <li>Click <strong>Actions → Reset</strong></li>
          <li>Confirm reset action</li>
        </ul>
        <p><strong>Note:</strong> This removes the factor enrollment, requiring user to re-enroll</p>
      </div>

      <div class="step">
        <strong>Step 3.3:</strong> Unlock User Account (if locked)</strong>
        <ul>
          <li>If user locked due to failed attempts, in user profile:</li>
          <li>Click <strong>More Actions → Unlock User</strong></li>
          <li>Confirm unlock</li>
          <li>User can now attempt login again</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 3.4:</strong> Communicate with User
        <ul>
          <li>Notify user that MFA has been reset</li>
          <li>Provide re-enrollment instructions</li>
          <li>User needs to enroll new Okta Verify on mobile</li>
          <li>Then re-enroll desktop device</li>
          <li>Verify successful login after re-enrollment</li>
        </ul>
      </div>

      <h4>Part 4: Bypass Codes (Temporary Access)</h4>

      <div class="step">
        <strong>Step 4.1:</strong> Generate Temporary Bypass Code
        <ul>
          <li>In Okta Admin Console, navigate to user profile</li>
          <li>Click <strong>Security</strong> tab</li>
          <li>Under <strong>Factor Enrollments</strong>, click <strong>Actions</strong></li>
          <li>Select <strong>Generate Temporary Access Code</strong> (if available)</li>
          <li>Note: Feature availability depends on Okta configuration</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.2:</strong> Communicate Code to User
        <ul>
          <li>Securely share bypass code with user (phone call, secure chat)</li>
          <li>Inform user of code expiration time</li>
          <li>Instruct user to use code for one-time access</li>
          <li>Emphasize re-enrolling MFA immediately after access</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 4.3:</strong> User Uses Bypass Code
        <ul>
          <li>User attempts desktop login</li>
          <li>Enters local password</li>
          <li>At MFA challenge, enters bypass code instead of MFA</li>
          <li>Gains temporary access</li>
          <li>Immediately re-enrolls MFA factors</li>
        </ul>
      </div>

      <h4>Part 5: Emergency Access Procedures</h4>

      <div class="step">
        <strong>Step 5.1:</strong> Local Administrator Override (Windows)
        <ul>
          <li>If user completely locked out of Windows:</li>
          <li>Boot into Safe Mode or use local admin account</li>
          <li>Disable Okta Verify Credential Provider temporarily:</li>
        </ul>
        <pre><code># Disable Okta Credential Provider
Set-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{Okta-GUID}" -Name "Disabled" -Value 1

# Or stop Okta Verify service
Stop-Service OktaVerify
Set-Service OktaVerify -StartupType Disabled</code></pre>
        <ul>
          <li>User can now login with local password only</li>
          <li>Re-enroll Okta Verify</li>
          <li>Re-enable credential provider</li>
        </ul>
      </div>

      <div class="step">
        <strong>Step 5.2:</strong> Recovery Mode (macOS)
        <ul>
          <li>Boot into Recovery Mode (Cmd+R at startup)</li>
          <li>Open Terminal from Utilities menu</li>
          <li>Remove Okta configuration profile:</li>
        </ul>
        <pre><code>profiles remove -identifier com.okta.OktaVerify</code></pre>
        <ul>
          <li>Reboot normally</li>
          <li>User can login without MFA</li>
          <li>Re-deploy profile and re-enroll</li>
        </ul>
        <p><strong>Warning:</strong> This should only be used in true emergency scenarios</p>
      </div>

      <h3>Expected Outcomes</h3>
      <ul>
        <li>Understanding of multiple recovery paths</li>
        <li>Successfully tested recovery PIN functionality</li>
        <li>Completed self-service MFA reset process</li>
        <li>Performed admin-initiated unlock and reset</li>
        <li>Documented recovery procedures for helpdesk</li>
        <li>Established emergency access protocols</li>
      </ul>

      <h3>Recovery Decision Matrix</h3>

      <div class="decision-matrix">
        <table style="width: 100%; border-collapse: collapse;">
          <tr style="background: #f0f0f0;">
            <th style="padding: 10px; border: 1px solid #ddd;">Scenario</th>
            <th style="padding: 10px; border: 1px solid #ddd;">User Self-Service</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Helpdesk Action</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Admin Action</th>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Mobile device lost</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Use recovery PIN temporarily</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Guide through self-service reset</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Reset MFA if self-service unavailable</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Mobile offline</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Use recovery PIN or TOTP</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Remind user of offline options</td>
            <td style="padding: 10px; border: 1px solid #ddd;">No action needed</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Can't receive push</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Switch to TOTP in Okta Verify</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Troubleshoot push notifications</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Check user's authenticator config</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Enrollment corrupted</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Attempt re-enrollment</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Walk through re-enrollment</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Reset factor and redeploy profile</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Account locked</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Wait for auto-unlock period</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Verify identity, request unlock</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Unlock account immediately</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Complete lockout</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Contact helpdesk</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Escalate to admin</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Emergency access procedure</td>
          </tr>
        </table>
      </div>

      <h3>Best Practices for Recovery</h3>

      <div class="best-practices">
        <h4>For End Users:</h4>
        <ul>
          <li>Generate and save recovery PIN when setting up Desktop MFA</li>
          <li>Store recovery PIN separately from device (password manager)</li>
          <li>Enroll multiple MFA factors (Okta Verify + SMS + security key)</li>
          <li>Keep mobile Okta Verify app updated</li>
          <li>Test offline access periodically</li>
          <li>Know helpdesk contact information</li>
        </ul>

        <h4>For Helpdesk:</h4>
        <ul>
          <li>Verify user identity before resetting MFA</li>
          <li>Document all recovery actions in ticket system</li>
          <li>Guide users through self-service when possible</li>
          <li>Have escalation path to Okta admins</li>
          <li>Maintain recovery procedure documentation</li>
          <li>Track common recovery scenarios for process improvement</li>
        </ul>

        <h4>For Administrators:</h4>
        <ul>
          <li>Enable self-service MFA reset with appropriate verification</li>
          <li>Configure account lockout policies appropriately</li>
          <li>Set up monitoring for excessive lockouts</li>
          <li>Document emergency access procedures</li>
          <li>Maintain break-glass admin accounts</li>
          <li>Test recovery procedures regularly</li>
          <li>Communicate recovery options to end users proactively</li>
        </ul>
      </div>

      <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
        <p><strong>Related Labs:</strong></p>
        <ul>
          <li>Lab 1: Configure Desktop MFA in Jamf Pro</li>
          <li>Lab 2: Set up Platform SSO for macOS</li>
          <li>Lab 3: Troubleshoot a Failed Registration</li>
          <li>Lab 4: Implement FastPass</li>
          <li>Lab 5: Configure Desktop MFA for Windows in Intune</li>
        </ul>
      </div>
    `,
    tags: ['labs', 'hands-on', 'training', 'desktop-mfa', 'platform-sso', 'troubleshooting', 'jamf', 'intune', 'macos', 'windows'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-mdm-cheat-sheet',
    title: 'MDM Payload Quick Reference for Okta Device Access',
    category: 'quick-reference',
    content: `
      <h1>MDM Payload Quick Reference for Okta Device Access</h1>

      <div class="info-box">
        <h3>About This Reference</h3>
        <p>This quick reference guide provides comprehensive details on MDM configuration payload keys for Okta Device Access deployment. Use this as your go-to resource when configuring Desktop MFA, Platform SSO, and FastPass in your MDM solution.</p>
      </div>

      <h2>Desktop MFA Plist Keys (macOS)</h2>

      <h3>Core Configuration Keys</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key Name</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Data Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Required</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Example Value</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>OrgUrl</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Your Okta organization URL</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>https://company.okta.com</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnableDesktopAuth</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enable Desktop MFA authentication</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnabledFactors</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Array</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">MFA factors to enable (push, totp, sms)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>["push", "totp"]</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>GracePeriodMinutes</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Time before MFA required after enrollment</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>60</code> (1 hour)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnablePasswordSync</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Sync macOS password with Okta password</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>false</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnableFastPass</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enable passwordless FastPass authentication</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnableUserVerification</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Require biometric for user verification</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>RequireUserVerification</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enforce user verification for all auth</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
      </table>

      <h3>Advanced Configuration Keys</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key Name</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Data Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Required</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Example Value</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>OfflineAuthEnabled</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Allow offline authentication with cached credentials</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>OfflineAuthDurationDays</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Number of days offline auth is valid</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>7</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>AutoUpdateEnabled</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enable automatic Okta Verify updates</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>LogLevel</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Logging verbosity (error, warning, info, debug)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>info</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>ShowNotifications</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Display user-facing notifications</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>HideFromDock</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Hide Okta Verify icon from macOS Dock</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>false</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>RequireBiometric</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Require Touch ID/Face ID for Okta Verify</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>ProxyConfiguration</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Dictionary</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Custom proxy settings for network access</td>
          <td style="padding: 10px; border: 1px solid #ddd;">See Proxy Config section</td>
        </tr>
      </table>

      <h3>Complete plist Example</h3>

      <pre><code>&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"&gt;
&lt;plist version="1.0"&gt;
&lt;dict&gt;
    &lt;key&gt;OrgUrl&lt;/key&gt;
    &lt;string&gt;https://company.okta.com&lt;/string&gt;

    &lt;key&gt;EnableDesktopAuth&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;EnabledFactors&lt;/key&gt;
    &lt;array&gt;
        &lt;string&gt;push&lt;/string&gt;
        &lt;string&gt;totp&lt;/string&gt;
    &lt;/array&gt;

    &lt;key&gt;GracePeriodMinutes&lt;/key&gt;
    &lt;integer&gt;60&lt;/integer&gt;

    &lt;key&gt;EnablePasswordSync&lt;/key&gt;
    &lt;false/&gt;

    &lt;key&gt;EnableFastPass&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;EnableUserVerification&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;RequireUserVerification&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;OfflineAuthEnabled&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;OfflineAuthDurationDays&lt;/key&gt;
    &lt;integer&gt;7&lt;/integer&gt;

    &lt;key&gt;AutoUpdateEnabled&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;LogLevel&lt;/key&gt;
    &lt;string&gt;info&lt;/string&gt;

    &lt;key&gt;ShowNotifications&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;RequireBiometric&lt;/key&gt;
    &lt;true/&gt;
&lt;/dict&gt;
&lt;/plist&gt;</code></pre>

      <h2>Platform SSO Payload Keys (macOS)</h2>

      <h3>Extensible SSO Configuration</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key Name</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Data Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Required</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Example Value</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>ExtensionIdentifier</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta Verify Platform SSO extension ID</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>com.okta.OktaVerify.OktaVerifyPlatformSSO</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>TeamIdentifier</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta's Apple Team ID</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>4WE73L84WQ</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>Type</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Extension type</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>Redirect</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>URLs</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Array</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta domain URLs for SSO</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>["https://company.okta.com"]</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>ScreenLockedBehavior</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Behavior when screen is locked (DoNotHandle, Authenticate)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>Authenticate</code></td>
        </tr>
      </table>

      <h3>Extension Data Dictionary Keys</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key Name</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Data Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Required</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Example Value</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>oktaURL</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Primary Okta organization URL</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>https://company.okta.com</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>registrationMode</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">How users register (userInitiated, automatic)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>userInitiated</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>enableSecureEnclaveKeys</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Boolean</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Store keys in Secure Enclave</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>accountDisplayName</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Display name for SSO account</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>Okta SSO Account</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>usernameAttribute</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Attribute for username mapping</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>email</code></td>
        </tr>
      </table>

      <h3>Platform SSO Profile Example</h3>

      <pre><code>&lt;key&gt;ExtensionIdentifier&lt;/key&gt;
&lt;string&gt;com.okta.OktaVerify.OktaVerifyPlatformSSO&lt;/string&gt;

&lt;key&gt;TeamIdentifier&lt;/key&gt;
&lt;string&gt;4WE73L84WQ&lt;/string&gt;

&lt;key&gt;Type&lt;/key&gt;
&lt;string&gt;Redirect&lt;/string&gt;

&lt;key&gt;URLs&lt;/key&gt;
&lt;array&gt;
    &lt;string&gt;https://company.okta.com&lt;/string&gt;
    &lt;string&gt;https://company.okta-emea.com&lt;/string&gt;
&lt;/array&gt;

&lt;key&gt;ExtensionData&lt;/key&gt;
&lt;dict&gt;
    &lt;key&gt;oktaURL&lt;/key&gt;
    &lt;string&gt;https://company.okta.com&lt;/string&gt;

    &lt;key&gt;registrationMode&lt;/key&gt;
    &lt;string&gt;userInitiated&lt;/string&gt;

    &lt;key&gt;enableSecureEnclaveKeys&lt;/key&gt;
    &lt;true/&gt;

    &lt;key&gt;accountDisplayName&lt;/key&gt;
    &lt;string&gt;Okta SSO Account&lt;/string&gt;
&lt;/dict&gt;</code></pre>

      <h2>Windows Registry Keys (Intune OMA-URI)</h2>

      <h3>Desktop MFA Registry Configuration</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Registry Key</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Data Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Required</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Description</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Example Value</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>OrgUrl</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta organization URL</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>https://company.okta.com</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnableDesktopAuth</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enable Desktop MFA (1=enabled, 0=disabled)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>1</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnabledFactors</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">String</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Comma-separated list of factors</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>push,totp</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>GracePeriodMinutes</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Grace period in minutes</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>60</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnablePasswordSync</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enable password synchronization</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>0</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>EnableFastPass</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Enable FastPass</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>1</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>RequireUserVerification</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Require Windows Hello for FastPass</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>1</code></td>
        </tr>
      </table>

      <h3>OMA-URI Path Template</h3>

      <p>All keys follow this OMA-URI path format:</p>
      <pre><code>./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/[KeyName]</code></pre>

      <h3>Complete OMA-URI Examples</h3>

      <pre><code>Name: Okta Organization URL
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/OrgUrl
Data type: String
Value: https://company.okta.com

Name: Enable Desktop Authentication
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/EnableDesktopAuth
Data type: Integer
Value: 1

Name: Enabled Factors
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/EnabledFactors
Data type: String
Value: push,totp

Name: Grace Period Minutes
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/GracePeriodMinutes
Data type: Integer
Value: 60

Name: Enable FastPass
OMA-URI: ./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/EnableFastPass
Data type: Integer
Value: 1</code></pre>

      <h2>Platform-Specific Differences</h2>

      <h3>Jamf Pro vs Microsoft Intune vs Kandji</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Aspect</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Jamf Pro</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Microsoft Intune</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Kandji</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Configuration Format</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">XML plist</td>
          <td style="padding: 10px; border: 1px solid #ddd;">OMA-URI (Windows)<br/>plist (macOS)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">JSON or plist</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Profile Type</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Application & Custom Settings</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Custom Configuration Profile</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Custom Profile</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Preference Domain</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>com.okta.OktaVerify</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">N/A (uses OMA-URI on Windows)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>com.okta.OktaVerify</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Boolean Values</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>&lt;true/&gt;</code> or <code>&lt;false/&gt;</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Integer (1/0) for Windows<br/><code>&lt;true/&gt;</code> for macOS</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code> or <code>false</code> (JSON)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Array Format</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>&lt;array&gt;&lt;string&gt;...&lt;/string&gt;&lt;/array&gt;</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Comma-separated string (Windows)</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>["item1", "item2"]</code> (JSON)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Deployment Method</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Configuration Profile</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Configuration Profile + App deployment</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Custom Profile or Library Item</td>
        </tr>
      </table>

      <h2>Common Value Examples</h2>

      <h3>Factor Lists</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Configuration</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">macOS (Array)</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Windows (String)</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">Push notifications only</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>&lt;array&gt;&lt;string&gt;push&lt;/string&gt;&lt;/array&gt;</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>push</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">Push and TOTP</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>&lt;array&gt;&lt;string&gt;push&lt;/string&gt;&lt;string&gt;totp&lt;/string&gt;&lt;/array&gt;</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>push,totp</code></td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">All factors</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>&lt;array&gt;&lt;string&gt;push&lt;/string&gt;&lt;string&gt;totp&lt;/string&gt;&lt;string&gt;sms&lt;/string&gt;&lt;/array&gt;</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>push,totp,sms</code></td>
        </tr>
      </table>

      <h3>Grace Period Common Values</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Duration</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Value (Minutes)</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Use Case</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">No grace period</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>0</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Immediate MFA enforcement (testing, high security)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">30 minutes</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>30</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Quick user onboarding window</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">1 hour</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>60</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Standard grace period</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">1 day</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>1440</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Generous onboarding for large rollouts</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">1 week</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>10080</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Extended pilot/testing period</td>
        </tr>
      </table>

      <h3>Offline Authentication Settings</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Setting</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Recommended Value</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Notes</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>OfflineAuthEnabled</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>true</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Essential for users who travel or work remotely</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>OfflineAuthDurationDays</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>7</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Balance between security and usability</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">High security environment</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>1-3 days</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Shorter duration for sensitive environments</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;">Remote workforce</td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>14-30 days</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Longer for distributed teams with connectivity challenges</td>
        </tr>
      </table>

      <h2>Quick Troubleshooting Reference</h2>

      <h3>Missing or Wrong Keys</h3>

      <div class="troubleshooting-ref">
        <h4>Symptom: Profile installs but Okta Verify doesn't detect org</h4>
        <p><strong>Check:</strong></p>
        <ul>
          <li>OrgUrl key is present and spelled correctly (case-sensitive)</li>
          <li>URL includes https:// protocol</li>
          <li>URL doesn't have trailing slash</li>
          <li>Domain matches your Okta org exactly</li>
        </ul>
        <p><strong>Verify on macOS:</strong></p>
        <pre><code>defaults read com.okta.OktaVerify OrgUrl</code></pre>
        <p><strong>Verify on Windows:</strong></p>
        <pre><code>Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "OrgUrl"</code></pre>

        <h4>Symptom: Desktop MFA not triggering at login</h4>
        <p><strong>Check:</strong></p>
        <ul>
          <li>EnableDesktopAuth is set to <code>true</code> (macOS) or <code>1</code> (Windows)</li>
          <li>GracePeriodMinutes has expired or set to 0</li>
          <li>Device is enrolled in Okta Verify</li>
          <li>User is within policy scope in Okta</li>
        </ul>

        <h4>Symptom: Wrong factors appearing</h4>
        <p><strong>Check:</strong></p>
        <ul>
          <li>EnabledFactors array/string format is correct for platform</li>
          <li>Factor names are lowercase (push, totp, sms)</li>
          <li>No spaces in Windows comma-separated list</li>
          <li>Factors are enabled in Okta admin console</li>
        </ul>
      </div>

      <h3>Format Errors</h3>

      <div class="format-errors">
        <h4>Common plist Errors (macOS)</h4>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr style="background: #f0f0f0;">
            <th style="padding: 10px; border: 1px solid #ddd;">Error</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Cause</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Fix</th>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Profile fails to install</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Malformed XML</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Validate plist syntax with <code>plutil</code> or online validator</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Key not recognized</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Typo in key name</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Check exact spelling and case from this reference</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Boolean not working</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Using <code>&lt;boolean&gt;true&lt;/boolean&gt;</code></td>
            <td style="padding: 10px; border: 1px solid #ddd;">Use <code>&lt;true/&gt;</code> or <code>&lt;false/&gt;</code> tags</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Array items not loading</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Missing <code>&lt;string&gt;</code> tags</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Each array item needs <code>&lt;string&gt;value&lt;/string&gt;</code></td>
          </tr>
        </table>

        <h4>Common OMA-URI Errors (Windows/Intune)</h4>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
          <tr style="background: #f0f0f0;">
            <th style="padding: 10px; border: 1px solid #ddd;">Error</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Cause</th>
            <th style="padding: 10px; border: 1px solid #ddd;">Fix</th>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Policy not applying</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Incorrect OMA-URI path</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Ensure exact path: <code>./Device/Vendor/MSFT/Registry/HKLM/Software/Okta/Okta Verify/[Key]</code></td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Boolean key not working</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Using Boolean data type</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Use Integer type with values 1 (true) or 0 (false)</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Key name has spaces</td>
            <td style="padding: 10px; border: 1px solid #ddd;">OMA-URI doesn't escape spaces</td>
            <td style="padding: 10px; border: 1px solid #ddd;">"Okta Verify" in path should have space as-is</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Value not set</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Wrong data type selected</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Match data type exactly from table above</td>
          </tr>
        </table>
      </div>

      <div class="best-practices-box" style="margin-top: 30px; padding: 20px; background: #e8f5e9; border-radius: 8px;">
        <h3>Best Practices</h3>
        <ul>
          <li><strong>Version control:</strong> Keep copies of your MDM profiles in version control</li>
          <li><strong>Test first:</strong> Always deploy to test group before production rollout</li>
          <li><strong>Document changes:</strong> Track which settings you modify and why</li>
          <li><strong>Validate syntax:</strong> Use plist validators before uploading to MDM</li>
          <li><strong>Start simple:</strong> Begin with minimal required keys, add optional features gradually</li>
          <li><strong>Monitor deployment:</strong> Check MDM logs and device status after deployment</li>
          <li><strong>Keep reference:</strong> Bookmark this page and Okta's official documentation</li>
        </ul>
      </div>
    `,
    tags: ['quick-reference', 'mdm', 'configuration', 'plist', 'oma-uri', 'jamf', 'intune', 'kandji', 'cheat-sheet'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-troubleshooting-commands',
    title: 'Troubleshooting Command Reference for Okta Device Access',
    category: 'quick-reference',
    content: `
      <h1>Troubleshooting Command Reference for Okta Device Access</h1>

      <div class="info-box">
        <h3>About This Reference</h3>
        <p>This quick reference provides essential diagnostic commands for troubleshooting Okta Device Access issues on Windows and macOS. Bookmark this page for quick access when diagnosing registration, authentication, or configuration problems.</p>
      </div>

      <h2>Windows Diagnostic Commands</h2>

      <h3>Service Management</h3>

      <h4>Check Okta Verify Service Status</h4>
      <pre><code># PowerShell
Get-Service OktaVerify

# Expected output (Running):
Status   Name               DisplayName
------   ----               -----------
Running  OktaVerify         Okta Verify</code></pre>

      <h4>Restart Okta Verify Service</h4>
      <pre><code># PowerShell (as Administrator)
Restart-Service OktaVerify

# Verify restart
Get-Service OktaVerify</code></pre>

      <h4>Set Service to Automatic Startup</h4>
      <pre><code># PowerShell (as Administrator)
Set-Service OktaVerify -StartupType Automatic

# Verify setting
Get-Service OktaVerify | Select-Object Name, Status, StartType</code></pre>

      <h4>View Service Details</h4>
      <pre><code># PowerShell
Get-WmiObject Win32_Service | Where-Object {$_.Name -eq "OktaVerify"} | Format-List *</code></pre>

      <h3>Registry Configuration</h3>

      <h4>View All Okta Verify Registry Keys</h4>
      <pre><code># PowerShell
Get-ItemProperty "HKLM:\\SOFTWARE\\Okta\\Okta Verify" | Format-List</code></pre>

      <h4>Check Specific Configuration Values</h4>
      <pre><code># Organization URL
Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "OrgUrl"

# Desktop Auth Enabled
Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "EnableDesktopAuth"

# Enabled Factors
Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "EnabledFactors"

# Grace Period
Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "GracePeriodMinutes"</code></pre>

      <h4>Verify Credential Provider Registration</h4>
      <pre><code># PowerShell
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\*" |
  Where-Object {$_.PSChildName -like "*Okta*" -or $_.Default -like "*Okta*"} |
  Format-List</code></pre>

      <h3>Event Viewer Logs</h3>

      <h4>View Recent Okta Verify Events</h4>
      <pre><code># PowerShell
Get-WinEvent -LogName "Okta Verify" -MaxEvents 20 | Format-Table TimeCreated, LevelDisplayName, Message -AutoSize</code></pre>

      <h4>Filter for Errors Only</h4>
      <pre><code># PowerShell
Get-WinEvent -LogName "Okta Verify" |
  Where-Object {$_.LevelDisplayName -eq "Error"} |
  Select-Object TimeCreated, Message |
  Format-List</code></pre>

      <h4>Export Logs to File</h4>
      <pre><code># PowerShell
Get-WinEvent -LogName "Okta Verify" -MaxEvents 100 |
  Export-Csv C:\\Users\\Public\\okta-verify-logs.csv -NoTypeInformation</code></pre>

      <h4>Search for Specific Events</h4>
      <pre><code># Search for registration events
Get-WinEvent -LogName "Okta Verify" |
  Where-Object {$_.Message -like "*registration*"} |
  Select-Object TimeCreated, Message

# Search for authentication failures
Get-WinEvent -LogName "Okta Verify" |
  Where-Object {$_.Message -like "*failed*" -or $_.Message -like "*error*"} |
  Select-Object TimeCreated, Message</code></pre>

      <h3>Network Connectivity</h3>

      <h4>Test Okta Domain Connectivity</h4>
      <pre><code># PowerShell
Test-NetConnection your-domain.okta.com -Port 443

# Expected output includes:
# TcpTestSucceeded : True</code></pre>

      <h4>DNS Resolution Check</h4>
      <pre><code># PowerShell
Resolve-DnsName your-domain.okta.com

# Or using nslookup
nslookup your-domain.okta.com</code></pre>

      <h4>Test HTTPS Connection with Details</h4>
      <pre><code># PowerShell
$response = Invoke-WebRequest -Uri "https://your-domain.okta.com/.well-known/okta-organization" -UseBasicParsing
$response.StatusCode  # Should return 200

# Curl alternative
curl -I https://your-domain.okta.com</code></pre>

      <h3>Okta Verify Application</h3>

      <h4>Check Installed Version</h4>
      <pre><code># PowerShell
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" |
  Where-Object {$_.DisplayName -like "*Okta Verify*"} |
  Select-Object DisplayName, DisplayVersion, InstallDate</code></pre>

      <h4>Find Installation Path</h4>
      <pre><code># PowerShell
Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" |
  Where-Object {$_.DisplayName -like "*Okta Verify*"} |
  Select-Object InstallLocation</code></pre>

      <h4>Check Running Processes</h4>
      <pre><code># PowerShell
Get-Process | Where-Object {$_.ProcessName -like "*Okta*"} |
  Select-Object ProcessName, Id, StartTime, Path</code></pre>

      <h2>macOS Diagnostic Commands</h2>

      <h3>Configuration Profiles</h3>

      <h4>List All Installed Profiles</h4>
      <pre><code># Terminal
sudo profiles -L

# Filter for Okta profiles
sudo profiles -L | grep -i okta</code></pre>

      <h4>View Full Profile Configuration</h4>
      <pre><code># Terminal
sudo profiles show

# View specific profile
sudo profiles show -type configuration</code></pre>

      <h4>Check Okta Verify Preferences</h4>
      <pre><code># Terminal
defaults read com.okta.OktaVerify

# Check specific keys
defaults read com.okta.OktaVerify OrgUrl
defaults read com.okta.OktaVerify EnableDesktopAuth
defaults read com.okta.OktaVerify EnabledFactors</code></pre>

      <h4>Verify Profile Installation Status</h4>
      <pre><code># Terminal
sudo profiles status

# Check MDM enrollment
sudo profiles show -type enrollment</code></pre>

      <h3>Platform SSO Extension</h3>

      <h4>Check Platform SSO Status</h4>
      <pre><code># Terminal
app-sso platform -s

# Expected output for registered device:
# Platform SSO: Registered</code></pre>

      <h4>List SSO Keys</h4>
      <pre><code># Terminal
app-sso platform -l

# Shows keys stored in Secure Enclave</code></pre>

      <h4>View SSO Configuration</h4>
      <pre><code># Terminal
app-sso config -l

# Shows configured SSO extensions</code></pre>

      <h3>System Extensions</h3>

      <h4>List System Extensions</h4>
      <pre><code># Terminal
systemextensionsctl list

# Filter for Okta
systemextensionsctl list | grep -i okta</code></pre>

      <h4>Check Extension Status</h4>
      <pre><code># Terminal
# View system extension info
system_profiler SPExtensionsDataType | grep -A 10 -i okta</code></pre>

      <h3>Console Logs</h3>

      <h4>View Recent Okta Verify Logs</h4>
      <pre><code># Terminal
log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 30m --info

# View with timestamps
log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 30m --style compact</code></pre>

      <h4>Filter for Errors Only</h4>
      <pre><code># Terminal
log show --predicate 'subsystem == "com.okta.OktaVerify" AND messageType == "Error"' --last 1h</code></pre>

      <h4>Monitor Logs in Real-Time</h4>
      <pre><code># Terminal
log stream --predicate 'subsystem == "com.okta.OktaVerify"' --level info</code></pre>

      <h4>Export Logs to File</h4>
      <pre><code># Terminal
log show --predicate 'subsystem == "com.okta.OktaVerify"' --last 1h > ~/Desktop/okta-logs.txt</code></pre>

      <h4>Search for Specific Events</h4>
      <pre><code># Registration events
log show --predicate 'subsystem == "com.okta.OktaVerify" AND message CONTAINS "registration"' --last 1h

# Authentication events
log show --predicate 'subsystem == "com.okta.OktaVerify" AND message CONTAINS "authentication"' --last 30m

# FastPass events
log show --predicate 'subsystem == "com.okta.OktaVerify" AND message CONTAINS "FastPass"' --last 30m</code></pre>

      <h4>Platform SSO Logs</h4>
      <pre><code># Terminal
log show --predicate 'subsystem == "com.apple.AppSSO"' --last 30m

# Filter for authentication events
log show --predicate 'subsystem == "com.apple.AppSSO" AND message CONTAINS "auth"' --last 1h</code></pre>

      <h3>Network Connectivity</h3>

      <h4>Test Okta Domain Connectivity</h4>
      <pre><code># Terminal
ping -c 4 your-domain.okta.com

# DNS lookup
nslookup your-domain.okta.com</code></pre>

      <h4>Test HTTPS Connection</h4>
      <pre><code># Terminal
curl -I https://your-domain.okta.com

# Verbose output with timing
curl -v https://your-domain.okta.com/.well-known/okta-organization</code></pre>

      <h4>Check Proxy Settings</h4>
      <pre><code># Terminal
networksetup -getwebproxy Wi-Fi
networksetup -getsecurewebproxy Wi-Fi</code></pre>

      <h3>Okta Verify Application</h3>

      <h4>Check Installation</h4>
      <pre><code># Terminal
ls -la /Applications/Okta\ Verify.app

# Check version
defaults read /Applications/Okta\ Verify.app/Contents/Info.plist CFBundleShortVersionString</code></pre>

      <h4>Check Running Processes</h4>
      <pre><code># Terminal
ps aux | grep -i okta

# More detailed process info
pgrep -lf Okta</code></pre>

      <h4>View Application Info</h4>
      <pre><code># Terminal
system_profiler SPApplicationsDataType | grep -A 10 "Okta Verify"</code></pre>

      <h2>Log File Locations</h2>

      <h3>Windows Log Paths</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Log Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Location</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Contents</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Verify Event Log</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Event Viewer → Applications and Services Logs → Okta Verify</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Registration, authentication, service events</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Application Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>%LOCALAPPDATA%\\Okta\\Okta Verify\\logs</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Detailed application logs</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Service Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>%ProgramData%\\Okta\\Okta Verify\\logs</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Service-level operations</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>System Event Log</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Event Viewer → Windows Logs → System</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Service start/stop, system-level errors</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Application Event Log</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Event Viewer → Windows Logs → Application</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Application crashes, errors</td>
        </tr>
      </table>

      <h3>macOS Log Paths</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Log Type</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Access Method</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Contents</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Verify Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Console.app → Search for "OktaVerify"</td>
          <td style="padding: 10px; border: 1px solid #ddd;">All Okta Verify application events</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Unified Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>log show</code> command</td>
          <td style="padding: 10px; border: 1px solid #ddd;">System-wide logging subsystem</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Platform SSO Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Console.app → Search for "AppSSO"</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Platform SSO extension events</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>System Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>/var/log/system.log</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">General system events (older macOS)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Install Logs</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;"><code>/var/log/install.log</code></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Package installation events</td>
        </tr>
      </table>

      <h2>Common Diagnostic Scenarios</h2>

      <h3>Scenario 1: Registration Fails</h3>

      <div class="diagnostic-scenario">
        <h4>Step 1: Verify Configuration</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-ItemProperty "HKLM:\\SOFTWARE\\Okta\\Okta Verify" | Format-List</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>defaults read com.okta.OktaVerify
sudo profiles -L | grep -i okta</code></pre>

        <h4>Step 2: Check Network Connectivity</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Test-NetConnection your-domain.okta.com -Port 443</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>curl -I https://your-domain.okta.com</code></pre>

        <h4>Step 3: Review Logs</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-WinEvent -LogName "Okta Verify" | Where-Object {$_.Message -like "*registration*"} | Select-Object TimeCreated, Message</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>log show --predicate 'subsystem == "com.okta.OktaVerify" AND message CONTAINS "registration"' --last 30m</code></pre>

        <h4>Step 4: Restart Service/Application</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Restart-Service OktaVerify</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>killall "Okta Verify"
open -a "Okta Verify"</code></pre>
      </div>

      <h3>Scenario 2: Authentication Fails</h3>

      <div class="diagnostic-scenario">
        <h4>Step 1: Verify Service Status</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-Service OktaVerify</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>ps aux | grep -i "Okta Verify"</code></pre>

        <h4>Step 2: Check Desktop Auth Configuration</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "EnableDesktopAuth"</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>defaults read com.okta.OktaVerify EnableDesktopAuth</code></pre>

        <h4>Step 3: Review Authentication Logs</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-WinEvent -LogName "Okta Verify" | Where-Object {$_.Message -like "*auth*"} | Select-Object TimeCreated, LevelDisplayName, Message</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>log show --predicate 'subsystem == "com.okta.OktaVerify" AND message CONTAINS "auth"' --last 1h</code></pre>

        <h4>Step 4: Test Network Connection</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Test-NetConnection your-domain.okta.com -Port 443
Invoke-WebRequest -Uri "https://your-domain.okta.com/.well-known/okta-organization"</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>curl -v https://your-domain.okta.com/.well-known/okta-organization</code></pre>
      </div>

      <h3>Scenario 3: Password Sync Issues</h3>

      <div class="diagnostic-scenario">
        <h4>Step 1: Verify Password Sync Enabled</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-ItemPropertyValue "HKLM:\\SOFTWARE\\Okta\\Okta Verify" -Name "EnablePasswordSync"</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>defaults read com.okta.OktaVerify EnablePasswordSync</code></pre>

        <h4>Step 2: Check for Sync Errors</h4>
        <p><strong>Windows:</strong></p>
        <pre><code>Get-WinEvent -LogName "Okta Verify" | Where-Object {$_.Message -like "*password*" -or $_.Message -like "*sync*"}</code></pre>
        <p><strong>macOS:</strong></p>
        <pre><code>log show --predicate 'subsystem == "com.okta.OktaVerify" AND (message CONTAINS "password" OR message CONTAINS "sync")' --last 1h</code></pre>

        <h4>Step 3: Verify Network Connectivity</h4>
        <p><strong>Both platforms:</strong></p>
        <pre><code># Test connection during password change
# Monitor logs in real-time during password sync attempt</code></pre>
      </div>

      <h2>Quick Fixes</h2>

      <h3>Restart Okta Verify Service</h3>

      <div class="quick-fix">
        <p><strong>Windows:</strong></p>
        <pre><code># PowerShell (as Administrator)
Restart-Service OktaVerify

# Alternative: Services management console
services.msc
# Find "Okta Verify" → Right-click → Restart</code></pre>

        <p><strong>macOS:</strong></p>
        <pre><code># Terminal
killall "Okta Verify"
sleep 2
open -a "Okta Verify"</code></pre>
      </div>

      <h3>Reinstall Configuration Profile</h3>

      <div class="quick-fix">
        <p><strong>macOS Only:</strong></p>
        <pre><code># Remove existing profile
sudo profiles remove -identifier com.okta.OktaVerify

# Trigger MDM to reinstall (Jamf example)
sudo jamf policy

# Verify reinstallation
sudo profiles -L | grep -i okta</code></pre>
      </div>

      <h3>Clear Okta Verify Cache</h3>

      <div class="quick-fix">
        <p><strong>Windows:</strong></p>
        <pre><code># PowerShell (as Administrator)
Stop-Service OktaVerify
Remove-Item "$env:LOCALAPPDATA\\Okta\\Okta Verify\\cache\\*" -Recurse -Force
Start-Service OktaVerify</code></pre>

        <p><strong>macOS:</strong></p>
        <pre><code># Terminal
killall "Okta Verify"
rm -rf ~/Library/Caches/com.okta.OktaVerify
open -a "Okta Verify"</code></pre>
      </div>

      <h3>Force MDM Sync</h3>

      <div class="quick-fix">
        <p><strong>Windows (Intune):</strong></p>
        <pre><code># Settings → Accounts → Access work or school → [Account] → Info → Sync

# Or via PowerShell
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Intune*"} | Start-ScheduledTask</code></pre>

        <p><strong>macOS (Jamf):</strong></p>
        <pre><code># Terminal
sudo jamf policy

# Or via Self Service app
# Open Self Service → Check for policies</code></pre>
      </div>

      <div class="tips-box" style="margin-top: 30px; padding: 20px; background: #fff3cd; border-radius: 8px;">
        <h3>Pro Tips</h3>
        <ul>
          <li><strong>Always run PowerShell as Administrator</strong> on Windows for diagnostic commands</li>
          <li><strong>Use <code>sudo</code></strong> on macOS for profile and system-level commands</li>
          <li><strong>Capture logs during reproduction</strong> - Start log monitoring before attempting the failing action</li>
          <li><strong>Check timestamps</strong> - Ensure log entries align with when the issue occurred</li>
          <li><strong>Export logs before making changes</strong> - Preserve state for comparison</li>
          <li><strong>Bookmark this page</strong> - Quick reference when troubleshooting in the field</li>
          <li><strong>Document your findings</strong> - Note which commands revealed the issue for future reference</li>
        </ul>
      </div>
    `,
    tags: ['quick-reference', 'troubleshooting', 'commands', 'diagnostics', 'windows', 'macos', 'logs', 'powershell', 'terminal'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-feature-comparison',
    title: 'Okta Device Access Feature Comparison Matrix',
    category: 'quick-reference',
    content: `
      <h1>Okta Device Access Feature Comparison Matrix</h1>

      <div class="info-box">
        <h3>About This Reference</h3>
        <p>This comprehensive comparison guide helps you understand the differences between Okta Device Access features, platform capabilities, MFA factors, MDM solutions, and deployment approaches. Use this to make informed decisions for your organization's implementation strategy.</p>
      </div>

      <h2>Desktop MFA vs Password Sync vs FastPass</h2>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Aspect</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Desktop MFA</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Password Sync</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">FastPass</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Authentication Method</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Local password + MFA factor</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta password (synced to local)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Passwordless (biometric + cryptographic key)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Password Management</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Separate local and Okta passwords</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Single password (Okta syncs to local)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No passwords required</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>MFA Required</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes (at every login or per policy)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No (unless separate policy requires it)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Biometric serves as MFA</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Platforms Supported</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Windows 10+, macOS 11+</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Windows 10+, macOS 11+</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Windows 10 1809+, macOS 13+ (Platform SSO)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Tenant Required</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Classic or OIE</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Classic or OIE</td>
          <td style="padding: 10px; border: 1px solid #ddd;">OIE only</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Hardware Requirements</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Mobile device for MFA enrollment</td>
          <td style="padding: 10px; border: 1px solid #ddd;">None (beyond basic OS requirements)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">TPM 2.0 (Windows) or T2/Apple Silicon (macOS)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Biometric Support</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Optional (can use for approving MFA)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Required (Windows Hello, Touch ID, Face ID)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Offline Access</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes (cached credentials + grace period)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes (local password cached)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes (cryptographic keys cached)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Security Level</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">High (MFA required)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium (single password)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Very High (FIDO2 compliant, phishing-resistant)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>User Experience</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Two steps: password + MFA approval</td>
          <td style="padding: 10px; border: 1px solid #ddd;">One step: password only</td>
          <td style="padding: 10px; border: 1px solid #ddd;">One step: biometric only</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Deployment Complexity</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Low</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium-High</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Best For</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Organizations requiring strong MFA without password changes</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Simplifying user experience with unified password</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Zero-trust environments, passwordless initiatives</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>License Cost</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta Verify included in Workforce Identity</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Okta Verify included in Workforce Identity</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Requires OIE license</td>
        </tr>
      </table>

      <h2>Windows vs macOS Capabilities</h2>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Feature</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Windows</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">macOS</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Notes</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Desktop MFA</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Fully supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Fully supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Feature parity across platforms</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Password Sync</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Fully supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Fully supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Feature parity across platforms</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>FastPass</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Via Windows Hello</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Via Touch ID/Face ID</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Platform-specific biometric integration</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Platform SSO</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✗ Not supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ macOS 13+ (Ventura)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Apple-exclusive feature</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Credential Provider</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Native integration</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Authorization plugin</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Different OS integration mechanisms</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Secure Key Storage</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">TPM 2.0</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Secure Enclave (T2/Apple Silicon)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Hardware-backed security on both</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>MDM Configuration</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Registry (OMA-URI)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Configuration Profile (plist)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Platform-native config methods</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Offline Duration</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Configurable (days)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Configurable (days)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Same offline capabilities</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>MFA Factors</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Push, TOTP, SMS</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Push, TOTP, SMS</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Same factor support</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Grace Period</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Configurable on both platforms</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Self-Service Recovery</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">✓ Supported</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Recovery PIN available on both</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Deployment Complexity</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium (Intune/SCCM)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium (Jamf/Intune)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Similar deployment effort</td>
        </tr>
      </table>

      <h2>MFA Factor Comparison</h2>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Factor</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Strengths</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Weaknesses</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Best Use Cases</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Offline Support</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Verify Push</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Simple user experience<br/>
            • Fast authentication<br/>
            • Number matching for phishing resistance<br/>
            • Doesn't require typing
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Requires mobile device online<br/>
            • Network dependent<br/>
            • Battery drain concern
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Standard corporate users<br/>
            • Office environments<br/>
            • Users with reliable connectivity
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Verify TOTP</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Works offline<br/>
            • No network required<br/>
            • Industry standard<br/>
            • Backup when push fails
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Requires typing 6-digit code<br/>
            • Time-sensitive (30-60 sec window)<br/>
            • Can be phished
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Offline scenarios<br/>
            • Backup factor<br/>
            • Users in low connectivity areas
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>FIDO2/WebAuthn</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Phishing-resistant<br/>
            • No shared secrets<br/>
            • Hardware-backed<br/>
            • Industry standard
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Requires hardware security key<br/>
            • Additional cost<br/>
            • Can be lost/forgotten<br/>
            • Limited offline
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • High-security environments<br/>
            • Admins and privileged users<br/>
            • Zero-trust initiatives
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">Limited</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>SMS</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Widely accessible<br/>
            • No app required<br/>
            • Works on basic phones
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Vulnerable to SIM swapping<br/>
            • Can be intercepted<br/>
            • Network dependent<br/>
            • Not recommended by NIST
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Fallback only<br/>
            • Users without smartphones<br/>
            • Low-security requirements
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">No</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>FastPass (Biometric)</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Passwordless<br/>
            • Phishing-resistant<br/>
            • Excellent UX<br/>
            • Hardware-backed<br/>
            • FIDO2 compliant
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Requires compatible hardware<br/>
            • Biometric enrollment needed<br/>
            • OIE tenant required<br/>
            • Limited fallback options
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Passwordless initiatives<br/>
            • Modern devices<br/>
            • Best-in-class security + UX
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">Yes (cached)</td>
        </tr>
      </table>

      <h2>MDM Solution Comparison</h2>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Aspect</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Jamf Pro</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Microsoft Intune</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Kandji</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Workspace ONE</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Platform Focus</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">macOS, iOS exclusive</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Cross-platform (Windows, macOS, iOS, Android)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">macOS, iOS exclusive</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Cross-platform (all major OS)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Ease of Configuration</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">High (Apple-focused UI)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium (complex for beginners)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Very High (modern, intuitive)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium (enterprise-focused)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Okta Integration</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (plist support)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good (OMA-URI for Windows, plist for macOS)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (JSON/plist, library items)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good (custom profiles)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Platform SSO Support</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good (macOS profiles)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>App Deployment</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">PKG, App Store apps</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Win32, MSI, macOS PKG</td>
          <td style="padding: 10px; border: 1px solid #ddd;">PKG, DMG, App Store</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Multi-format support</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Reporting & Analytics</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (detailed Apple insights)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (Microsoft ecosystem integration)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good (modern dashboards)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (enterprise analytics)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Self-Service Portal</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Jamf Self Service (native app)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Company Portal (web + app)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Self Service (native app)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Workspace ONE Intelligent Hub</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Pricing Model</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Per device/year (premium pricing)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Per user/month (bundled with M365)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Per device/month (competitive)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Per device (enterprise pricing)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Support Quality</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (Apple experts)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good (large support org)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Excellent (responsive, modern)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Good (enterprise-tier support)</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Best For</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Apple-only organizations, creative industries</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Microsoft 365 shops, cross-platform needs</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Modern Apple-focused orgs, SMBs</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Large enterprises, diverse device fleets</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Learning Curve</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Low-Medium (Apple admins)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium-High (complex UI)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Low (modern, intuitive)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Medium-High (feature-rich)</td>
        </tr>
      </table>

      <h2>Deployment Approach Comparison</h2>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Approach</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Pros</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Cons</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Best For</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Timeline</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Big Bang</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Fast implementation<br/>
            • Everyone on same version<br/>
            • Simpler project management<br/>
            • Clear cutover date
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • High risk if issues arise<br/>
            • Heavy support burden<br/>
            • Limited rollback options<br/>
            • All eggs in one basket
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Small organizations (&lt;100 users)<br/>
            • Homogeneous environment<br/>
            • Mature IT teams<br/>
            • Weekend deployment windows
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">1-2 weeks</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Phased Rollout</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Reduced risk<br/>
            • Learn from each phase<br/>
            • Manageable support load<br/>
            • Can adjust between phases
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Longer overall timeline<br/>
            • Version fragmentation<br/>
            • Multiple communication waves<br/>
            • Complexity tracking status
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Medium organizations (100-1000)<br/>
            • Multiple locations<br/>
            • Varying device types<br/>
            • Standard recommendation
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">4-12 weeks</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Pilot Program</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Test in production<br/>
            • Identify issues early<br/>
            • Build internal champions<br/>
            • Refine documentation<br/>
            • Minimal user impact
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Longest timeline<br/>
            • Pilot selection crucial<br/>
            • May delay benefits<br/>
            • Resource intensive
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Large organizations (1000+)<br/>
            • Complex environments<br/>
            • Risk-averse culture<br/>
            • First Okta deployment
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">12-24 weeks</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Opt-In/Voluntary</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • User choice empowerment<br/>
            • Enthusiasts first<br/>
            • Organic adoption<br/>
            • Lower resistance
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Slow adoption<br/>
            • May never reach 100%<br/>
            • Fragmented state<br/>
            • Difficult to mandate later
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Optional security features<br/>
            • Cultural fit organizations<br/>
            • Non-critical deployments<br/>
            • Feature testing
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">Ongoing</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Department by Department</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Clear boundaries<br/>
            • Department-specific support<br/>
            • Targeted communications<br/>
            • Easier to manage
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Political challenges<br/>
            • Who goes first?<br/>
            • Department dependencies<br/>
            • Uneven timeline
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">
            • Organizations with distinct departments<br/>
            • Decentralized IT<br/>
            • Varying security requirements
          </td>
          <td style="padding: 10px; border: 1px solid #ddd;">8-16 weeks</td>
        </tr>
      </table>

      <h3>Recommended Deployment Strategy by Organization Size</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #f0f0f0;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Organization Size</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Recommended Approach</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Phases</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key Considerations</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>&lt;100 users</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Big Bang or Small Pilot + Rollout</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Pilot (10-20 users) → Full deployment</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Quick wins, limited resources, direct communication possible</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>100-500 users</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Phased Rollout</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Pilot (20) → Phase 1 (20%) → Phase 2 (30%) → Phase 3 (50%)</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Balance speed and risk, learn between phases</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>500-2000 users</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Pilot + Phased Rollout</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Pilot (50) → Early Adopters (10%) → 4-6 phases</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Multiple locations, diverse devices, structured approach</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>2000+ users</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Extended Pilot + Phased</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Pilot (100) → Early Adopters (5%) → 6-10 phases by department/location</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Complex environment, change management critical, detailed planning</td>
        </tr>
      </table>

      <div class="decision-guide" style="margin-top: 30px; padding: 20px; background: #e3f2fd; border-radius: 8px;">
        <h3>Decision Guide: Which Feature Should You Deploy?</h3>

        <h4>Choose Desktop MFA if:</h4>
        <ul>
          <li>You need strong MFA at desktop login</li>
          <li>You're comfortable managing separate local and Okta passwords</li>
          <li>You're on Okta Classic or OIE</li>
          <li>Users have mobile devices for MFA enrollment</li>
        </ul>

        <h4>Choose Password Sync if:</h4>
        <ul>
          <li>You want to simplify user experience with one password</li>
          <li>MFA at every desktop login is too disruptive</li>
          <li>You have password policies enforced in Okta</li>
          <li>You're not ready for passwordless</li>
        </ul>

        <h4>Choose FastPass if:</h4>
        <ul>
          <li>You're pursuing passwordless authentication</li>
          <li>You have OIE tenant</li>
          <li>Devices support biometrics (Windows Hello, Touch ID, Face ID)</li>
          <li>You want phishing-resistant authentication</li>
          <li>Best security and UX is priority</li>
        </ul>

        <h4>Choose Platform SSO (macOS) if:</h4>
        <ul>
          <li>You're deploying on macOS 13+</li>
          <li>You want native Apple integration</li>
          <li>You need Okta password to unlock macOS</li>
          <li>You want seamless SSO to apps</li>
        </ul>
      </div>
    `,
    tags: ['quick-reference', 'comparison', 'features', 'mdm', 'deployment', 'planning', 'decision-guide'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-email-templates',
    title: 'Email Templates for Okta Device Access Sales',
    category: 'sales-tools',
    content: `
      <h2>Overview</h2>
      <p>This collection of email templates helps Solution Engineers communicate effectively throughout the sales cycle. Customize these templates based on your prospect's specific needs, industry, and pain points.</p>

      <h2>1. POC Proposal Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Proof of Concept Proposal - Okta Device Access for [Company Name]</p>

        <p>Hi [First Name],</p>

        <p>Thank you for your time on our recent call. Based on our discussion about [specific pain points: password reset tickets, lack of MFA at endpoint, etc.], I believe a Proof of Concept would be valuable to demonstrate how Okta Device Access can address these challenges.</p>

        <p><strong>Proposed POC Scope:</strong></p>
        <ul>
          <li><strong>Duration:</strong> 2-4 weeks</li>
          <li><strong>Pilot Group:</strong> 10-20 users (IT team or early adopters)</li>
          <li><strong>Features to Test:</strong>
            <ul>
              <li>Desktop MFA for Windows/macOS login</li>
              <li>[FastPass passwordless authentication - if applicable]</li>
              <li>[Password Sync - if applicable]</li>
            </ul>
          </li>
          <li><strong>Success Criteria:</strong>
            <ul>
              <li>Successful enrollment of pilot users</li>
              <li>MFA enforcement at device login</li>
              <li>User feedback on experience</li>
              <li>Integration with [their MDM solution]</li>
            </ul>
          </li>
        </ul>

        <p><strong>Value Proposition:</strong></p>
        <ul>
          <li>Reduce password reset tickets by up to 50% with Password Sync</li>
          <li>Enforce MFA at the most critical access point - the device itself</li>
          <li>Improve user experience with passwordless FastPass authentication</li>
          <li>Gain visibility into device security posture</li>
        </ul>

        <p><strong>Next Steps:</strong></p>
        <ol>
          <li>Review and approve POC scope</li>
          <li>Identify pilot user group</li>
          <li>Schedule kickoff meeting (1 hour)</li>
          <li>Okta provisions trial tenant</li>
        </ol>

        <p>Are you available next [day/time] to discuss the POC plan and answer any questions?</p>

        <p>Best regards,<br/>
        [Your Name]<br/>
        [Title]<br/>
        [Contact Info]</p>
      </div>

      <h2>2. Technical Follow-up Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Follow-up: Okta Device Access Demo & Technical Details</p>

        <p>Hi [First Name],</p>

        <p>Thank you for attending today's demonstration of Okta Device Access. I wanted to recap what we covered and provide the technical resources you requested.</p>

        <p><strong>Demo Summary:</strong></p>
        <ul>
          <li>Desktop MFA with Okta Verify - Showed how users authenticate at Windows/macOS login with biometrics</li>
          <li>FastPass Passwordless - Demonstrated phishing-resistant authentication flow</li>
          <li>MDM Integration - Walked through [Jamf/Intune] configuration and policy deployment</li>
          <li>Admin Experience - Reviewed policy configuration and reporting dashboards</li>
        </ul>

        <p><strong>Addressing Your Questions:</strong></p>
        <ul>
          <li><strong>Q: How does this work with our existing AD/Azure AD?</strong><br/>
          A: Okta integrates via LDAP/AD connector or Azure AD integration. User identities remain in your existing directory.</li>

          <li><strong>Q: What happens if a user loses their phone?</strong><br/>
          A: Users can authenticate with backup factors (SMS, email, or help desk can reset). We can also configure offline access policies.</li>

          <li><strong>Q: Can we enforce device compliance checks?</strong><br/>
          A: Yes, Okta integrates with your MDM to verify disk encryption, OS version, and other compliance attributes before granting access.</li>
        </ul>

        <p><strong>Resources:</strong></p>
        <ul>
          <li><a href="#">Okta Device Access Technical Overview (PDF)</a></li>
          <li><a href="#">Deployment Guide for [Jamf/Intune]</a></li>
          <li><a href="#">Architecture Diagram</a></li>
          <li><a href="#">Security & Compliance Whitepaper</a></li>
        </ul>

        <p><strong>Next Steps:</strong></p>
        <ol>
          <li>Share these materials with your security and IT teams</li>
          <li>Schedule follow-up with technical stakeholders (if needed)</li>
          <li>Discuss POC timeline and scope</li>
        </ol>

        <p>I'm available [day/time] if you'd like to dive deeper into any specific area. What works best for your schedule?</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h2>3. Executive Summary Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Executive Summary: Okta Device Access Business Value for [Company Name]</p>

        <p>Hi [Executive Name],</p>

        <p>I've been working with [First Name] and [their team] on Okta Device Access. I wanted to share a brief executive summary of the business value and outcomes we can deliver for [Company Name].</p>

        <p><strong>Business Challenge:</strong></p>
        <p>[Company Name] is experiencing [specific challenges: high password reset volume, endpoint security gaps, compliance requirements, user friction, etc.]. This impacts productivity, security posture, and operational costs.</p>

        <p><strong>Okta Device Access Solution:</strong></p>
        <ul>
          <li><strong>Enhanced Security:</strong> MFA at device login, phishing-resistant authentication, device trust verification</li>
          <li><strong>Improved User Experience:</strong> Single password (or passwordless), biometric authentication, seamless access</li>
          <li><strong>Operational Efficiency:</strong> Reduce help desk tickets, automate provisioning, centralized management</li>
        </ul>

        <p><strong>Expected ROI:</strong></p>
        <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
          <tr style="background: #e3f2fd;">
            <th style="padding: 10px; text-align: left; border: 1px solid #ddd;">Metric</th>
            <th style="padding: 10px; text-align: left; border: 1px solid #ddd;">Current State</th>
            <th style="padding: 10px; text-align: left; border: 1px solid #ddd;">With Okta</th>
            <th style="padding: 10px; text-align: left; border: 1px solid #ddd;">Annual Savings</th>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Password Reset Tickets</td>
            <td style="padding: 10px; border: 1px solid #ddd;">[X] tickets/month</td>
            <td style="padding: 10px; border: 1px solid #ddd;">50% reduction</td>
            <td style="padding: 10px; border: 1px solid #ddd;">$[amount]</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Time Saved per User</td>
            <td style="padding: 10px; border: 1px solid #ddd;">5 min/day</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Single sign-on</td>
            <td style="padding: 10px; border: 1px solid #ddd;">$[amount]</td>
          </tr>
          <tr>
            <td style="padding: 10px; border: 1px solid #ddd;">Security Incidents</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Phishing risk</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Phishing-resistant</td>
            <td style="padding: 10px; border: 1px solid #ddd;">Risk mitigation</td>
          </tr>
        </table>

        <p><strong>Customer Success Stories:</strong></p>
        <ul>
          <li><strong>[Similar Company/Industry]:</strong> Reduced password-related tickets by 60%, achieved SOC2 compliance</li>
          <li><strong>[Another Reference]:</strong> Deployed to 5,000 users in 8 weeks, 95% user satisfaction</li>
        </ul>

        <p><strong>Recommended Next Step:</strong></p>
        <p>I'd like to schedule a brief 30-minute executive briefing to discuss how Okta Device Access aligns with [Company Name]'s strategic security and productivity initiatives.</p>

        <p>Would you have time in the next week or two?</p>

        <p>Best regards,<br/>
        [Your Name]<br/>
        [Title]</p>
      </div>

      <h2>4. Trial Extension Request Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Request: POC Extension for Okta Device Access</p>

        <p>Hi [First Name],</p>

        <p>I wanted to check in on the Okta Device Access POC progress. I see your trial is scheduled to end on [date], and I'd like to discuss extending it to ensure you can fully evaluate the solution.</p>

        <p><strong>Progress to Date:</strong></p>
        <ul>
          <li>[X] users successfully enrolled</li>
          <li>Desktop MFA tested on [Windows/macOS]</li>
          <li>[Feature] successfully configured and tested</li>
          <li>Positive feedback from pilot users</li>
        </ul>

        <p><strong>Rationale for Extension:</strong></p>
        <p>Based on our recent conversations, I understand you'd like to:</p>
        <ul>
          <li>Test with additional user groups in [department/location]</li>
          <li>Evaluate [specific feature] that wasn't in the initial scope</li>
          <li>Run parallel testing with [competing solution/current tool]</li>
          <li>Conduct security review with your [InfoSec/compliance] team</li>
        </ul>

        <p><strong>Proposed Extension:</strong></p>
        <ul>
          <li><strong>Additional Time:</strong> [2-4] weeks</li>
          <li><strong>New End Date:</strong> [date]</li>
          <li><strong>Additional Goals:</strong>
            <ul>
              <li>[Specific objective 1]</li>
              <li>[Specific objective 2]</li>
              <li>[Specific objective 3]</li>
            </ul>
          </li>
        </ul>

        <p>I can process the extension request today if this timeline works for you. Let me know if you need any additional support or resources during the extended trial.</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h2>5. Post-Demo Follow-up Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Thanks for Your Time - Okta Device Access Demo Recap</p>

        <p>Hi [First Name],</p>

        <p>Thank you for your time today! I enjoyed walking through how Okta Device Access can help [Company Name] achieve [specific goals discussed].</p>

        <p><strong>What We Covered:</strong></p>
        <ul>
          <li>Your current challenges with [pain points]</li>
          <li>How Desktop MFA works with [Windows/macOS]</li>
          <li>FastPass passwordless authentication [if applicable]</li>
          <li>Integration with your [MDM solution]</li>
          <li>Deployment approach for [X users]</li>
        </ul>

        <p><strong>Key Takeaways:</strong></p>
        <ul>
          <li>Okta Device Access extends your existing Okta investment to the device layer</li>
          <li>You can reduce password-related friction while improving security</li>
          <li>Deployment can be phased starting with [suggested pilot group]</li>
          <li>Integration with [their MDM] is straightforward using [method]</li>
        </ul>

        <p><strong>Addressing Your Questions:</strong></p>
        <ul>
          <li><strong>Offline access:</strong> Users can cache credentials for offline authentication (configurable duration)</li>
          <li><strong>User migration:</strong> We can migrate users gradually without impacting current workflows</li>
          <li><strong>Support requirements:</strong> Minimal ongoing support; most common issue is forgotten passwords (which decreases over time)</li>
        </ul>

        <p><strong>Next Actions:</strong></p>
        <ol>
          <li>I'll send over the [technical documentation/architecture diagram] you requested</li>
          <li>Review with your team and identify any additional questions</li>
          <li>Schedule follow-up to discuss POC or next steps</li>
        </ol>

        <p>What's the best next step from your perspective? I'm happy to schedule a technical deep-dive, prepare a POC proposal, or connect you with a reference customer.</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h2>6. Objection Response Email Templates</h2>

      <h3>Objection: "This seems expensive"</h3>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Re: Okta Device Access Pricing & ROI</p>

        <p>Hi [First Name],</p>

        <p>I appreciate you being candid about budget concerns. Let me break down the value and ROI to help frame the investment.</p>

        <p><strong>Cost Breakdown:</strong></p>
        <ul>
          <li>Okta Device Access: $[X] per user/year</li>
          <li>Part of broader Okta Workforce Identity solution</li>
          <li>Includes Okta Verify, Desktop MFA, FastPass, Password Sync</li>
        </ul>

        <p><strong>ROI Analysis:</strong></p>
        <ul>
          <li><strong>Help Desk Savings:</strong> 50% reduction in password resets = $[X]/year</li>
          <li><strong>Productivity Gains:</strong> 5 min/user/day saved = $[X]/year</li>
          <li><strong>Security Risk Mitigation:</strong> Phishing-resistant MFA reduces breach risk</li>
          <li><strong>Compliance:</strong> Meet MFA requirements for [SOC2/HIPAA/etc.]</li>
        </ul>

        <p><strong>Typical Payback Period:</strong> 6-12 months for most customers</p>

        <p>Would it be helpful to build a custom ROI model based on your specific metrics? I can work with you to quantify the business case.</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h3>Objection: "We already have MFA"</h3>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Re: Extending MFA to the Device Layer</p>

        <p>Hi [First Name],</p>

        <p>That's great that you have MFA for applications! Many of our customers were in the same position. Here's what they found:</p>

        <p><strong>The Gap:</strong></p>
        <p>Most organizations have MFA for cloud apps and VPN, but the device login itself often remains unprotected with just a password. This creates a significant vulnerability:</p>
        <ul>
          <li>Stolen credentials can access the device</li>
          <li>Local applications and data are accessible without MFA</li>
          <li>Device is the gateway to everything else</li>
        </ul>

        <p><strong>What Okta Device Access Adds:</strong></p>
        <ul>
          <li>MFA at the device login screen (Windows/macOS)</li>
          <li>Phishing-resistant FastPass authentication</li>
          <li>Device trust signals integrated with your existing Okta policies</li>
          <li>Unified authentication experience across device and apps</li>
        </ul>

        <p><strong>Think of it this way:</strong> You lock the front door to your house (device) and the rooms inside (apps). Okta Device Access ensures both are protected.</p>

        <p>Would you be open to a brief call to discuss how this complements your existing MFA strategy?</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h3>Objection: "Too complex to deploy"</h3>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Re: Okta Device Access Deployment Simplicity</p>

        <p>Hi [First Name],</p>

        <p>I understand deployment complexity is a concern. Let me share how straightforward this actually is, especially with your existing [MDM solution].</p>

        <p><strong>Deployment Overview:</strong></p>
        <ol>
          <li><strong>Configure Okta Policies</strong> (1-2 hours) - Set up authentication and MFA policies in Okta admin console</li>
          <li><strong>Deploy via MDM</strong> (1 hour) - Push Okta Verify configuration via [Jamf/Intune/etc.]</li>
          <li><strong>Pilot Testing</strong> (1-2 weeks) - Test with 10-20 users</li>
          <li><strong>Phased Rollout</strong> (4-8 weeks) - Gradually deploy to all users</li>
        </ol>

        <p><strong>What Makes It Easy:</strong></p>
        <ul>
          <li>No changes to Active Directory or domain controllers</li>
          <li>Leverages your existing MDM for deployment</li>
          <li>Users enroll themselves (guided experience)</li>
          <li>Okta provides deployment guides and best practices</li>
          <li>I'll be with you every step of the way</li>
        </ul>

        <p><strong>Customer Example:</strong></p>
        <p>[Similar Company] deployed to 2,000 users in 6 weeks with a team of 2 IT admins. They reported it was easier than expected.</p>

        <p>Would a technical walkthrough of the deployment process help address your concerns?</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h2>7. Reference Request Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Customer Reference for Okta Device Access</p>

        <p>Hi [First Name],</p>

        <p>Based on our conversation, I think it would be valuable for you to hear directly from a customer who has successfully deployed Okta Device Access in a similar environment.</p>

        <p><strong>Suggested Reference:</strong></p>
        <ul>
          <li><strong>Company:</strong> [Company Name]</li>
          <li><strong>Industry:</strong> [Similar industry]</li>
          <li><strong>Size:</strong> [Similar user count]</li>
          <li><strong>Environment:</strong> [Similar tech stack - MDM, devices, etc.]</li>
          <li><strong>Use Case:</strong> [Similar challenges they solved]</li>
        </ul>

        <p><strong>What They Achieved:</strong></p>
        <ul>
          <li>Deployed to [X] users in [Y] weeks</li>
          <li>Reduced password reset tickets by [X]%</li>
          <li>Achieved [compliance requirement]</li>
          <li>[Other relevant metrics]</li>
        </ul>

        <p><strong>Discussion Topics:</strong></p>
        <p>You can ask them about:</p>
        <ul>
          <li>Deployment process and challenges</li>
          <li>User adoption and feedback</li>
          <li>Integration with [their MDM/environment]</li>
          <li>Ongoing management and support</li>
          <li>ROI and business impact</li>
        </ul>

        <p>I'll coordinate the introduction if you're interested. Would a 30-minute call work for you?</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h2>8. Contract Renewal Email</h2>

      <div class="email-template" style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Subject:</strong> Okta Device Access Renewal & Expansion Opportunities</p>

        <p>Hi [First Name],</p>

        <p>I wanted to reach out as your Okta Device Access contract is coming up for renewal on [date]. I've been reviewing your usage and success metrics, and wanted to share some highlights.</p>

        <p><strong>Your Success Over the Past Year:</strong></p>
        <ul>
          <li><strong>Users Enrolled:</strong> [X] users actively using Desktop MFA/FastPass</li>
          <li><strong>Authentication Events:</strong> [X] successful device logins</li>
          <li><strong>Help Desk Impact:</strong> [X]% reduction in password reset tickets</li>
          <li><strong>Security Posture:</strong> MFA enforced at device layer across your fleet</li>
        </ul>

        <p><strong>Renewal Details:</strong></p>
        <ul>
          <li><strong>Current License Count:</strong> [X] users</li>
          <li><strong>Renewal Date:</strong> [date]</li>
          <li><strong>Renewal Options:</strong> 1-year, 2-year, or 3-year terms (discounts available for multi-year)</li>
        </ul>

        <p><strong>Expansion Opportunities:</strong></p>
        <p>Based on your current deployment, here are some areas to consider:</p>
        <ul>
          <li><strong>Additional Users:</strong> Expand from [current] to [target] users</li>
          <li><strong>Additional Features:</strong> [FastPass upgrade, Platform SSO for macOS, etc.]</li>
          <li><strong>Additional Platforms:</strong> [Extend to contractors, Linux devices, etc.]</li>
        </ul>

        <p><strong>New Capabilities Since You Purchased:</strong></p>
        <ul>
          <li>[New feature 1] - [Brief description and value]</li>
          <li>[New feature 2] - [Brief description and value]</li>
          <li>[Integration update] - [Brief description]</li>
        </ul>

        <p>I'd like to schedule time to review your renewal and discuss how we can continue to deliver value. Are you available next week for a brief call?</p>

        <p>Best regards,<br/>
        [Your Name]</p>
      </div>

      <h2>Email Best Practices</h2>

      <div class="best-practices" style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>General Guidelines</h3>
        <ul>
          <li><strong>Personalize:</strong> Always customize with specific details from your conversations</li>
          <li><strong>Be Concise:</strong> Busy executives appreciate brevity; technical folks may want more detail</li>
          <li><strong>Clear Call to Action:</strong> Every email should have a clear next step</li>
          <li><strong>Timing:</strong> Follow up within 24 hours of meetings; send mid-week (Tue-Thu) for best response</li>
          <li><strong>Subject Lines:</strong> Be specific and action-oriented</li>
          <li><strong>Formatting:</strong> Use bullet points, bold key items, keep paragraphs short</li>
          <li><strong>Value First:</strong> Lead with value and outcomes, not features</li>
          <li><strong>Proof Points:</strong> Include customer examples, metrics, and case studies when relevant</li>
          <li><strong>Response Path:</strong> Make it easy to respond (specific questions, suggested times, simple yes/no)</li>
        </ul>

        <h3>Email Cadence</h3>
        <ul>
          <li><strong>After Demo:</strong> Same day or within 24 hours</li>
          <li><strong>After POC Kickoff:</strong> Weekly check-ins</li>
          <li><strong>After POC Completion:</strong> Within 48 hours with results summary</li>
          <li><strong>Follow-up if No Response:</strong> Wait 3-5 business days, then send brief follow-up</li>
          <li><strong>Executive Summary:</strong> After technical validation is complete</li>
        </ul>

        <h3>What to Avoid</h3>
        <ul>
          <li>Don't send generic templated emails without customization</li>
          <li>Don't overwhelm with too much technical jargon (match their level)</li>
          <li>Don't include too many attachments (send links instead)</li>
          <li>Don't write novels (keep under 300 words when possible)</li>
          <li>Don't be pushy or aggressive in tone</li>
          <li>Don't forget to proofread (typos undermine credibility)</li>
        </ul>
      </div>
    `,
    tags: ['sales-tools', 'email-templates', 'communication', 'poc', 'objection-handling', 'follow-up', 'best-practices'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-presentation-guide',
    title: 'Presentation Deck Guide for Okta Device Access',
    category: 'sales-tools',
    content: `
      <h2>Overview</h2>
      <p>This guide helps Solution Engineers create and deliver effective presentations for different audiences and stages of the sales cycle. Choose the right deck structure based on your audience and objectives.</p>

      <h2>1. Executive Overview Deck (5-10 Slides)</h2>

      <div class="deck-structure" style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>Purpose</h3>
        <p>High-level business value presentation for C-level executives and decision makers. Focus on outcomes, not features.</p>

        <h3>Audience</h3>
        <ul>
          <li>CIO, CISO, CTO</li>
          <li>VP of IT/Security</li>
          <li>Business executives</li>
        </ul>

        <h3>Duration</h3>
        <p>15-20 minutes presentation + 10 minutes Q&A</p>

        <h3>Slide-by-Slide Breakdown</h3>

        <h4>Slide 1: Title Slide</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Presentation title: "Okta Device Access: Modern Endpoint Security for [Company Name]"</li>
          <li>Your name and title</li>
          <li>Date</li>
          <li>Optional: Their logo (builds rapport)</li>
        </ul>

        <h4>Slide 2: The Challenge</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Start with their specific pain points (discovered in previous conversations)</li>
          <li>3-4 key challenges they face</li>
          <li>Business impact of these challenges (cost, risk, productivity)</li>
        </ul>
        <p><strong>Example Content:</strong></p>
        <ul>
          <li>"Help desk overwhelmed with 500+ password reset tickets per month"</li>
          <li>"Device endpoints lack MFA protection - growing security gap"</li>
          <li>"Users manage multiple passwords - friction and security risk"</li>
          <li>"Compliance requirements mandate stronger device authentication"</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>Acknowledge you've heard these challenges from them</li>
          <li>Quantify the impact where possible</li>
          <li>Set up the "why now" urgency</li>
        </ul>

        <h4>Slide 3: The Solution - Okta Device Access</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>High-level description: "Modern authentication for Windows and macOS devices"</li>
          <li>Key capabilities (3-4 bullets, outcomes-focused):
            <ul>
              <li>Multi-factor authentication at device login</li>
              <li>Passwordless authentication with biometrics</li>
              <li>Unified identity across devices and applications</li>
              <li>Device trust and compliance verification</li>
            </ul>
          </li>
          <li>Visual: Simple diagram showing user → device → apps flow</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>Position as extension of their existing Okta investment (if applicable)</li>
          <li>Emphasize "unified" and "modern" approach</li>
          <li>Mention it works with their existing MDM</li>
        </ul>

        <h4>Slide 4: Business Value</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Three value pillars with metrics:
            <ul>
              <li><strong>Enhanced Security:</strong> Phishing-resistant MFA, device trust, reduced breach risk</li>
              <li><strong>Improved User Experience:</strong> Single password or passwordless, faster logins, less friction</li>
              <li><strong>Operational Efficiency:</strong> 50% reduction in password tickets, automated provisioning, centralized management</li>
            </ul>
          </li>
          <li>Use icons/visuals for each pillar</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>Connect each value point back to their stated challenges</li>
          <li>Share specific customer metrics where relevant</li>
          <li>Emphasize the "win-win" of security + user experience</li>
        </ul>

        <h4>Slide 5: ROI Summary</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Simple table or visual showing:
            <ul>
              <li>Help desk savings: $X per year</li>
              <li>Productivity gains: $X per year</li>
              <li>Security risk reduction: Quantified or qualitative</li>
              <li>Total value: $X annually</li>
            </ul>
          </li>
          <li>Payback period: 6-12 months</li>
          <li>Note: "Based on [similar company size/industry] benchmarks"</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>"These are conservative estimates based on industry benchmarks"</li>
          <li>"We can build a custom model using your specific metrics"</li>
          <li>Mention intangible benefits (compliance, reduced risk, employee satisfaction)</li>
        </ul>

        <h4>Slide 6: Proof - Customer Success</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>2-3 customer logos (similar industry/size if possible)</li>
          <li>Brief case study highlights:
            <ul>
              <li>"[Healthcare company] deployed to 3,000 users in 8 weeks"</li>
              <li>"Reduced password tickets by 65%"</li>
              <li>"Achieved HIPAA compliance requirement for device MFA"</li>
            </ul>
          </li>
          <li>Pull quote from customer if available</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>Focus on relatable success stories</li>
          <li>Offer to connect them with reference customers</li>
          <li>Position as "proven" and "battle-tested"</li>
        </ul>

        <h4>Slide 7: How It Works (Optional Technical Slide)</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Simple 3-step process:
            <ol>
              <li>Deploy Okta Verify via MDM</li>
              <li>Users enroll with Okta credentials</li>
              <li>Authenticate at device login with MFA/biometrics</li>
            </ol>
          </li>
          <li>Clean visual/diagram</li>
          <li>Note: "No changes to Active Directory or domain controllers"</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>"Implementation is straightforward"</li>
          <li>"Leverages your existing infrastructure"</li>
          <li>"We have a proven deployment methodology"</li>
        </ul>

        <h4>Slide 8: Implementation Roadmap</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>High-level timeline:
            <ul>
              <li>Week 1-2: Planning and configuration</li>
              <li>Week 3-4: Pilot testing (20-50 users)</li>
              <li>Week 5-12: Phased rollout to all users</li>
              <li>Ongoing: Monitoring and optimization</li>
            </ul>
          </li>
          <li>Gantt chart or timeline visual</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>"Realistic timeline based on your organization size"</li>
          <li>"Phased approach minimizes risk and allows learning"</li>
          <li>"We'll be with you every step of the way"</li>
        </ul>

        <h4>Slide 9: Next Steps & Call to Action</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Clear recommended next steps:
            <ol>
              <li>Technical deep-dive with IT/security team</li>
              <li>Proof of Concept (2-4 weeks)</li>
              <li>Business case and ROI modeling</li>
            </ol>
          </li>
          <li>Proposed timeline for next steps</li>
          <li>Your contact information</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>"What makes the most sense as a next step for [Company Name]?"</li>
          <li>"I recommend starting with a POC to prove value in your environment"</li>
          <li>"I'm here to support you through the evaluation process"</li>
        </ul>

        <h4>Slide 10: Q&A / Discussion</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Simple "Questions?" slide</li>
          <li>Your contact info</li>
        </ul>
      </div>

      <h2>2. Technical Architecture Deck (10-15 Slides)</h2>

      <div class="deck-structure" style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>Purpose</h3>
        <p>Deep technical dive for IT architects, systems engineers, and security engineers. Focus on how it works, integration points, and technical requirements.</p>

        <h3>Audience</h3>
        <ul>
          <li>IT Architects</li>
          <li>Systems Engineers</li>
          <li>Security Engineers</li>
          <li>Desktop/Endpoint team</li>
        </ul>

        <h3>Duration</h3>
        <p>30-45 minutes presentation + 15-30 minutes Q&A</p>

        <h3>Key Slides to Include</h3>

        <h4>Slide 1-2: Title & Agenda</h4>
        <p>Set expectations for technical depth and topics to be covered.</p>

        <h4>Slide 3: Current State Assessment</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Diagram of their current environment (based on discovery):
            <ul>
              <li>Identity provider (AD, Azure AD, Okta)</li>
              <li>MDM solution (Jamf, Intune, Workspace ONE)</li>
              <li>Device types and OS versions</li>
              <li>Current authentication methods</li>
            </ul>
          </li>
          <li>Pain points and gaps in current architecture</li>
        </ul>

        <h4>Slide 4: Future State Architecture</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Comprehensive architecture diagram showing:
            <ul>
              <li>Okta as identity provider</li>
              <li>Okta Verify on endpoints</li>
              <li>MDM integration</li>
              <li>Directory integration (AD/Azure AD)</li>
              <li>Cloud applications</li>
              <li>On-prem applications (if applicable)</li>
            </ul>
          </li>
          <li>Data flows and authentication sequences</li>
        </ul>
        <p><strong>Talking Points:</strong></p>
        <ul>
          <li>Walk through authentication flow step-by-step</li>
          <li>Explain how components integrate</li>
          <li>Address any questions about data residency, latency, etc.</li>
        </ul>

        <h4>Slide 5: Desktop MFA Technical Deep-Dive</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>How Desktop MFA works:
            <ul>
              <li>Credential Provider (Windows) / Authorization Plugin (macOS)</li>
              <li>Okta Verify agent on device</li>
              <li>Authentication policy evaluation</li>
              <li>Factor prompts (push, biometric, etc.)</li>
            </ul>
          </li>
          <li>Sequence diagram of login flow</li>
          <li>Offline access capabilities</li>
        </ul>

        <h4>Slide 6: FastPass Passwordless (if applicable)</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>FastPass architecture and FIDO2/WebAuthn standards</li>
          <li>Biometric authentication flow (Windows Hello, Touch ID, Face ID)</li>
          <li>Public key cryptography overview</li>
          <li>Phishing resistance explanation</li>
        </ul>

        <h4>Slide 7: MDM Integration</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>How Okta integrates with their specific MDM:
            <ul>
              <li>Configuration profiles</li>
              <li>Policy deployment</li>
              <li>Device compliance checks</li>
              <li>Reporting integration</li>
            </ul>
          </li>
          <li>Specific technical steps for [Jamf/Intune/etc.]</li>
          <li>Example configurations/screenshots</li>
        </ul>

        <h4>Slide 8: Directory Integration</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>How Okta integrates with their directory:
            <ul>
              <li>AD: LDAP interface, AD connector, OU structure</li>
              <li>Azure AD: Native integration, sync options</li>
              <li>Hybrid: Best practices for hybrid environments</li>
            </ul>
          </li>
          <li>User provisioning and deprovisioning flows</li>
          <li>Group-based policy assignment</li>
        </ul>

        <h4>Slide 9: Security & Compliance</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Security architecture:
            <ul>
              <li>Encryption (in transit and at rest)</li>
              <li>Certificate-based authentication</li>
              <li>Key storage (TPM, Secure Enclave)</li>
              <li>Zero trust principles</li>
            </ul>
          </li>
          <li>Compliance certifications (SOC2, ISO 27001, FedRAMP, etc.)</li>
          <li>Audit logging and reporting</li>
        </ul>

        <h4>Slide 10: Device Trust & Conditional Access</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Device trust signals:
            <ul>
              <li>Device registration status</li>
              <li>Disk encryption (FileVault, BitLocker)</li>
              <li>OS version compliance</li>
              <li>Antivirus/EDR status</li>
              <li>Jailbreak/root detection</li>
            </ul>
          </li>
          <li>Policy examples: "Require managed device + disk encryption for access to sensitive apps"</li>
        </ul>

        <h4>Slide 11: Offline Access & Recovery</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Offline authentication capabilities:
            <ul>
              <li>Cached credential timeout</li>
              <li>Grace period configuration</li>
              <li>Biometric-based offline access</li>
            </ul>
          </li>
          <li>Recovery scenarios:
            <ul>
              <li>Lost device</li>
              <li>Lost phone (for MFA)</li>
              <li>Locked out user</li>
              <li>Help desk workflows</li>
            </ul>
          </li>
        </ul>

        <h4>Slide 12: Deployment Technical Requirements</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Minimum OS versions (Windows 10+, macOS 11+)</li>
          <li>Network requirements (ports, URLs to whitelist)</li>
          <li>MDM requirements and versions</li>
          <li>Active Directory/Azure AD requirements</li>
          <li>Certificate requirements (if applicable)</li>
          <li>Firewall/proxy considerations</li>
        </ul>

        <h4>Slide 13: Deployment Process & Timeline</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Detailed implementation phases:
            <ul>
              <li>Phase 1: Planning (1 week)
                <ul>
                  <li>Requirements gathering</li>
                  <li>Architecture design</li>
                  <li>Policy definition</li>
                </ul>
              </li>
              <li>Phase 2: Configuration (1-2 weeks)
                <ul>
                  <li>Okta tenant configuration</li>
                  <li>MDM profile creation</li>
                  <li>Testing in lab environment</li>
                </ul>
              </li>
              <li>Phase 3: Pilot (2-4 weeks)
                <ul>
                  <li>Deploy to 20-50 users</li>
                  <li>Gather feedback</li>
                  <li>Refine configuration</li>
                </ul>
              </li>
              <li>Phase 4: Rollout (4-8 weeks)
                <ul>
                  <li>Phased deployment by group</li>
                  <li>User communication</li>
                  <li>Support monitoring</li>
                </ul>
              </li>
            </ul>
          </li>
        </ul>

        <h4>Slide 14: Operations & Support</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Day 2 operations:
            <ul>
              <li>Monitoring and alerting</li>
              <li>User provisioning automation</li>
              <li>Policy updates and changes</li>
              <li>Troubleshooting common issues</li>
            </ul>
          </li>
          <li>Support model:
            <ul>
              <li>Okta support (24/7)</li>
              <li>Documentation and knowledge base</li>
              <li>Community resources</li>
            </ul>
          </li>
        </ul>

        <h4>Slide 15: Q&A and Technical Discussion</h4>
        <p>Leave ample time for technical questions and whiteboard discussions.</p>
      </div>

      <h2>3. Security Benefits Deck (8-12 Slides)</h2>

      <div class="deck-structure" style="background: #f0f4ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>Purpose</h3>
        <p>Security-focused presentation for CISOs and security teams. Emphasize threat mitigation, compliance, and risk reduction.</p>

        <h3>Audience</h3>
        <ul>
          <li>CISO</li>
          <li>Security architects</li>
          <li>Compliance team</li>
          <li>Risk management</li>
        </ul>

        <h3>Duration</h3>
        <p>25-30 minutes presentation + 15-20 minutes Q&A</p>

        <h3>Key Slides to Include</h3>

        <h4>Slide 1-2: Title & Security Landscape</h4>
        <p>Open with current threat landscape and endpoint security challenges.</p>

        <h4>Slide 3: The Endpoint Security Gap</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Statistics on endpoint-based attacks:
            <ul>
              <li>70% of breaches start at the endpoint</li>
              <li>Credential theft is #1 attack vector</li>
              <li>Average cost of breach: $4.45M (IBM 2023)</li>
            </ul>
          </li>
          <li>Diagram showing the gap: "You protect cloud apps with MFA, but what about the device itself?"</li>
          <li>Real-world attack scenarios (phishing, stolen credentials, insider threat)</li>
        </ul>

        <h4>Slide 4: Threat Mitigation with Okta Device Access</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>How Okta Device Access mitigates specific threats:
            <ul>
              <li><strong>Credential Theft:</strong> MFA at device login prevents stolen passwords from being useful</li>
              <li><strong>Phishing:</strong> FastPass is phishing-resistant (FIDO2/WebAuthn)</li>
              <li><strong>Insider Threat:</strong> Device trust and continuous verification</li>
              <li><strong>Ransomware:</strong> Prevent unauthorized device access</li>
              <li><strong>Lost/Stolen Devices:</strong> Require MFA even if device is unlocked</li>
            </ul>
          </li>
          <li>Use MITRE ATT&CK framework references if audience is sophisticated</li>
        </ul>

        <h4>Slide 5: Zero Trust Architecture</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>How Okta Device Access fits into zero trust model:
            <ul>
              <li>Verify explicitly (MFA always)</li>
              <li>Least privileged access (device + user context)</li>
              <li>Assume breach (continuous verification)</li>
            </ul>
          </li>
          <li>Device trust as part of security posture</li>
          <li>Integration with other zero trust controls (network, application, data)</li>
        </ul>

        <h4>Slide 6: Compliance & Regulatory Benefits</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>How Okta Device Access helps meet compliance requirements:
            <ul>
              <li><strong>HIPAA:</strong> Access controls (§164.312(a)(1)), audit logs (§164.312(b))</li>
              <li><strong>SOC 2:</strong> Access control (CC6.1), logical security (CC6.6)</li>
              <li><strong>PCI-DSS:</strong> MFA for non-console access (8.3)</li>
              <li><strong>NIST CSF:</strong> Identity management and access control (PR.AC)</li>
              <li><strong>CMMC:</strong> Multi-factor authentication (AC.2.016)</li>
              <li><strong>GDPR:</strong> Security of processing (Article 32)</li>
            </ul>
          </li>
          <li>Audit trail and reporting capabilities</li>
        </ul>

        <h4>Slide 7: Phishing-Resistant Authentication</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Why traditional MFA isn't enough (push fatigue, MFA bypass attacks)</li>
          <li>How FastPass provides phishing resistance:
            <ul>
              <li>FIDO2/WebAuthn standards-based</li>
              <li>Public key cryptography</li>
              <li>Origin binding prevents man-in-the-middle</li>
            </ul>
          </li>
          <li>Recent high-profile phishing attacks that bypassed traditional MFA</li>
          <li>Executive order and government mandate trends toward phishing-resistant MFA</li>
        </ul>

        <h4>Slide 8: Device Trust & Context-Aware Policies</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Device trust signals Okta can evaluate:
            <ul>
              <li>Device managed by MDM</li>
              <li>Disk encryption enabled</li>
              <li>OS up to date</li>
              <li>Antivirus/EDR running</li>
              <li>Device location</li>
              <li>Time of access</li>
            </ul>
          </li>
          <li>Example policies:
            <ul>
              <li>"Only allow access to financial systems from managed, encrypted devices"</li>
              <li>"Block access if device is jailbroken or rooted"</li>
              <li>"Require additional MFA if accessing from unusual location"</li>
            </ul>
          </li>
        </ul>

        <h4>Slide 9: Security Operations Benefits</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Enhanced visibility:
            <ul>
              <li>Centralized authentication logs</li>
              <li>Device inventory and status</li>
              <li>Failed authentication attempts</li>
              <li>Anomaly detection</li>
            </ul>
          </li>
          <li>Integration with SIEM/SOAR tools</li>
          <li>Incident response capabilities (revoke access, force re-auth, lock device)</li>
          <li>Audit trail for forensics</li>
        </ul>

        <h4>Slide 10: Risk Reduction & ROI</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Quantify security risk reduction:
            <ul>
              <li>Reduced likelihood of credential-based breaches</li>
              <li>Faster incident detection and response</li>
              <li>Decreased attack surface</li>
            </ul>
          </li>
          <li>Cost avoidance:
            <ul>
              <li>Average breach cost: $4.45M</li>
              <li>Even 10% risk reduction = $445K value</li>
            </ul>
          </li>
          <li>Insurance and compliance benefits (lower premiums, easier audits)</li>
        </ul>

        <h4>Slide 11: Implementation Security Best Practices</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Security considerations during deployment:
            <ul>
              <li>Phased rollout for risk mitigation</li>
              <li>Backup authentication methods</li>
              <li>Security team involvement in policy design</li>
              <li>Monitoring during rollout</li>
            </ul>
          </li>
          <li>Long-term security hygiene:
            <ul>
              <li>Regular policy reviews</li>
              <li>Stay current with Okta security updates</li>
              <li>User security awareness training</li>
            </ul>
          </li>
        </ul>

        <h4>Slide 12: Next Steps & Security Review</h4>
        <p><strong>What to Include:</strong></p>
        <ul>
          <li>Offer security-specific next steps:
            <ul>
              <li>Security architecture review with your team</li>
              <li>Compliance mapping workshop</li>
              <li>POC with security testing scenarios</li>
            </ul>
          </li>
          <li>Security resources: Whitepapers, certifications, penetration test results</li>
        </ul>
      </div>

      <h2>Presentation Delivery Best Practices</h2>

      <div class="best-practices" style="background: #fff3e0; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>Before the Presentation</h3>
        <ul>
          <li><strong>Know Your Audience:</strong> Research attendees on LinkedIn, understand their roles and priorities</li>
          <li><strong>Customize Content:</strong> Never deliver a generic deck - tailor to their industry, challenges, and environment</li>
          <li><strong>Practice:</strong> Rehearse at least once, especially for executive presentations</li>
          <li><strong>Test Technology:</strong> Check screen sharing, demo environment, connectivity 30 minutes before</li>
          <li><strong>Prepare Backup:</strong> Have PDF version ready in case of tech issues</li>
          <li><strong>Set Expectations:</strong> Share agenda upfront, ask about time constraints</li>
        </ul>

        <h3>During the Presentation</h3>
        <ul>
          <li><strong>Start Strong:</strong> Begin with their challenges, not your company/product</li>
          <li><strong>Tell Stories:</strong> Use customer examples and real-world scenarios, not just bullet points</li>
          <li><strong>Be Concise:</strong> Executives appreciate brevity; technical folks want depth. Adjust accordingly.</li>
          <li><strong>Visual > Text:</strong> Use diagrams, screenshots, and visuals. Avoid text-heavy slides.</li>
          <li><strong>Pause for Questions:</strong> Invite questions throughout, don't wait until the end</li>
          <li><strong>Read the Room:</strong> Watch for engagement signals. Speed up if they're bored, slow down if confused.</li>
          <li><strong>Bridge to Demo:</strong> When possible, transition from slides to live demo to show real product</li>
          <li><strong>Handle Objections:</strong> Address concerns with empathy and evidence, not defensiveness</li>
        </ul>

        <h3>After the Presentation</h3>
        <ul>
          <li><strong>Send Follow-up:</strong> Within 24 hours, send summary and next steps</li>
          <li><strong>Share Deck:</strong> Provide PDF version (but remove confidential customer info)</li>
          <li><strong>Include Resources:</strong> Add links to documentation, whitepapers, case studies</li>
          <li><strong>Schedule Next Meeting:</strong> Try to book the next call before you hang up</li>
          <li><strong>Internal Debrief:</strong> Document feedback, concerns, and key takeaways for the team</li>
        </ul>
      </div>

      <h2>Customization Tips</h2>

      <h3>Industry-Specific Customization</h3>

      <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background: #e3f2fd;">
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Industry</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Key Talking Points</th>
          <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Relevant Use Cases</th>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Healthcare</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">HIPAA compliance, patient privacy, shared workstations, fast user switching</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Clinical workstation access, EHR security, mobile clinician devices</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Financial Services</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">SOC 2, PCI-DSS, phishing-resistant MFA, zero trust, insider threat</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Trader workstations, remote banking, privileged access</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Education</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Student data protection (FERPA), shared lab computers, budget constraints</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Computer lab security, faculty/staff devices, student privacy</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Retail</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">POS security, shift workers, minimal friction, seasonal workforce</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Store POS systems, back-office devices, distribution centers</td>
        </tr>
        <tr>
          <td style="padding: 10px; border: 1px solid #ddd;"><strong>Technology</strong></td>
          <td style="padding: 10px; border: 1px solid #ddd;">Modern security, developer experience, API integration, rapid deployment</td>
          <td style="padding: 10px; border: 1px solid #ddd;">Developer workstations, contractor access, BYOD</td>
        </tr>
      </table>

      <h3>Persona-Specific Customization</h3>

      <ul>
        <li><strong>For CIOs:</strong> Focus on digital transformation, user experience, operational efficiency, total cost of ownership</li>
        <li><strong>For CISOs:</strong> Emphasize threat mitigation, zero trust, compliance, risk reduction, security operations</li>
        <li><strong>For IT Directors:</strong> Highlight ease of deployment, integration with existing tools, help desk reduction, manageability</li>
        <li><strong>For Architects:</strong> Deep-dive on technical architecture, integration patterns, scalability, API capabilities</li>
        <li><strong>For End User Computing Teams:</strong> Focus on user experience, device management integration, pilot success, rollout strategy</li>
      </ul>

      <h3>Company Size Customization</h3>

      <ul>
        <li><strong>SMB (< 500 users):</strong> Emphasize simplicity, quick time-to-value, SaaS model (no infrastructure), affordable pricing</li>
        <li><strong>Mid-Market (500-2000):</strong> Balance of sophistication and ease, phased approach, proven methodology, reference customers</li>
        <li><strong>Enterprise (2000+):</strong> Scalability, global deployment, integration with complex environments, enterprise support, strategic partnership</li>
      </ul>

      <div class="tips" style="background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3>Pro Tips for Great Presentations</h3>
        <ul>
          <li><strong>Use Their Terminology:</strong> If they call it "endpoint" vs "device", match their language</li>
          <li><strong>Show, Don't Tell:</strong> One demo is worth a thousand slides</li>
          <li><strong>Quantify Everything:</strong> Turn qualitative benefits into quantitative metrics whenever possible</li>
          <li><strong>Create Urgency:</strong> Tie to business initiatives, compliance deadlines, or upcoming projects</li>
          <li><strong>Leave Room for Discovery:</strong> Don't pack slides so tight there's no time for conversation</li>
          <li><strong>End with Clear CTA:</strong> Never end a presentation without a clear next step</li>
          <li><strong>Build Champions:</strong> Identify and empower internal advocates who can champion the project</li>
        </ul>
      </div>
    `,
    tags: ['sales-tools', 'presentations', 'decks', 'executive-summary', 'technical-architecture', 'security', 'delivery-best-practices'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-shared-devices-scenario',
    title: 'Advanced Scenario: Shared Device Environments',
    content: `
      <h2>Overview</h2>
      <p>Shared device environments present unique challenges for identity and access management. This guide provides detailed strategies for implementing Okta Device Access in shared workstation scenarios across different industries.</p>

      <h2>Healthcare Shared Workstations</h2>

      <h3>Environment Characteristics</h3>
      <ul>
        <li><strong>Clinical workflows:</strong> Nurses, physicians, and staff share workstations on wheels (WOWs)</li>
        <li><strong>HIPAA requirements:</strong> Individual accountability for all PHI access</li>
        <li><strong>Fast user switching:</strong> Users need to switch quickly between patients</li>
        <li><strong>24/7 operations:</strong> Cannot disrupt patient care for maintenance</li>
        <li><strong>Mobility:</strong> Devices move between rooms, floors, and buildings</li>
      </ul>

      <h3>Technical Configuration</h3>
      <ul>
        <li><strong>Desktop MFA policy:</strong> Require MFA for all users, no grace periods on shared devices</li>
        <li><strong>Factor selection:</strong> Okta Verify Push (fastest for clinicians with phones) + TOTP backup</li>
        <li><strong>Session management:</strong> Auto-logout after 5-15 minutes of inactivity</li>
        <li><strong>Fast user switching:</strong> Configure Windows/macOS to allow quick switch without full logout</li>
        <li><strong>Offline support:</strong> Enable offline factors for areas with poor connectivity</li>
      </ul>

      <h3>User Experience Optimization</h3>
      <ul>
        <li><strong>Login speed:</strong> Optimize for <5 second authentication</li>
        <li><strong>QR code alternative:</strong> Provide TOTP for users without phones</li>
        <li><strong>Visual cues:</strong> Clear indication of which user is logged in</li>
        <li><strong>Training:</strong> 2-minute quick-start video on entering patient rooms</li>
        <li><strong>Support availability:</strong> 24/7 help desk coverage for clinical staff</li>
      </ul>

      <h3>Implementation Guide</h3>
      <ol>
        <li><strong>Week 1-2:</strong> Pilot with IT-friendly clinical unit (e.g., outpatient clinic)</li>
        <li><strong>Week 3-4:</strong> Gather feedback, adjust session timeouts based on workflow observation</li>
        <li><strong>Week 5-8:</strong> Phased rollout by department (ICU, Med-Surg, ED, etc.)</li>
        <li><strong>Week 9-12:</strong> Complete deployment, ongoing optimization</li>
      </ol>

      <h3>Success Metrics</h3>
      <ul>
        <li>100% individual accountability (no shared accounts)</li>
        <li>Zero HIPAA audit findings related to device access</li>
        <li>Login time <10 seconds (target <5 seconds)</li>
        <li>User satisfaction >80% (measured post-rollout)</li>
        <li>Help desk tickets <2% of user base per month</li>
      </ul>

      <h2>Retail POS Systems</h2>

      <h3>Environment Characteristics</h3>
      <ul>
        <li><strong>Multi-shift workers:</strong> Cashiers, supervisors, managers share terminals</li>
        <li><strong>Minimal friction:</strong> Fast login critical for customer service</li>
        <li><strong>Audit requirements:</strong> Track who processed each transaction</li>
        <li><strong>High turnover:</strong> Frequent onboarding/offboarding</li>
        <li><strong>Peak periods:</strong> Cannot slow down during rushes</li>
      </ul>

      <h3>Technical Configuration</h3>
      <ul>
        <li><strong>Desktop MFA policy:</strong> MFA required, but optimize for speed</li>
        <li><strong>Factor selection:</strong> Okta Verify Push or TOTP (numeric codes easy to enter)</li>
        <li><strong>Shared device tags:</strong> Tag devices as "shared-retail-pos" for specific policies</li>
        <li><strong>Session timeouts:</strong> Short timeouts (2-5 min) for security, auto-lock at register</li>
        <li><strong>Biometric option:</strong> Consider Windows Hello fingerprint for speed</li>
      </ul>

      <h3>User Experience Optimization</h3>
      <ul>
        <li><strong>Numeric focus:</strong> TOTP codes easier than typing usernames</li>
        <li><strong>Barcode badges:</strong> Scan badge to populate username</li>
        <li><strong>Visual consistency:</strong> Same login experience across all terminals</li>
        <li><strong>Manager override:</strong> Supervisor can unlock for emergency customer service</li>
        <li><strong>Simple training:</strong> 30-second demonstration during onboarding</li>
      </ul>

      <h3>Implementation Guide</h3>
      <ol>
        <li><strong>Week 1:</strong> Pilot with one store (preferably lower-traffic location)</li>
        <li><strong>Week 2:</strong> Monitor peak period performance, adjust configurations</li>
        <li><strong>Week 3-6:</strong> Roll out to additional stores in waves</li>
        <li><strong>Week 7-8:</strong> Complete deployment across all locations</li>
      </ol>

      <h3>Success Metrics</h3>
      <ul>
        <li>Login time <8 seconds (faster than old password system)</li>
        <li>Zero transaction attribution errors</li>
        <li>Reduced fraudulent transactions (better accountability)</li>
        <li>PCI compliance for all device access</li>
      </ul>

      <h2>Manufacturing Floor Devices</h2>

      <h3>Environment Characteristics</h3>
      <ul>
        <li><strong>Harsh environments:</strong> Dust, heat, gloves, loud noise</li>
        <li><strong>Limited training:</strong> Workers may have basic computer skills</li>
        <li><strong>Shift changes:</strong> Multiple workers per device per day</li>
        <li><strong>Production tracking:</strong> Link work output to individual workers</li>
        <li><strong>Safety considerations:</strong> Quick lockout for safety compliance</li>
      </ul>

      <h3>Technical Configuration</h3>
      <ul>
        <li><strong>Simplified MFA:</strong> TOTP or PIN-based (gloves make phone use difficult)</li>
        <li><strong>Hardened devices:</strong> Industrial PCs or tablets with enhanced durability</li>
        <li><strong>Proximity cards:</strong> Badge tap + PIN for two factors</li>
        <li><strong>Session management:</strong> Auto-lock when worker moves to different station</li>
        <li><strong>Offline mode:</strong> Full offline support for network outages</li>
      </ul>

      <h3>User Experience Optimization</h3>
      <ul>
        <li><strong>Large UI elements:</strong> Easy to tap with gloves</li>
        <li><strong>Visual feedback:</strong> Clear success/failure indicators</li>
        <li><strong>Language support:</strong> Multi-language options for diverse workforce</li>
        <li><strong>Audio cues:</strong> Beeps for success/failure (loud environment)</li>
        <li><strong>Supervisor assist:</strong> Floor managers can help with issues</li>
      </ul>

      <h3>Implementation Guide</h3>
      <ol>
        <li><strong>Week 1-2:</strong> Pilot with administrative area (less harsh environment)</li>
        <li><strong>Week 3-4:</strong> Test on production floor with one line/area</li>
        <li><strong>Week 5-6:</strong> Gather feedback, adjust for glove use and noise</li>
        <li><strong>Week 7-12:</strong> Phased rollout across production areas</li>
      </ol>

      <h3>Success Metrics</h3>
      <ul>
        <li>100% production line accountability</li>
        <li>Login time <15 seconds (acceptable for shift changes)</li>
        <li>Zero safety incidents related to authentication delays</li>
        <li>Reduced quality issues (better worker tracking)</li>
      </ul>

      <h2>Call Center Shared Desks</h2>

      <h3>Environment Characteristics</h3>
      <ul>
        <li><strong>High turnover:</strong> Frequent new hires and departures</li>
        <li><strong>Session management:</strong> Agents take breaks, need quick lock/unlock</li>
        <li><strong>Performance metrics:</strong> Track individual call handling, quality scores</li>
        <li><strong>Hoteling:</strong> Different desk each day</li>
        <li><strong>Call volume:</strong> Cannot delay customer calls for auth issues</li>
      </ul>

      <h3>Technical Configuration</h3>
      <ul>
        <li><strong>Desktop MFA:</strong> Fast factors only (Push, TOTP)</li>
        <li><strong>Session timeout:</strong> 5-10 minutes for break scenarios</li>
        <li><strong>Single sign-on:</strong> Device login also authenticates to call center apps</li>
        <li><strong>Quick unlock:</strong> Passwordless unlock for returning from breaks</li>
        <li><strong>Device assignment:</strong> No device binding (hoteling)</li>
      </ul>

      <h3>User Experience Optimization</h3>
      <ul>
        <li><strong>Predictable experience:</strong> Same at every desk</li>
        <li><strong>Break optimization:</strong> Lock but maintain session for quick return</li>
        <li><strong>Onboarding integration:</strong> Factor enrollment during new hire orientation</li>
        <li><strong>Minimal clicks:</strong> One-click to ready state</li>
        <li><strong>Help desk proximity:</strong> IT support desk on floor for issues</li>
      </ul>

      <h3>Implementation Guide</h3>
      <ol>
        <li><strong>Week 1:</strong> Pilot with training team (controlled environment)</li>
        <li><strong>Week 2-3:</strong> Pilot with small production team</li>
        <li><strong>Week 4-6:</strong> Rollout by team/shift</li>
        <li><strong>Week 7-8:</strong> Complete deployment</li>
      </ol>

      <h3>Success Metrics</h3>
      <ul>
        <li>No impact to average handle time (AHT)</li>
        <li>Individual agent accountability for all calls</li>
        <li>Reduced fraudulent activity (better attribution)</li>
        <li>User satisfaction >75% (call center baseline lower)</li>
      </ul>

      <h2>General Best Practices for Shared Devices</h2>

      <h3>Security Considerations</h3>
      <ul>
        <li>Never use shared accounts - always individual authentication</li>
        <li>Implement automatic session timeouts appropriate for environment</li>
        <li>Audit all device access - integrate with SIEM/compliance systems</li>
        <li>Use device-appropriate factors (consider gloves, noise, etc.)</li>
        <li>Monitor for anomalous patterns (same user on multiple devices simultaneously)</li>
      </ul>

      <h3>User Experience Guidelines</h3>
      <ul>
        <li>Optimize for speed - every second counts in production environments</li>
        <li>Provide visual and audio feedback for environments</li>
        <li>Support multiple languages if needed</li>
        <li>Make training minimal and practical</li>
        <li>Ensure consistent experience across all shared devices</li>
      </ul>

      <h3>Technical Configuration Tips</h3>
      <ul>
        <li>Tag shared devices in MDM for specific policies</li>
        <li>Configure appropriate session timeouts by device type</li>
        <li>Enable offline factors for network-challenged areas</li>
        <li>Test thoroughly during actual work shifts (not after-hours)</li>
        <li>Monitor authentication metrics to identify friction points</li>
      </ul>

      <h3>Change Management Approach</h3>
      <ul>
        <li>Involve frontline workers in pilot selection and feedback</li>
        <li>Communicate business benefits (security, compliance) clearly</li>
        <li>Provide supervisor/manager override for emergencies</li>
        <li>Ensure 24/7 support coverage if devices operate 24/7</li>
        <li>Measure and communicate success metrics to workforce</li>
      </ul>
    `,
    summary: 'Comprehensive guide for implementing Okta Device Access in shared device environments including healthcare workstations, retail POS, manufacturing floor devices, and call center desks with specific configurations, best practices, and success metrics for each scenario.',
    category: 'use-cases',
    tags: ['shared devices', 'healthcare', 'retail', 'manufacturing', 'call center', 'implementation', 'user experience', 'session management'],
    source: 'internal',
    createdAt: new Date(),
    updatedAt: new Date(),
    isRead: false,
    isStarter: true,
  },
  {
    id: 'se-vdi-scenario',
    title: 'Advanced Scenario: VDI and Virtual Desktop Environments',
    content: `
      <h2>Overview</h2>
      <p>Virtual Desktop Infrastructure (VDI) and virtual desktop environments present unique challenges for device authentication and identity management. This guide covers implementation strategies for major VDI platforms.</p>

      <h2>Citrix Virtual Apps and Desktops</h2>

      <h3>Environment Overview</h3>
      <ul>
        <li><strong>Published applications:</strong> RemoteApp-style individual app delivery</li>
        <li><strong>Full desktop:</strong> Complete Windows desktop experience</li>
        <li><strong>HDX protocol:</strong> Citrix's display protocol for remote sessions</li>
        <li><strong>Delivery controller:</strong> Citrix infrastructure component that brokers connections</li>
        <li><strong>StoreFront/Workspace:</strong> User portal for accessing virtual resources</li>
      </ul>

      <h3>Technical Considerations</h3>
      <ul>
        <li><strong>Authentication layers:</strong> Client device → Citrix Gateway → VDA (Virtual Delivery Agent)</li>
        <li><strong>Device registration:</strong> Register VDA or client device to Okta</li>
        <li><strong>Okta Verify placement:</strong> Install on client device, not in VDA</li>
        <li><strong>SSO integration:</strong> SAML federation between Okta and Citrix Workspace</li>
        <li><strong>Session handling:</strong> Persistent vs non-persistent VDA considerations</li>
      </ul>

      <h3>Recommended Architecture</h3>
      <ul>
        <li><strong>Client-side authentication:</strong> Desktop MFA on physical endpoint, not VDA</li>
        <li><strong>SSO to Citrix:</strong> User authenticates to device → SSO into Citrix Workspace → launch apps</li>
        <li><strong>Okta as IdP:</strong> Federate Citrix Gateway/Workspace with Okta SAML</li>
        <li><strong>Factor selection:</strong> Okta Verify on physical device (phone or client PC)</li>
        <li><strong>Policy enforcement:</strong> Device trust on physical endpoint, not virtual desktop</li>
      </ul>

      <h3>Implementation Steps</h3>
      <ol>
        <li><strong>Configure Okta-Citrix SAML federation</strong> (Citrix as SP, Okta as IdP)</li>
        <li><strong>Deploy Okta Verify to client devices</strong> (physical endpoints accessing Citrix)</li>
        <li><strong>Configure Desktop MFA on client devices</strong> (not VDA)</li>
        <li><strong>Test authentication flow:</strong> Device login → Citrix Workspace SSO → app launch</li>
        <li><strong>Configure policies:</strong> Require device trust for Citrix access</li>
      </ol>

      <h3>Common Pitfalls</h3>
      <ul>
        <li>Installing Okta Verify inside VDA (won't persist in non-persistent pools)</li>
        <li>Trying to enforce Desktop MFA on VDA login (not supported)</li>
        <li>Not federating Citrix Workspace with Okta (duplicating authentication)</li>
        <li>Incorrect StoreFront/Workspace SAML configuration</li>
      </ul>

      <h2>VMware Horizon</h2>

      <h3>Environment Overview</h3>
      <ul>
        <li><strong>Instant clones:</strong> Non-persistent desktops created on-demand</li>
        <li><strong>Linked clones:</strong> Pool of desktops based on parent image</li>
        <li><strong>Full clones:</strong> Independent, persistent virtual machines</li>
        <li><strong>Blast protocol:</strong> VMware's display protocol (HTML5 or native)</li>
        <li><strong>Connection Server:</strong> Horizon component that brokers desktop connections</li>
      </ul>

      <h3>Technical Considerations</h3>
      <ul>
        <li><strong>Persistent vs non-persistent:</strong> Affects where Okta Verify can be installed</li>
        <li><strong>Profile management:</strong> FSLogix, VMware Dynamic Environment Manager for user state</li>
        <li><strong>Authentication tiers:</strong> Client device → Horizon → Windows desktop</li>
        <li><strong>True SSO:</strong> VMware's certificate-based SSO to Windows</li>
        <li><strong>Smart card support:</strong> Physical smart cards through USB redirection</li>
      </ul>

      <h3>Recommended Architecture</h3>
      <ul>
        <li><strong>Client-side Desktop MFA:</strong> Authenticate on physical endpoint</li>
        <li><strong>Okta + Workspace ONE:</strong> Integrate with VMware Workspace ONE for unified access</li>
        <li><strong>SAML to Horizon:</strong> Federate Horizon Connection Server with Okta</li>
        <li><strong>True SSO configuration:</strong> Automatic Windows login after Horizon authentication</li>
        <li><strong>Persistent desktop option:</strong> For users needing Okta Verify in VDI, use full clones</li>
      </ul>

      <h3>Implementation Steps</h3>
      <ol>
        <li><strong>Deploy Desktop MFA to client devices</strong> (physical endpoints)</li>
        <li><strong>Configure Okta-Horizon SAML federation</strong></li>
        <li><strong>Enable VMware True SSO</strong> (eliminates second Windows login)</li>
        <li><strong>Configure authentication policies</strong> (device trust on physical endpoint)</li>
        <li><strong>Test end-to-end flow:</strong> Physical device login → Horizon portal → desktop launch</li>
      </ol>

      <h3>Non-Persistent Desktop Handling</h3>
      <ul>
        <li><strong>Challenge:</strong> Instant clones reset on logoff, losing Okta Verify enrollment</li>
        <li><strong>Solution:</strong> Don't install Okta Verify in VDI; authenticate at client device layer</li>
        <li><strong>Alternative:</strong> Use persistent desktops (full clones) for users requiring in-VDI Okta Verify</li>
        <li><strong>Profile redirection:</strong> FSLogix can persist some Okta Verify data, but not recommended</li>
      </ul>

      <h2>Azure Virtual Desktop (AVD)</h2>

      <h3>Environment Overview</h3>
      <ul>
        <li><strong>Windows 10/11 multi-session:</strong> Multiple users on same OS instance</li>
        <li><strong>FSLogix:</strong> Profile container technology for user state</li>
        <li><strong>Personal desktops:</strong> 1:1 user-to-VM assignment</li>
        <li><strong>Pooled desktops:</strong> Shared, non-persistent VMs</li>
        <li><strong>RemoteApp:</strong> Individual application streaming</li>
      </ul>

      <h3>Technical Considerations</h3>
      <ul>
        <li><strong>Azure AD join:</strong> AVD VMs can be Azure AD joined or hybrid joined</li>
        <li><strong>Conditional Access:</strong> Integrate with Azure AD Conditional Access</li>
        <li><strong>Multi-session OS:</strong> Windows 10/11 Enterprise multi-session support</li>
        <li><strong>FSLogix profiles:</strong> User profiles stored in Azure Files or NetApp</li>
        <li><strong>Client authentication:</strong> Windows, macOS, iOS, Android, web clients</li>
      </ul>

      <h3>Recommended Architecture</h3>
      <ul>
        <li><strong>Hybrid identity:</strong> Okta federates with Azure AD, AVD uses Azure AD</li>
        <li><strong>Client-side Desktop MFA:</strong> On physical endpoint accessing AVD</li>
        <li><strong>AVD SSO:</strong> Single sign-on from client to AVD desktop</li>
        <li><strong>Conditional Access integration:</strong> Okta device trust feeds Azure AD policies</li>
        <li><strong>Personal desktops for special cases:</strong> Users needing persistent Okta Verify in VDI</li>
      </ul>

      <h3>Implementation Steps</h3>
      <ol>
        <li><strong>Configure Okta-Azure AD federation</strong> (SAML or OIDC)</li>
        <li><strong>Deploy Desktop MFA to client devices</strong></li>
        <li><strong>Enable AVD SSO</strong> (Azure AD join + SSO settings)</li>
        <li><strong>Configure Conditional Access</strong> (require compliant device for AVD access)</li>
        <li><strong>Test authentication:</strong> Client login → AVD portal → desktop/app launch</li>
      </ol>

      <h3>FSLogix Considerations</h3>
      <ul>
        <li><strong>Profile containers:</strong> Store user data, but not recommended for Okta Verify</li>
        <li><strong>Office containers:</strong> Separate container for Office 365 cache</li>
        <li><strong>Cloud Cache:</strong> Multi-location profile redundancy</li>
        <li><strong>Okta Verify challenges:</strong> Device binding may not survive profile container moves</li>
      </ul>

      <h2>Amazon WorkSpaces</h2>

      <h3>Environment Overview</h3>
      <ul>
        <li><strong>Persistent WorkSpaces:</strong> Dedicated virtual desktop per user</li>
        <li><strong>Non-persistent pools:</strong> Auto-provisioned, destroyed after use</li>
        <li><strong>Client applications:</strong> Windows, macOS, iOS, Android, web clients</li>
        <li><strong>Directory integration:</strong> AWS Managed Microsoft AD or AD Connector</li>
        <li><strong>SAML 2.0 support:</strong> Can federate with external IdPs</li>
      </ul>

      <h3>Technical Considerations</h3>
      <ul>
        <li><strong>Registration code:</strong> WorkSpaces uses registration codes for client setup</li>
        <li><strong>MFA at directory level:</strong> AWS supports RADIUS-based MFA</li>
        <li><strong>SAML federation:</strong> Can federate WorkSpaces access with Okta</li>
        <li><strong>Persistent vs AlwaysOn:</strong> Different lifecycle models</li>
        <li><strong>Client device trust:</strong> Limited visibility into client device state</li>
      </ul>

      <h3>Recommended Architecture</h3>
      <ul>
        <li><strong>Client-side Desktop MFA:</strong> Physical endpoint authentication</li>
        <li><strong>SAML to WorkSpaces:</strong> Federate WorkSpaces web access with Okta</li>
        <li><strong>AD Connector to Okta:</strong> Sync users from Okta to AWS Managed AD</li>
        <li><strong>Persistent WorkSpaces:</strong> For users requiring Okta Verify in-VDI</li>
        <li><strong>Client registration:</strong> Manage WorkSpaces client via MDM</li>
      </ul>

      <h3>Implementation Steps</h3>
      <ol>
        <li><strong>Configure Okta-WorkSpaces SAML federation</strong></li>
        <li><strong>Deploy Desktop MFA to client devices</strong></li>
        <li><strong>Set up AWS Managed AD</strong> (sync users from Okta if needed)</li>
        <li><strong>Configure WorkSpaces directory</strong> (enable SAML if using web access)</li>
        <li><strong>Test flow:</strong> Client device login → WorkSpaces client/web → desktop launch</li>
      </ol>

      <h2>General VDI Best Practices</h2>

      <h3>Architecture Principles</h3>
      <ul>
        <li><strong>Authenticate at the edge:</strong> Secure physical endpoints, not virtual desktops</li>
        <li><strong>Use SSO:</strong> Single authentication should flow through to VDI</li>
        <li><strong>Device trust on endpoints:</strong> Register physical devices, not VDI instances</li>
        <li><strong>Factor placement:</strong> Okta Verify on physical device or phone, not VDI</li>
        <li><strong>Persistent for exceptions:</strong> Use persistent VDI only when truly needed</li>
      </ul>

      <h3>Common Questions and Answers</h3>
      <ul>
        <li><strong>Q: Can I use Desktop MFA inside VDI?</strong><br>A: Not recommended. Non-persistent VDI resets on logoff. Use Desktop MFA on client devices instead.</li>
        <li><strong>Q: What about Okta Verify in persistent VDI?</strong><br>A: Possible with full clones/persistent desktops, but adds complexity. Better to authenticate at client layer.</li>
        <li><strong>Q: How do I handle offline VDI access?</strong><br>A: Offline VDI access typically requires VPN or cached credentials. Configure offline factors on client device.</li>
        <li><strong>Q: Can I use Platform SSO in VDI?</strong><br>A: Platform SSO is for physical macOS devices, not applicable to VDI sessions.</li>
        <li><strong>Q: What about thin clients?</strong><br>A: Deploy Desktop MFA on thin client OS if supported (IGEL, HP ThinPro), otherwise use SAML to VDI broker.</li>
      </ul>

      <h3>Licensing Considerations</h3>
      <ul>
        <li><strong>Device licensing:</strong> License physical endpoints accessing VDI, not VDI instances</li>
        <li><strong>User licensing:</strong> Per-user licensing simplifies VDI scenarios</li>
        <li><strong>Persistent VDI:</strong> If registering VDI instances, each counts as a device</li>
        <li><strong>Thin clients:</strong> Thin clients running Okta Verify count as devices</li>
      </ul>

      <h3>Troubleshooting VDI Issues</h3>
      <ul>
        <li><strong>Issue: Okta Verify lost after VDI logoff</strong><br>Solution: Don't install in non-persistent VDI; use client-side authentication</li>
        <li><strong>Issue: Double authentication (device + VDI)</strong><br>Solution: Configure SSO from client to VDI broker with SAML federation</li>
        <li><strong>Issue: Slow authentication to VDI</strong><br>Solution: Check network latency, optimize connection broker placement, enable protocol acceleration</li>
        <li><strong>Issue: Factor not available in VDI</strong><br>Solution: Ensure factors configured for client device, not VDI session</li>
      </ul>

      <h2>Implementation Decision Tree</h2>

      <h3>When to use Client-Side Desktop MFA</h3>
      <ul>
        <li>Non-persistent VDI (instant clones, pooled desktops)</li>
        <li>Multi-session environments (AVD, RDSH)</li>
        <li>Primarily accessing published apps (not full desktops)</li>
        <li>Thin client infrastructure</li>
        <li>Want to avoid complexity of VDI-side authentication</li>
      </ul>

      <h3>When to use VDI-Side Desktop MFA</h3>
      <ul>
        <li>Persistent, full-clone VDI (1:1 user-to-VM)</li>
        <li>Users have dedicated virtual desktops</li>
        <li>VDI IS the primary "device" for users (no physical endpoint control)</li>
        <li>Strong requirement for in-VDI MFA (regulatory, policy)</li>
        <li>Willing to manage complexity of VDI enrollment lifecycle</li>
      </ul>

      <h3>When to use SAML Federation Only</h3>
      <ul>
        <li>Web-based VDI access (HTML5 clients)</li>
        <li>No control over client devices (BYOD, contractor-owned)</li>
        <li>Want simple, lightweight authentication</li>
        <li>Don't need device trust signals</li>
        <li>Primary concern is SSO into VDI environment</li>
      </ul>
    `,
    summary: 'Comprehensive guide for implementing Okta Device Access in VDI and virtual desktop environments including Citrix, VMware Horizon, Azure Virtual Desktop, and Amazon WorkSpaces with architecture patterns, best practices, and troubleshooting.',
    category: 'use-cases',
    tags: ['vdi', 'virtual desktop', 'citrix', 'vmware', 'azure virtual desktop', 'workspaces', 'architecture', 'implementation'],
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
