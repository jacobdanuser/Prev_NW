# Public ByteDance/TikTok telemetry inventory

Updated: 2026-07-29

This inventory captures **publicly documented telemetry/data categories**, primarily from TikTok's current U.S. Privacy Policy and EEA/UK/Switzerland Privacy Policy. It is not a packet capture, internal telemetry dump, proprietary schema, or private-user dataset.

## Telemetry / automatically collected categories

### Usage and interaction telemetry

- How users interact with content and advertisements
- Duration and frequency of use
- Engagement with other users
- Search history
- Interactions with websites through the in-app browser
- Page views and interaction measurements collected through cookies and similar technologies

### Device, application, and network telemetry

The U.S. policy publicly lists:

- IP address
- user agent
- mobile carrier
- time-zone settings
- advertising identifiers
- device model
- device system
- network type
- screen resolution
- operating system
- app names and file names/types
- keystroke patterns or rhythms
- battery state
- audio settings
- connected audio devices
- automatically assigned device IDs
- automatically assigned user IDs

The EEA policy additionally describes service-related, diagnostic, and performance information including **crash reports and performance logs**.

### Location telemetry

Public policy documentation describes:

- approximate location inferred from device/network information such as SIM-card region, IP address, and device-system settings;
- approximate or precise location when location services are enabled;
- location information deliberately added to user content, such as points of interest.

### Content-derived telemetry

The U.S. policy says TikTok may automatically collect characteristics/features from videos, images, and audio, including:

- objects and scenery;
- existence and location of faces and body parts;
- spoken words/text in user content;
- biometric identifiers/information as defined under U.S. law, such as faceprints and voiceprints, where applicable and subject to required permissions.

### Content/message/AI metadata

Public documentation identifies automatically uploaded metadata associated with user content, messages, and AI interactions, including information about:

- how content was created;
- when content was created;
- where content was created;
- by whom content was created;
- when a message or prompt was sent;
- username information that can associate content with an account.

### Cookies, SDKs, pixels, and similar telemetry mechanisms

The U.S. policy identifies cookies and similar technologies including web beacons, Flash cookies, pixels, and SDKs. The policy says these technologies can be used to measure/analyze service usage, understand page views and interactions, enhance functionality, provide advertising, and promote services elsewhere.

### Cross-service / partner measurement telemetry

Public documentation says advertisers, publishers, measurement partners, and other partners may provide information about activity outside TikTok services, including:

- pages visited;
- products/services purchased;
- apps downloaded;
- mobile advertising identifiers;
- hashed email addresses and phone numbers;
- cookie identifiers.

TikTok's policy also describes advertiser tools such as TikTok Pixel as mechanisms through which similar information can be collected from third-party websites/apps.

## AI interaction telemetry

The current U.S. Privacy Policy explicitly includes AI interactions among collected information. This can include prompts, questions, files, other information submitted to AI-powered interfaces, and generated responses. The policy also states that user content, messages, AI interactions, and associated metadata may be scanned/analyzed/reviewed for service improvement, technology development, safety, security, and policy enforcement.

## Security/diagnostic purposes

The policies describe use of collected information for identifying technical or security issues, addressing bugs and spam accounts, detecting abuse/fraud/illegal activity, and maintaining service safety, security, and stability.

## Data retention

TikTok states that retention varies according to the type of information and the purpose for which it is used, as well as legal, contractual, and legitimate-business considerations. The public policy does not provide one universal retention period for all telemetry categories.

## Important distinction

The word **telemetry** here is an analytical grouping, not a claim that TikTok internally labels every listed field as telemetry. The source documents use broader terms such as “automatically collected information,” “technical information,” “usage information,” “metadata,” and “diagnostic/performance information.”

## Not included

This repository does not contain:

- private user telemetry;
- intercepted network traffic;
- device-extracted databases;
- credentials or authentication material;
- private API responses;
- proprietary source code;
- internal telemetry schemas not publicly documented;
- private tracking identifiers belonging to individuals;
- non-public ByteDance/TikTok infrastructure information.

## Sources

- TikTok U.S. Privacy Policy, last updated July 15, 2026: https://t.tiktok.com/legal/page/us/privacy-policy/en?lang=en
- TikTok EEA/UK/Switzerland Privacy Policy: https://in.tiktok.com/legal/page/eea/privacy-policy/en
- TikTok U.S. Terms of Service, last updated July 15, 2026: https://t.tiktok.com/legal/page/us/terms-of-service/en
- TikTok Law Enforcement Guidelines: https://t.tiktok.com/legal/page/global/law-enforcement/en?lang=en

These sources are public policy/legal documents, not evidence of a particular individual's data collection.
