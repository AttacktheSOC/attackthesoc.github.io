+++
title = "Using KQL to Detect Gaps in your Conditional Access Strategy"
date = 2025-03-23T10:32:18-04:00
categories = ["KQL", "XDR", "Azure", "Conditional Access"]
tags = ["Defender XDR", "KQL", "Gap Analysis", "CAPs"]
authors = ["Dylan Tenebruso"]
description = "Conditional Access Policies serve as the frontline defenders of your Azure resources, but evolving business requirements can introduce unintended gaps. This article explores how to transform your high-level CAP strategy into actionable alerts using KQL, enabling detection and remediation of these vulnerabilities."
draft = false
+++
Conditional Access Policies are the sentry standing at the gateway of your Azure resources. Every organization will have unique rules for the various needs of the business and the logic can get complicated very quickly.

If I asked what your Conditional Access strategy is at a high level, I bet you can provide the full rundown. You would describe the concept of how it should work. Should. Problem is, and through no fault of your own, as your requirements shift so to does the possibility for gaps to manifest within your design. Eventually, it becomes inevitable.

It'd be great if we could take that high-level concept, flip it and turn it into an actionable alert. We know what our CAPs should allow, therefore we ought to know what we're attempting to prevent. Let's take that and create some detections to find current gaps in our policies and catch any that may be created in the future.

## Community Solutions
There are tons of other blogs and tools out there for just this purpose, granted with their own angle, pros, and cons. Here are a few of those:
* [Conditional Access Gap Analyzer Workbook](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/workbook-conditional-access-gap-analyzer) - This is a workbook built-in to the platform and can be found in the Entra Admin Center at:  Identity > Monitoring & health > Workbooks
* [Maester](https://maester.dev/) - A PowerShell-based Entra security testing framework built by the one and only [Merill](https://twitter.com/merill). This masterfully crafted and community-supported framework makes it simple to confirm your security configurations including [Conditional Access What-if policy testing](https://maester.dev/docs/ca-what-if)
* [CA Optics](https://github.com/jsa2/caOptics) - This is an archived project as the creator has refocused efforts on other projects initiatives. I personally have not used this tool but it comes recommended by others in the community.
* [CAP 'What if' Simulation - DCToolbox](https://danielchronlund.com/2023/11/24/conditional-access-what-if-simulation-with-powershell/) - found this in response to Twitter post from [Erica Zelic](https://twitter.com/IAMERICAbooted). Looks like a pretty cool PowerShell What if simulator, similar to Maester, with some crazy looking UI.
* [MFASweep](https://github.com/dafthack/MFASweep) - A tool developed by [Beau Bullock](https://twitter.com/dafthack) that performs auth attempts to Microsoft services with provided credentials and reports back where single-factor gaps are laying in wait.

## CAP GAP Violation Detection
Clearly, there are plenty of options and I'm sure there are more I missed, not to mention the countless articles on the subject.

To reiterate, this flavor of CAP gap detection is to detect on activity that, according to our personal understanding of our CAP strategy, should not occur. Let's use a real world example based on the Conditional Access Policy templates provided by Microsoft.

{{< alert "microsoft" >}}[Template Documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin) {{< /alert >}}


![You have security, but is it securing?](steward.gif)
 
### Require MFA for administrators
This policy is pretty cut and dry.

**CAP Strategy**: Require every administrator to perform multifactor authentication

**What shouldn't happen**: None of our administrators should be able to authenticate to any resource without performing MFA.

**Detection**: If a member of any Administrator role and/or specified group, successfully initializes a session via single-factor authentication

**Considerations**: Exclude from the detection any excluded resources and single-factor-only signins (i.e. Windows Signin)

```SQL
let firstPartyIds = dynamic(["c2ada927-a9e2-4564-aae2-70775a2fa0af","04436913-cf0d-4d2a-9cc6-2ffe7f1d3d1c"]);
let excludedResourceIds = dynamic([]);
// initialize list of CAP targeted group members
let CAPTargetGroup = materialize(ExposureGraphEdges
| where EdgeLabel == "member of" and TargetNodeLabel == "group"
| where TargetNodeName == "<GROUP_NAME>"
| distinct SourceNodeName);
let privilegedRoles = dynamic(["Global Administrator", "Application Administrator", "Authentication Administrator", "Billing Administrator", "Cloud Application Administrator", "Conditional Access Administrator", "Exchange Administrator", "Helpdesk Administrator", "Password Administrator", "Privileged Authentication Administrator", "Privileged Role Administrator", "Security Administrator", "SharePoint Administrator", "User Administrator"]);
let CAPTargetAdmins = IdentityInfo
| where AssignedRoles has_any(privilegedRoles)// or isnotempty(PrivilegedEntraPimRoles)
| distinct AccountDisplayName;
SigninLogs
| where Identity in (CAPTargetGroup, CAPTargetAdmins)
| where ResultType == 0
| where AuthenticationRequirement == @"singleFactorAuthentication"
// when looking for single-factor authentication exclude the expected
| where ResourceId !in (firstPartyIds, excludedResourceIds)
| where AppDisplayName != @"Windows Sign In"
| project-away OperationName, OperationVersion, Category, DurationMs, Resource, ResourceGroup, ProcessingTimeInMilliseconds
```

#### KQL Explained
First, we initialize lists containing the targets of the Conditional Access Policy as well as a list of resource Ids for the resources we've excluded from the CAP. Next, we're focusing the results on those lists where a successful signin occurred; *ResultType == 0*. Following this, we hone in on sessions that were initialized via single-factor authentication which, according to our strategy, shouldn't occur. Finally, we excluded any events that are expected to be single-factor. This includes Microsoft services that cannot be targeted by Conditional Access.

### Require Group Members Access a Specific App from a Trusted Location and via a Company Owned Device

**CAP Strategy**: Require members of a specific group to signin to a specific resource from a Trusted location (named locations) and via a company owned device

**What shouldn't happen**: Group members shouldn't be able to successfully signin to the app outside of the specified trusted named locations, nor from any device except Company owned

**Detection**: If a group member signs in via a Personal device or from any location not marked as Trusted

**Considerations**: Exclude from the detection any excluded resources or excluded users

```SQL
let excludedUsers = dynamic([""]);
let CAPTargetGroup = materialize(ExposureGraphEdges
| where EdgeLabel == "member of" and TargetNodeLabel == "group"
| where TargetNodeName == "<GROUP_NAME>"
| distinct SourceNodeName);
SigninLogs
| where ApplicationDisplayName == @"<AppDisplayName>"//ResourceId == @"<resourceId>"
| where ResultType == 0
| where Identity in (CAPTargetGroup) and Identity !in (excludedUsers)
| where NetworkLocationDetails !has "trustedNamedLocation"
| extend DeviceDetail = parse_json(DeviceDetail)
//# Specify expected Device Details
| extend
              IsCompliant = DeviceDetail.isCompliant,
              IsManaged = DeviceDetail.isManaged,
              TrustType = DeviceDetail.trustType
//# modify according to what is expected in your environment
| where IsCompliant == true
| where IsManaged == true              
| where TrustType in ("Workplace", "AzureAD", "ServerAD")
| project-away OperationName, OperationVersion, Category, DurationMs, Resource, ResourceGroup, ProcessingTimeInMilliseconds, DeviceDetail, NetworkLocationDetails
```

### Identify Resource with No Policies Applied to SignIns
This is query will help you to identify resources in your environment which have sessions where not Authentication policies were applied. This could be noisy and unpredictable as Microsoft has underlying services that are exempt from Conditional Access.

{{< alert "info" >}} On a similar note, [Nathan McNulty has a LI post](https://www.linkedin.com/posts/nathanmcnulty_this-is-a-fun-one-lets-say-you-have-activity-7298413919147016192-MwEk) regarding how we might unknowingly introduce gaps to your CAP strategy and offers some mitigation ideas via MS Docs {{< /alert >}}

**CAP Strategy**: Require MFA to all resources

**What shouldn't happen**: There should never be single-factor signins to any resource unless explicit exclusions were made

**Detection**: If any user successfully initializes a session via single-factor authentication to any unexpected resource

**Considerations**: Exclude from the detection any excluded resources and single-factor-only signins (i.e. Windows Signin)

```SQL
let firstPartyIds = dynamic(["c2ada927-a9e2-4564-aae2-70775a2fa0af","04436913-cf0d-4d2a-9cc6-2ffe7f1d3d1c"]);
let excludedResourceIds = dynamic([]);
SigninLogs
| where ResultType == 0
| where ResourceTenantId == AADTenantId
| where AuthenticationRequirement == @"singleFactorAuthentication"
| where ConditionalAccessStatus == "notApplied"
// when looking for single factor authentication exclude the expected
| where ResourceId in (firstPartyIds, excludedResourceIds)
| where AppDisplayName != @"Windows Sign In"
| where ResourceTenantId == AADTenantId
```

## Final Thoughts
This won't be the end all of your gap analysis strategy. There are going to be scenarios where this can't cut it. In fact, you might even find this approach harder to maintain than some of the others mentioned. If that's the case for you then don't lose hope and just accept that there will be gaps. Keep trying and if you find the answer, share what worked for you in hopes to help someone else in a similar situation.

Nevertheless, as in defense-in-depth, so in detection-in-depth. Layer your approach, consider only a couple detections that you know will be unchanged for a long time. Then in the more dynamic spaces of your infrastructure use Maester or even Merill's other tool [Conditional Access Documenter](https://idpowertoys.merill.net/ca) to visually export your rules and go over their logic manually. Maybe the native 'What if' tool does enough to fill your need.

Point is, you have options...

{{< alert "github" >}}You can find all the queries mentioned in this post plus a base template [here on my GitHub!](https://github.com/AttacktheSOC/Azure-SecOps/blob/main/KQL/ConditionalAccessPolicies/CAP-Gap-Detections.md){{< /alert>}}


# Thank you for reading

As always, I hope you walk away from this article with a new perspective and with some ideas jumping around in the gray matter. Make sure you check out those other tools mentioned in this article. All mentioned are great members of the community who are constantly building and sharing, be sure to give them a follow. Now go create something, find a solution and share it with the community.

Until next time on, Attack the SOC!
