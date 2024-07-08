+++
title = "Simplifying User and Entity Behavior Detection"
date = 2024-07-07T13:34:24-04:00
categories = ["Detection Engineering", "Threat Hunting", "Sentinel", "Defender"]
tags = ["Detection", "KQL", "Sentinel", "User Behavior", "Entity Behavior", "UBA", "UEBA", "Correlation"]
authors = ["Dylan Tenebruso"]
description = "Exploring methods on developing custom User and Entity behavior detection ideas that work in our envrionment. Focusing on efficiency by ensuring our detection rules are specific and deliberate. Staying specific by utilizing log correlation and being deliberate by asking ourselves a simple question, why?"
draft = false
+++
##  Like Nailing Jell-o to a Wall
In a poll I ran asking the community which detection domains could use more of their attention, User Behavior reigned supreme.

{{< twitter user="DylanInfosec" id="1785997692855816626" >}}

Most of the detections in our environments for User and Entity Behavior Analytics (UEBA) originate from closed-source machine learning-based detections that present outliers in our log data. *Anomalies*.

An example of a possible out-of-the-box UEBA detection:

*A user was observed performing an unusual admin activity while connecting from an IP address they haven't used within the last 30 days.*

Meh. Not bad, but you'll likely be wading through a decent amount of false positives. 

A method I use to help me develop ideas for UEBA detections comes from an article by Florian Roth, titled, [About Detection Engineering](https://cyb3rops.medium.com/about-detection-engineering-44d39e0755f0). It's part of a must-read series for anyone with a role that in one way or another touches detection engineering. The one specific excerpt that stuck with me was this:
>"However, detection engineering is by no means limited to the detection of events (activity). It also includes detecting conditions (states), often used in digital forensics or incident response.

>Activity: adding the guest account to the local admin group
>State: the guest account is a member of the local admin group"

Later on in the post, he shares his broader definition of detection engineering to account for this and the "targets" mentioned in the same article:
>Detection engineering transforms an idea of how to detect a specific condition or activity into a concrete description of how to detect it.

What does this mean? I can only give my interpretation and my focus for this article is on the *specific condition* part. 

A lot of times we tend to think in terms of *Activity*. "How can I detect suspicious inbound activity?" or "What might a malicious insider's actions look like?". This certainly works and at times is necessary but this forces us to attempt to define the mutable. Like nailing jell-o to a wall, you can't define something with no solid form. We need a foundation to build the rest of our efforts off of.

As stated in the definition provided by Florian, we're not only looking for activity but states/conditions. There are many ways for someone to do bad things but if we can define an undesirable state/condition, we can work to identify the paths that lead to that state or brainstorm what symptoms might stem from the condition.

Though you can use the terms "state" and "condition" interchangeably, I like to separate them as it helps me differentiate the stages of the detection system I'm trying to build. How I think of it is, what needs to happen to achieve a certain **state** and what would the symptoms be of a certain **condition**. See what I mean here:

Id | State/Condition | Activity1 | Activity2
--- | --- | --- | ---
1 | Untrusted MFA factor set for user | Same SMS used by multiple users | MFA Push sent to non-managed mobile
2 | Salesforce profile allows direct(legacy) login | Admin made changes to profile configs | Admin enabled login form auth method

Id 1 shows activities that can be detected which would prove the condition "Untrusted MFA factor set for user" exists. They're symptoms of a condition already existing.

Id 2 shows activities that lead to a specific state. You would detect on these activities occurring before the state is true.

Continue this by flipping the state/condition designations. If the condition "Salesforce profile allows direct(legacy) login" existed what would the symptoms be? Legacy auth logins in the Sign-in logs? User activity in Salesforce by a user who didn't log on via SSO. You now have the *early warning system* and the *something has gone wrong* alerts.

This method allows us to be specific and deliberate with our alerting.  By stacking it with other methods such as mind maps, waterfall modeling, and data flow diagrams, we mitigate the challenge that specificity creates gaps in visibility. Furthermore, we can always confirm and validate our detections via frameworks like [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [msInvader](https://github.com/mvelazc0/msInvader), and/or [TTPForge](https://github.com/facebookincubator/TTPForge).

## Achieving Specificity Using Log Correlation

Now that we can define the states/conditions we want to build our detections around, we need to ensure that we're not burying ourselves in False-positive alerts (FPs) by holding to the "specific and deliberate". Specificity can achieved by correlating data between different event logs and data sources. Being deliberate comes from asking ourselves the question, "Why?". 

That second tool might be the most important one you can add to your utility belt and it's one I credit my colleague and mentor, Steve, for drilling into my head every day... or at least making the effort to, the rest is on me to use it.

![number one tool in my utility belt](utility_belt.gif)

Let's see all this in action.

#### Lux in Umbra... Documentorum?: Identifying Shadow Credential Attacks

Here, we'll start with a **State**: Anomalous Credentials exist in KCL for an AD Object.

We got there by setting a goal to create detections around user authentication. After some research around authentication we documented and generated diagrams of the auth flows in our organization. During this process, we learned how our implementation of Windows Hello for Business (WHfB) works. Finally, we brainstormed some undesirable states/conditions that could exist in our environment.

Now to ask ourselves, why this detection matters? This gives us an indication of what sort of ROI we can expect from this rule. Roughly, our answer to "Why?" is our business justification for the time spent working on this detection (planning + writing + testing + deploying + maintaining).

Why: Values stored in the msDS-KeyCredentialLink attribute function as an alternate set of persistent credentials for the associated object. This means they'll survive a password change and an attacker who added those credentials can use them to authenticate as that object in our environment.

For this, we'll look specifically actions that could be taken to make this state true. In this case, that'll be additions to the KeyCredentialLink attribute for a device where the *write* didn't come from that same device. 

{{< alert "microsoft" >}}
To better understand how Windows Hello for Business Provisioning works and how the KCL ties into all this, read the docs here: [Provisioning WHfB in a Hybrid Key Trust deployment](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/how-it-works-provisioning#provisioning-in-a-hybrid-key-trust-deployment-model-with-managed-authentication)
{{< /alert >}}

To start this detection rule, we'll have to look at Event ID 5136 *A directory service object was modified*, an extremely busy event.
{{< alert "microsoft" >}}
 [MS Docs - Event 5136 - DS Object Modified](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
{{< /alert >}}

You might see this a lot in your environment if you're using Windows Hello for Business (WHfB) Key Trust in a Hybrid joined environment. You'll see good 'ol MSOL_* (the Azure AD Connect sync account) writing to this attribute often to keep the public key in sync for WHfB. You will see similar activity with On-prem Cert trust deployments of WHfB and environments utilizing Credential Guard.

Let's write out some pseudo-detection.

*A directory service object (computer) was modified (EID 5136) with an 'add' operation and the attribute modified is msDS-KeyCredentialLink (kcl)...*

No big deal. In modern environments, this is happening all the time. But what if we add the following line?

*where the target computer object of the correlated logon event (EID 4624) has an IP that isn't associated with the subject computer object.* 

That's a KCL entry made for a computer from an IP address not known to be used nor have been used by that computer. We would achieve this by correlating one event log with another and pulling in data from a completely separate source to add context to the existing data.

Smells like Shadow Credentials...

As Bobby Hill once said:
![That's my purse! I don't know you!](bobby-hill-thats-my-purse.gif)

### Diving Deeper

#### Explaining the Detection

A technical breakdown of Shadow Credentials is beyond the scope of this post and there already are some really great posts on this exact topic from some much more knowledgeable people. 

To learn more about what Shadow Credentials are (and I highly recommend you do), please read these:

{{< alert "circle-info">}}
[Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) by Elad Shamir

[Detecting shadow credentials](https://cyberstoph.org/posts/2022/03/detecting-shadow-credentials/) by Christoph Falta
{{< /alert >}}

Christoph's blog post was the main inspiration behind this particular detection. At one point in the post, Christoph states the following:
>You could go for the corresponding event 4624 again and check IP addresses but this is usually a less reliable source of information for clients and would also imply that you have things like DHCP logs.
> Christoph Falta

Microsoft XDR makes this a possibility with the DeviceNetworkInfo table because we can correlate and confirm whether or not the associated logon comes from an IP address associated with the Device the addition was issued for.

We pull the correlated logon in via the *Logon ID* within the 5136 EventData with the Name value of "SubjectLogonId". The correlated 4624 of the same Logon ID gives us the source IP address and the workstation name via the EventData with the Name values "IpAddress" and "WorkstationName" respectively.

Finally, we're going to query the DeviceNetworkInfo table where the DeviceName == WorkstationName and confirm whether or not the IP address used for the logon was ever actually associated with the computer by checking against the DeviceNetworkInfo column IPAddresses.

#### KQL

Let's write this out in KQL:

```SQL
let domainName = ".domain.com"
let kcl_added = materialize ( SecurityEvent
// all DS object modified events where a value add operation took place
| where EventID == 5136 and OperationType == @"%%14674"
// now to parse out the EventData XML values to only pull writes to the KCL 
| project EventData
| extend EventDataXml = parse_xml(EventData)
| extend DataElements = EventDataXml["EventData"]["Data"]
| mv-expand DataElement = DataElements
| extend Name = tostring(DataElement["@Name"]), Value = tostring(DataElement["#text"])
| summarize bag = make_bag(bag_pack(Name, Value)) by EventData
| evaluate bag_unpack(bag)
| extend AttributeLDAPDisplayName = column_ifexists('AttributeLDAPDisplayName','x'), OperationType = column_ifexists('OperationType','x'), SubjectLogonId = column_ifexists('SubjectLogonId','x')
| project AttributeLDAPDisplayName, OperationType, SubjectLogonId
// focus in on events related to the KCL attribute
| where AttributeLDAPDisplayName == "msDS-KeyCredentialLink"
| project SubjectLogonId);
let correlateLogon = materialize ( SecurityEvent
// pull in the correlated logon event for the KCL modification
| where EventID == 4624
| where TargetLogonId in (kcl_added) // looking for the correlated logon events via the SubjectLogoId
| project IpAddress, WorkstationName = tolower(strcat(WorkstationName, domainName)));
DeviceNetworkInfo
| join kind=inner correlateLogon on $left.DeviceName == $right.WorkstationName
// check for any logons where the IP does not match any known IPs associated with the modified computer object; aka the Subject of the kcl modification
| where IPAddresses !has IpAddress
| summarize count() by TargetComputer = WorkstationName, AttackerIP = IpAddress
| project-away count_
```

{{< alert "github">}}
You can find [this KQL detection](https://github.com/AttacktheSOC/Azure-SecOps/blob/main/KQL/UEBA/ShadowCredentialsAddedtoADComputerObject.kql) and more at [GitHub - AttacktheSOC: Azure-SecOps](https://github.com/AttacktheSOC/Azure-SecOps)
{{< /alert >}}

This is a simple detection for a single flavor of Shadow Credentials, detecting only on *Computer object* KCL additions. 

## Final Thoughts

Decide on an area of focus > research and document your environment > ideate on what undesireable states and conditions that can be applied to your area of focus. Just start spitballing ideas, write 'em down, take the ones you like, and expand on them. They may turn into something great or lead you down another detection path you hadn't previously thought of. 

Here are a few non-specific ideas off the cuff, see if you can come up with a detection system for them. What would lead to the state being true? And, what are the symptoms of such a condition existing? Draft your detection ideas and then ask yourself, Why? If you don't have a solid answer then perhaps that rule doesn't make the cut:

1. Using Azure Arc for AMA only? Azure Arc is not deployed in Monitor Mode. How did it get that way? What unauthorized activity can you detect on for servers not in Monitor Mode?
2. AiTM using NTLMrelayx on the network. Symptoms might be DeviceNetowrkEvent.RemoteURL == server names not resolving to the correct IP (DeviceNetowrkEvent.RemoteIP) according to the DeviceNetworkInfo.IPAddresses column. Or common websites resolving to private IPs
3. IDP logs? Hopefully, you're not still allowing SMS and email for MFA but if you are; The same phone number/email is set for multiple users. 

## Plug-a-post

Take a *Detection-in-Depth* approach that layers tools and techniques to support your overall Defense-in-Depth strategy. Deception technology, one of these techniques, helps cover visibility gaps and detect suspicious behavior at all stages of the kill chain. 
{{< alert "comment" >}}To learn how to deploy honey tokens and accounts fleet-wide with a few clicks, check out my other post [Stacking MDE Deception Rules with Thinkst Canarytokens](/posts/stacking-your-deception "Stack Your Deception: Stacking MDE Deception Rules with Thinkst Canarytokens") {{< /alert>}}

# Thank you for reading

As always, I hope this helped you percolate the mind juice and filter out some ideas! Maybe you even learned something new. Now go create something and share it with the community.

Until next time on, Attack the SOC!