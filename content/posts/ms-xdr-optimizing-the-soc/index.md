+++
title = "Optimizing and Automating the SOC"
date = 2024-06-04T21:32:18-04:00
categories = ["Automation", "Defender", "Sentinel"]
tags = ["Defender XDR", "SOAR", "SOC", "optimization", "automation"]
authors = ["Dylan Tenebruso"]
description = "Looking at ways to ease the load of SOC analysts by using XDR built-in features. We'll automate noisy black box detections away, analyze our heavy hitting alerts and incidents and tighten up our detections."
draft = true
+++
Alright, so you got the blinky boxes and colorful dashboards showing data no one remembers why they wanted to see. You're drooling at the sight of that "Enter prompt here.." bar and the budget is burning a hole in your pocket. 

Here's you:
![Mario chasing the flying goalpost](mario_goalpost.gif)

Chasing down a goalpost that seemingly grew wings. You're hemorrhaging FPs, you have tons of undiagnosed system Health alerts and you have some unknown unknowns, not because "that's just the nature of things" but because you haven't given yourself a minute to sit back and think.

In this post, we're going to look at some of the functionality that's built into the Microsoft Unified SOC Operations platform and some that isn't to help you clean up and get your SOC all optimized and stuff..

## Issues to Solve
1. Data Collection health
2. False-positives
3. Content Hub Version control
4. Playbook Health

## Data Collection Health
Do you know if any of your data collectors have stopped ingesting? Were you able to detect that anomalous uptick in events coming in from your DnsEvents table? To answer questions like this and so much more, you need to install the following Workbook from the Sentinel Content Hub.

{{< alert "microsoft" >}}[**Data Collection Health Monitoring**](https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health) {{< /alert >}}




## Identifying High False-positive Producers
### Built-in Optimization Tools

### Custom Optimizations

## Content Hub Version Control
### Built-in Optimization Tools

### Custom Optimizations

## Playbook Health
### Built-in Optimization Tools

### Custom Optimizations

## Honorable mention - SOC Optimization

You undoubtedly already know of the new [SOC Optimization tool](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/soc-optimization-unlock-the-power-of-precision-driven-security/ba-p/4130589) which if you're not familiar, click the link and become acquainted. MS developed it specifically to help you and your team optimize your SOC Operations and utilize the entire platform the way it was supposed to be used. Is there a data source you're neglecting? An attack type you're ill equipped to detect?

I'm not going to go into detail here because Microsoft already did:
{{< alert "microsoft" >}}
Read the Docs:
[SOC optimization overview](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-access?tabs=azure-portal)
[Recommendation's logic](https://learn.microsoft.com/en-us/azure/sentinel/soc-optimization/soc-optimization-reference)
{{< /alert >}}