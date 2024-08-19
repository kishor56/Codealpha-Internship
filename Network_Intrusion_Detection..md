# Developing a Network-Based Intrusion Detection System Using Snort

In this guide, we'll walk through the process of setting up a network-based intrusion detection system (NIDS) using **Snort**, one of the most widely used open-source NIDS tools. We'll cover installation, configuration, rule creation, and monitoring of alerts.

**Table of Contents**
1. [Prerequisites](#prerequisites)
2. [Installing Snort](#installing-snort)
3. [Configuring Snort](#configuring-snort)
4. [Writing Snort Rules](#writing-snort-rules)
5. [Running Snort](#running-snort)
6. [Testing Snort Rules](#testing-snort-rules)
7. [Monitoring Alerts](#monitoring-alerts)
8. [Conclusion](#conclusion)

## Prerequisites

Before we begin, ensure you have the following:

- A machine running **Ubuntu 20.04** (or a similar Linux distribution).
- **Root** or **sudo** privileges on the machine.
- Basic understanding of networking concepts and Linux command-line operations.

## Installing Snort

### Step 1: Update System Packages

First, update your system's package list to ensure all packages are up-to-date.

```bash
sudo apt-get update
sudo apt-get upgrade -y
```

### Step 2: Install Required Dependencies

Snort requires several dependencies. Install them using the following command:

```bash
sudo apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev liblzma-dev openssl libssl-dev
```

### Step 3: Download and Install Snort

1. **Download the latest Snort source code:**

   Visit the [Snort downloads page](https://www.snort.org/downloads) to find the latest version. As of my knowledge cutoff in September 2021, the latest version was **Snort 2.9.17**. Replace the version number with the latest one if necessary.

   ```bash
   wget https://www.snort.org/downloads/snort/snort-2.9.17.tar.gz
   ```

2. **Extract the downloaded archive:**

   ```bash
   tar -xzvf snort-2.9.17.tar.gz
   ```

3. **Navigate to the extracted directory and compile Snort:**

   ```bash
   cd snort-2.9.17
   ./configure --enable-sourcefire
   make
   sudo make install
   ```

4. **Update shared library links:**

   ```bash
   sudo ldconfig
   ```

5. **Verify Snort installation:**

   ```bash
   snort -V
   ```

   The output should display the installed Snort version.

## Configuring Snort

### Step 1: Create Necessary Directories

Snort requires specific directories for its configuration, logs, and rules.

```bash
sudo mkdir -p /etc/snort/rules
sudo mkdir /var/log/snort
sudo mkdir /usr/local/lib/snort_dynamicrules
```

### Step 2: Copy Configuration Files

Copy the default configuration files to the `/etc/snort` directory.

```bash
sudo cp etc/*.conf* /etc/snort/
sudo cp etc/*.map /etc/snort/
```

### Step 3: Configure snort.conf

Open the main configuration file `/etc/snort/snort.conf` in a text editor.

```bash
sudo nano /etc/snort/snort.conf
```

**Modify the following lines:**

1. **Set the network variables:**

   Define your home and external networks. For example:

   ```conf
   var HOME_NET 192.168.1.0/24
   var EXTERNAL_NET any
   ```

2. **Specify the rule path:**

   Ensure the rule path is set correctly.

   ```conf
   var RULE_PATH /etc/snort/rules
   var SO_RULE_PATH /etc/snort/so_rules
   var PREPROC_RULE_PATH /etc/snort/preproc_rules
   var WHITE_LIST_PATH /etc/snort/rules
   var BLACK_LIST_PATH /etc/snort/rules
   ```

3. **Include rule files:**

   At the end of the file, include your rule files:

   ```conf
   include $RULE_PATH/local.rules
   ```

### Step 4: Create a Local Rules File

Create an empty `local.rules` file where you'll define your custom rules.

```bash
sudo touch /etc/snort/rules/local.rules
```

### Step 5: Adjust Permissions

Ensure Snort has the necessary permissions to access its directories and files.

```bash
sudo chmod -R 5775 /etc/snort
sudo chmod -R 5775 /var/log/snort
sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules
```

## Writing Snort Rules

Snort rules follow a specific syntax. Here's a breakdown of the rule structure:

```
action proto src_ip src_port direction dst_ip dst_port (options)
```

**Example rule: Detecting ICMP ping requests**

Let's create a rule to detect ICMP echo requests (ping requests).

1. **Open the `local.rules` file:**

   ```bash
   sudo nano /etc/snort/rules/local.rules
   ```

2. **Add the following rule:**

   ```conf
   alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; itype:8; sid:1000001; rev:1;)
   ```

   **Explanation:**
   - **alert**: Action to perform when the rule matches.
   - **icmp**: Protocol.
   - **any any -> $HOME_NET any**: Traffic from any source IP and port to any IP in HOME_NET and any port.
   - **msg**: Message to log when the rule triggers.
   - **itype:8**: ICMP type 8 corresponds to echo requests.
   - **sid**: Snort ID for the rule (should be unique).
   - **rev**: Revision number of the rule.

3. **Save and exit the file.**

## Running Snort

You can run Snort in different modes. We'll run it in **NIDS mode** to monitor network traffic based on the defined rules.

### Step 1: Identify Network Interface

Find the network interface you want Snort to monitor.

```bash
ifconfig
```

Assume the interface is `eth0`.

### Step 2: Run Snort

Execute Snort with the following command:

```bash
sudo snort -A console -i eth0 -c /etc/snort/snort.conf -l /var/log/snort
```

**Explanation:**
- **-A console**: Outputs alerts to the console.
- **-i eth0**: Monitors the `eth0` interface.
- **-c /etc/snort/snort.conf**: Specifies the configuration file.
- **-l /var/log/snort**: Specifies the log directory.

## Testing Snort Rules

To test if Snort is correctly detecting intrusion attempts, perform actions that should trigger your rules.

### Test Case: ICMP Ping Detection

1. **Open a new terminal window.**

2. **Send a ping request to your HOME_NET from another machine or from the same machine if applicable:**

   ```bash
   ping -c 4 192.168.1.10
   ```

   Replace `192.168.1.10` with an IP address within your HOME_NET range.

3. **Observe Snort Output:**

   In the terminal where Snort is running, you should see alerts similar to:

   ```
   [**] [1:1000001:1] ICMP Ping detected [**]
   [Priority: 0] 
   09/01-12:34:56.789012 192.168.1.20 -> 192.168.1.10
   ICMP TTL:64 TOS:0x0 ID:54321 IpLen:20 DgmLen:84
   Type:8 Code:0 ID:12345 Seq:1 ECHO
   ```

## Monitoring Alerts

Snort logs alerts to the `/var/log/snort` directory. You can analyze these logs for further investigation.

### View Alert Logs

The alerts are typically stored in a file named `alert`. Use the following command to view them:

```bash
sudo cat /var/log/snort/alert
```

### Using Barnyard2 for Log Management

For better log management and to store logs in databases, you can use tools like **Barnyard2**. Setting up Barnyard2 is beyond the scope of this guide, but it's recommended for production environments.

## Conclusion

You've successfully set up a basic network-based intrusion detection system using Snort. You learned how to install and configure Snort, write custom rules, run Snort in NIDS mode, and monitor alerts.

**Next Steps:**
- Explore and implement more complex rules.
- Integrate Snort with a log management system like **Barnyard2** or **Splunk** for advanced monitoring and analysis.
- Regularly update Snort rules to keep up with the latest threats. You can use community rule sets like those from **Snort.org** or **Emerging Threats**.

**References:**
- [Snort Official Documentation](https://www.snort.org/documents)
- [Snort User Manual](https://www.snort.org/documents/snort-users-manual)

**Disclaimer:** Ensure you have proper authorization to monitor and test network traffic, especially in production environments. Unauthorized monitoring can lead to legal consequences.
