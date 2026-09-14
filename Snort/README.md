# Snort 2.9

A practical reference for writing, validating, and testing Snort 2.9 rules in a network laboratory.
> This guid focuses on Snort 2.9 syntax. Snort 3 uses a different configuration system in several areas.

## Table of contentes
- [1. What Is Snort?](#1-what-is-snort)
- [2. Rule Structure](#2-rule-structure)
- [3. Rule Actions](#3-rule-actions)
- [4. Protocols](#4-protocols)
- [5. IP Addresses and Variables](#5-ip-addresses-and-variables)
- [6. Ports](#6-ports)
- [7. Traffic Direction](#7-traffic-direction)
- [8. Rule Options](#8-rule-options)
- [9. Regular Expressions with `pcre`](#9-regular-expressions-with-pcre)
- [10. Rule Identification](#10-rule-identification)
- [11. Configuration and Rule Files](#11-configuration-and-rule-files)
- [12. Useful Snort Commands](#12-useful-snort-commands)
- [13. Testing with Netcat](#13-testing-with-netcat)
- [14. Snort and iptables](#14-snort-and-iptables)
- [15. Common Mistakes](#15-common-mistakes)
- [16. Rule Review Checklist](#16-rule-review-checklist)
- [17. Quick Templates](#17-quick-templates)

## 1. What is Snort?
Snort is a network traffic inspection engine that can operate as:
- A packet sniffer
- A packet logger
- A Network Intrusion Detection System (NIDS)
- A Network Intrution Prevention System (NIPS) when deployed inline

Snort rules are written using a domain-specific declarative syntax. A rule describes the traffic and payload conditions that must be met before Snort performs an action.

Snort rules are not Bash scripts. They do not represent a sequence of shell comands. Snort evaluates captured traffic against all applicable rules.

## 2. Rule Structure
A Snort rule contains a **header** and a set of **options**:

```mermaid
flowchart LR
  HD["Header"]
  OP["Options"]
  HD-->OP
```

```snort
ACTION PROTOCOL SOURCE_IP SOURCE_PORT DIRECTION DESTINATION_IP DESTINATION_PORT (OPTIONS;)
```

Generic example:

```snort
alert tcp $SOURCE_NET any -> $WEB_SERVER 8080 (msg:"Example detected"; content:"EXAMPLE"; sid:1000001; rev:1;)
```
### Rule header

```snort
alert tcp $SOURCE_NET any -> $WEB_SERVER 8080
```

The header selects the traffic to inspect.

### Rule options

```snort
(msg:"Example detected"; content:"EXAMPLE"; sid:1000001; rev:1;)
```

The options define payload conditions, alert metadata, rule identifiers, and other detection constraints.

## 3. Rule Actions

| Options | Summary | EXAMPLE |
|-----------|-----------|------|
| alert    | Generate an alert | ```alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;) ``` |
| log    | Record the packet | ```alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;) ``` |
| pass    | Ignore matching traffic | ```alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;) ``` |
| drop    | Block and alert in inline mode | ```alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;) ``` |
| sdrop    | Block silently in inline mode | ```alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;) ``` |
| reject    | Block and respond in active or inline mode | ```alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;) ``` |

## 4. Protocols
Common protocols in Snort 2.9 rule headers are:

| Protocols | Applications | EXAMPLE |
|-----------|-----------|------|
| tcp    | HTTP, HTTPS, IRC | ```alert tcp any any -> any 80 (...) ``` |
| udp    | DNS | ```alert udp any any -> any 53 (...) ``` |
| icmp    | ping | ```alert icmp any any -> any any (...) ``` |
| ip    | - | ```alert ip any any -> any any (...) ``` |

## 5. IP Addresses and Variables

| Types | Example |
|-----------|-----------|
| Single host    | ```10.5.1.10 ``` |
| Network     | ```10.5.2.0/24 ``` |
| Any address    | ``` any ``` |

### Variable definition

| Types | Example |
|-----------|-----------|
| Variable definition   | ``` var LOCAL_NET 10.5.2.0/24 ``` |
| Using variable     | ``` $LOCAL_NET ``` |
| Negation address    | ``` !10.5.2.0/24 ``` |
| Address list    | ``` [10.5.1.0/24,10.5.2.0/24] ``` |
| Everything but a list    | ``` ![10.5.1.0/24,10.5.2.0/24] ``` |

Variables make rules easier to read and maintain.

## 6. Ports

| Types | Example |
|-----------|-----------|
| Any port   | ``` any ``` |
| Specific port     | ``` 8180 ``` |
| Closed range    | ``` 6800:7000 ``` |
| Port and above    | ``` 1024: ``` |
| Port and below    | ``` :1023 ``` |
| Port list    | ``` [80,443,8180] ``` |

Example:

```snort
alert tcp $RED_LOCAL any -> $RED_EXTERNA 6800:7000 (...)
```

This selects TCP traffic from any client source port to destination ports 6800 through 7000.

## 7. Traffic Direction

| Types | Symbol | Example |
|-----------|-----------|-------|
| One direction   | ``` -> ``` | ``` $RED_LOCAL any -> $RED_EXTERNA 443 ``` |
| Both directions     | ``` <> ``` | ``` $RED_LOCAL any <> $RED_EXTERNA 443 ``` |

Use `->` when the requirement clearly identifies the initiating source and destination service.

## 8. Rule Options

Rule options are placed inside parentheses. Each option ends with a semicolon.

```snort
(msg:"Example"; content:"PATTERN"; sid:1000001; rev:1;)
```

Frequently used options include:

- `msg`
- `content`
- `nocase`
- `offset`
- `depth`
- `distance`
- `within`
- `pcre`
- `sid`
- `rev`

### Table summary 

<table>
<tr>
<th>Option</th>
<th>Description</th>
<th>Example</th>
</tr>
  
<tr>
<td>msg</td>
<td>Defines the alert text. If an assignment provides an exact message, preserve capitalization and punctuation.</td>
<td><pre>
msg:"Tomcat Manager access detected."
</pre></td>
</tr>

<tr>
<td>content</td>
<td>DThis searches for the exact byte sequence in the inspected payload.</td>
<td><pre>content:"GET /manager/html"; </pre></td>
</tr>

<tr>
<td></td>
<td>Multiple `content` options in one rule normally represent logical AND:</td>
<td>
  <pre>content:"PUT";
    content:"WEB-INF";
    content:"metasploit";</pre></td>
</tr>

<tr>
<td>nocase</td>
<td>`nocase` modifies the preceding `content`. Do not use nocase if content is not present. Matches values such as "metasploit" with:</td>
<td>
  <pre>metasploit
Metasploit
METASPLOIT;</pre></td>
</tr>

<tr>
<td>offset</td>
<td>Specifies the byte from which Snort begins searching:</td>
<td>
  <pre>content:"PUT"; offset:0;</pre></td>
</tr>

<tr>
<td>depth</td>
<td>Specifies how many bytes Snort inspects from the offset:</td>
<td>
  <pre>content:"PUT"; offset:0; depth:3;</pre></td>
</tr>

<tr>
<td>depth</td>
<td>Specifies how many bytes Snort inspects from the offset. Depth is length, not ending position.</td>
<td>
  <pre>content:"PUT"; offset:0; depth:3;</pre></td>
</tr>

<tr>
<td></td>
<td>All three later patterns must appear within the same 256-byte window beginning after `PUT`:</td>
<td>
  <pre>content:"PUT"; offset:0; depth:3;
content:"FIRST"; offset:3; depth:256;
content:"SECOND"; offset:3; depth:256;
content:"THIRD"; offset:3; depth:256;</pre></td>
</tr>

<tr>
<td>distance</td>
<td>Specifies how many bytes after the previous content match Snort should begin searching. Begins looking the new content immediately after the end of the first one:</td>
<td>
  <pre>content:"ABC";
content:"XYZ"; distance:0;</pre></td>
</tr>

<tr>
<td>within</td>
<td>Limits how far Snort may search after the previous content match. Searches for `XYZ` within 20 bytes after `ABC`. </td>
<td>
  <pre>content:"ABC";
content:"XYZ"; distance:0; within:20;</pre></td>
</tr>

<tr>
<td></td>
<td><pre>offset + depth      Absolute window from the payload start
distance + within  Relative window from the previous match</pre> </td>
<td></td>
</tr>

</table>


## 9. Regular Expressions with `pcre`

Use `pcre` for alternatives, line boundaries, repetition, and more flexible patterns.

Syntax:

```snort
pcre:"/REGULAR_EXPRESSION/MODIFIERS";
```

Example:

```snort
pcre:"/^(NICK|JOIN|SERVER)\s+/im";
```

### Expression components

#### Alternatives

```regex
(NICK|JOIN|SERVER)
```

Matches any one of the listed commands.

#### Start of line

```regex
^
```

Matches the beginning of a line.

#### Whitespace

```regex
\s
```

Matches one whitespace character.

```regex
\s+
```

Matches one or more whitespace characters.

#### `i` modifier

```regex
/i
```

Enables case-insensitive matching.

#### `m` modifier

```regex
/m
```

Enables multiline mode so that `^` can match the beginning of each line, not only the beginning of the complete payload.

### `content` vs `pcre`

Prefer `content` for:

- Fixed byte strings
- Simple literal matches
- Efficient payload inspection

Use `pcre` when you need:

- Logical OR
- Line boundaries
- Repetition
- Variable patterns

## 10. Rule Identification

### `sid`

Each custom rule needs a unique Snort ID:

```snort
sid:1000001;
```

A simple local sequence is:

```snort
sid:1000001;
sid:1000002;
sid:1000003;
```

Do not reuse a SID for two different rules.

### `rev`

Defines the rule revision:

```snort
rev:1;
```

Increase the revision when the published rule logic changes:

```snort
rev:2;
```

The revision is not the number of drafting attempts.

## 11. Configuration and Rule Files

A simple laboratory structure can use:

```text
/etc/snort/pruebas-snort.conf
/etc/snort/rules/local.rules
/var/log/snort/
```

The configuration includes the rule file:

```snort
include /etc/snort/rules/local.rules
```

Comments begin with `#`:

```snort
# Local network variables
var LOCAL_NET 10.5.2.0/24

# HTTP detection rule
alert tcp ...
```

## 12. Useful Snort Commands

### Display the installed version

```bash
snort -V
```

or:

```bash
snort --version
```

### List network interfaces

```bash
ip -br addr
```

### Capture traffic in sniffer mode

```bash
snort -i eth-int -v
```

### Validate configuration and rule syntax

```bash
snort -T -c /etc/snort/pruebas-snort.conf -i eth-int
```

A successful result ends with:

```text
Snort successfully validated the configuration!
```

### Run as an IDS and print alerts to the console

```bash
snort -q -A console -c /etc/snort/pruebas-snort.conf -i eth-int
```

Example interfaces in a segmented laboratory:

```bash
snort -q -A console -c /etc/snort/pruebas-snort.conf -i eth-ext
snort -q -A console -c /etc/snort/pruebas-snort.conf -i eth-dmz
snort -q -A console -c /etc/snort/pruebas-snort.conf -i eth-int
```

### Stop Snort

Press:

```text
Ctrl+C
```

### Important limitation of `snort -T`

Configuration test mode checks whether Snort can parse and load the configuration. It does not prove that a rule implements the intended detection logic.

A rule can validate and still:

- Select the wrong network
- Use the wrong port
- Implement AND instead of OR
- Search outside the intended byte window
- Produce false positives
- Fail to trigger on real traffic

Always perform positive and negative traffic tests when possible.

## 13. Testing with Netcat

Netcat can simulate clients and services in a controlled laboratory.

### Start a TCP listener

```bash
nc -l -p 8180
```

### Connect to the listener

```bash
nc 10.5.1.10 8180
```

Type a test payload after connecting.

### Send a prepared payload

```bash
printf 'GET /example HTTP/1.1\r\nHost: test\r\n\r\n' | nc 10.5.1.10 8180
```

### Start a UDP listener

```bash
nc -lu -p 53
```

### Connect using UDP

```bash
nc -u 10.5.1.10 53
```

### Recommended testing process

```text
1. Validate the configuration with snort -T.
2. Start Snort on the relevant interface.
3. Start the simulated destination service.
4. Generate matching traffic.
5. Confirm that an alert appears.
6. Generate similar non-matching traffic.
7. Confirm that no alert appears.
```

Only test systems and networks that you own or are explicitly authorized to assess.

## 14. Snort and iptables

Snort and iptables serve different purposes:

```text
iptables  Controls whether traffic is allowed or blocked
Snort     Inspects traffic and detects patterns
```

A restrictive firewall may block test traffic before it reaches the intended service. In a controlled laboratory, temporarily permissive firewall policies can make IDS testing easier.

Example temporary policy change:

```bash
iptables-save > /root/iptables-before-snort.rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -t nat -F
```

Restore the saved configuration after testing:

```bash
iptables-restore < /root/iptables-before-snort.rules
```

Do not use permissive firewall policies on an uncontrolled or production network.

## 15. Common Mistakes

### Missing the protocol

Incorrect:

```snort
alert $LOCAL_NET any -> $EXTERNAL_NET 6800:7000 (...)
```

Correct structure:

```snort
alert tcp $LOCAL_NET any -> $EXTERNAL_NET 6800:7000 (...)
```

### Treating multiple `content` options as OR

This means AND:

```snort
content:"JOIN";
content:"NICK";
content:"SERVER";
```

Use `pcre` for alternatives when a single rule must match any one value:

```snort
pcre:"/^(JOIN|NICK|SERVER)\s+/im";
```

### Using `within` as an absolute limit

`within` is relative to the preceding match. Use `offset` and `depth` for a window measured from the payload start.

### Treating `depth` as an end position

Incorrect interpretation:

```text
offset 3 plus 256 bytes means depth 259
```

Correct:

```snort
offset:3; depth:256;
```

### Applying `nocase`, `offset`, or `depth` to `pcre`

These are `content` modifiers. PCRE has its own modifiers, such as `i` and `m`.

### Missing PCRE delimiters

Incorrect:

```snort
pcre:"^(JOIN|NICK|SERVER)\s+/i";
```

Correct:

```snort
pcre:"/^(JOIN|NICK|SERVER)\s+/im";
```

### Reusing a SID

Every custom rule should have a unique SID.

### Assuming syntax validation proves detection correctness

`snort -T` validates parsing and configuration. It does not validate the intended semantics of the rule.

### Monitoring the wrong interface

A valid rule will not alert if Snort cannot see the relevant traffic. Select the interface through which the packet travels.

## 16. Rule Review Checklist

Before publishing or submitting a rule, verify:

- [ ] The action is correct.
- [ ] The transport protocol is correct.
- [ ] The source network or host is correct.
- [ ] The source port is defined.
- [ ] The traffic direction is correct.
- [ ] The destination host or network is correct.
- [ ] The destination port is correct.
- [ ] Existing variables are reused where appropriate.
- [ ] The alert message matches the requirement.
- [ ] Every literal pattern has its own `content` option.
- [ ] Logical AND and OR have been interpreted correctly.
- [ ] `offset` and `depth` define the intended absolute window.
- [ ] `distance` and `within` define the intended relative window.
- [ ] Every `pcre` expression is enclosed by `/.../`.
- [ ] PCRE modifiers are appropriate.
- [ ] The SID is unique.
- [ ] The revision is present.
- [ ] The rule passes `snort -T`.
- [ ] A positive test generates an alert.
- [ ] A negative test does not generate an alert.

## 17. Quick Templates

### Basic TCP alert

```snort
alert tcp $SOURCE_NET any -> $DESTINATION_HOST PORT (msg:"Exact alert message"; sid:1000001; rev:1;)
```

### Literal content at the beginning of a payload

```snort
alert tcp $SOURCE_NET any -> $DESTINATION_HOST PORT (msg:"Exact alert message"; content:"PATTERN"; offset:0; depth:LENGTH; sid:1000002; rev:1;)
```

### Several mandatory contents in one absolute window

```snort
alert tcp $SOURCE_NET any -> $DESTINATION_HOST PORT (msg:"Exact alert message"; content:"START"; offset:0; depth:5; content:"FIRST"; offset:5; depth:256; content:"SECOND"; offset:5; depth:256; sid:1000003; rev:1;)
```

### Relative content sequence

```snort
alert tcp $SOURCE_NET any -> $DESTINATION_HOST PORT (msg:"Exact alert message"; content:"FIRST"; content:"SECOND"; distance:0; within:64; sid:1000004; rev:1;)
```

### Alternative commands with PCRE

```snort
alert tcp $SOURCE_NET any -> $DESTINATION_NET 6800:7000 (msg:"IRC command detected"; pcre:"/^(NICK|JOIN|SERVER)\s+/im"; sid:1000005; rev:1;)
```

## Core Idea

```text
Rule header  Defines which traffic Snort inspects
Rule options Define what Snort searches for
Rule action  Defines what Snort does after a match
```

Use simple headers, precise payload conditions, unique rule identifiers, and real traffic tests to create reliable Snort rules.

