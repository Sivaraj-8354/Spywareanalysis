from scapy.all import rdpcap
import yara

# Define the YARA rule strings
agentteslarules = """
rule AgentTesla
{
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
        version = "1.0"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}
"""
detectspywarerules = """
rule DetectSpyware {
    meta:
        description = "Detects potential spyware behavior in email communications"
        author = "-"
        reference = "-"
        version = "1.0"

    strings:
        $username_string = "Username:" ascii
        $password_string = "Password:" ascii

    condition:
        any of them
}
"""

# Compile the YARA rules
compiled_rule = yara.compile(sources={"agentteslarules": agentteslarules, "detectspywarerules": detectspywarerules})

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    for pkt in packets:
        if pkt.haslayer('IP'):
            src_ip = pkt.getlayer('IP').src
            dst_ip = pkt.getlayer('IP').dst

            if pkt.haslayer('Raw'):
                payload = pkt.getlayer('Raw').load
                
                # Check for sensitive information such as passwords and usernames
                if is_sensitive_info(payload):
                    print("Sensitive information detected in packet from {} to {}: {}".format(src_ip, dst_ip, pkt.summary()))
                    print("Payload Content:")
                    print(payload.decode())  # Print the payload for more details
                    print()
                
                # Additional malware detection algorithms
                if is_executable_file(payload):
                    print("Executable file detected in packet from {} to {}: {}".format(src_ip, dst_ip, pkt.summary()))
                    print("File Content:")
                    print(payload)  # Print the file content for more details
                    print()
                
                # YARA rule detection
                spyware_info = is_spyware(payload)
                if spyware_info:
                    print("Spyware detected in packet from {} to {}: {}".format(src_ip, dst_ip, pkt.summary()))
                    print("Spyware Details:")
                    for key, value in spyware_info.items():
                        print("{}: {}".format(key.capitalize(), value))
                    print()

# Match payload against the compiled YARA rules and return spyware details if found
def is_spyware(payload):
    matches = compiled_rule.match(data=payload)
    if matches:
        # Extract metadata from YARA rule
        spyware_details = {}
        for match in matches:
            spyware_details['rule_name'] = match.rule
            spyware_details['description'] = match.meta['description']
            spyware_details['author'] = match.meta['author']
            spyware_details['reference'] = match.meta['reference']
            spyware_details['version'] = match.meta['version']
        return spyware_details
    return None

# Match payload against known malware signatures or patterns
def is_malware_signature(payload):
    # Example: Check for known malware signatures or patterns
    # Here we're checking for specific byte sequences that are commonly associated with malware
    malware_signatures = [b'\x4d\x5a', b'DOS mode', b'evil_payload']
    for signature in malware_signatures:
        if signature in payload:
            return True
    return False

# Check if the payload contains sensitive information
def is_sensitive_info(payload):
    # Example: Check for passwords and usernames in the payload
    # This function checks for common keywords indicating sensitive information
    sensitive_keywords = [b'password', b'username']
    for keyword in sensitive_keywords:
        if keyword in payload.lower():  # Convert to lowercase for case-insensitive search
            return True
    return False

# Check if the payload resembles an executable file
def is_executable_file(payload):
    # Example: Check if the payload resembles an executable file
    # This function checks for common file extensions indicating executable files
    executable_file_extensions = [b'.exe', b'.dll', b'.bat']
    for extension in executable_file_extensions:
        if extension in payload:
            return True
    return False

if __name__ == "__main__":
    pcap_file = "2023-01-Unit42-Wireshark-quiz.pcap"
    analyze_pcap(pcap_file)
