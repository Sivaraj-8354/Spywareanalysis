import tkinter as tk
from tkinter import filedialog
from functools import partial
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
        author = "Agent tesla"
        reference = "-"
        version = "1.0"

    strings:
        $username_string = "Username:" ascii
        $password_string = "Password:" ascii

    condition:
        any of them
}
"""
agentteslsmtprules = """
rule agenttesla_smtp_variant {

    meta:
        author = "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
        date = "2018/2"
	reference1 = "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
	reference2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
	reference3 = "Agent Tesla == negasteal -- @coldshell"
	version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
		$a = "type={"
		$b = "hwid={"
		$c = "time={"
		$d = "pcname={"
		$e = "logdata={"
		$f = "screen={"
		$g = "ipadd={"
		$h = "webcam_link={"
		$i = "screen_link={"
		$j = "site_username={"
		$k = "[passwords]"

    condition:
        6 of them
}"""

# Compile the YARA rules
compiled_rule = yara.compile(sources={"agentteslarules": agentteslarules, "detectspywarerules": detectspywarerules})


def analyze_pcap(filepath, output_text):
    packets = rdpcap(filepath)
    output_text.delete(1.0, tk.END)  # Clear previous output

    spyware_detected = False

    for pkt in packets:
        if pkt.haslayer('IP'):
            src_ip = pkt.getlayer('IP').src
            dst_ip = pkt.getlayer('IP').dst

            if pkt.haslayer('Raw'):
                payload = pkt.getlayer('Raw').load

                # Check for sensitive information such as passwords and usernames
                if is_sensitive_info(payload):
                    output_text.insert(tk.END, "\nSensitive information detected in packet from {} to {}:\n".format(src_ip, dst_ip))
                    output_text.insert(tk.END, "\nPacket Summary: {}\n".format(pkt.summary()))
                    output_text.insert(tk.END, "\nPayload Content:\n{}\n\n".format(payload.decode()))

                # Additional malware detection algorithms
                if is_executable_file(payload):
                    output_text.insert(tk.END, "\nExecutable file detected in packet from {} to {}:\n".format(src_ip, dst_ip))
                    output_text.insert(tk.END, "\nPacket Summary: {}\n".format(pkt.summary()))
                    output_text.insert(tk.END, "\nFile Content:\n{}\n\n".format(payload))

                # YARA rule detection
                spyware_info = is_spyware(payload)
                if spyware_info:
                    spyware_detected = True
                    output_text.insert(tk.END, "\nSpyware detected in packet from {} to {}:\n".format(src_ip, dst_ip))
                    output_text.insert(tk.END, "\nPacket Summary: {}\n".format(pkt.summary()))
                    output_text.insert(tk.END, "\nSpyware Details:\n")
                    for key, value in spyware_info.items():
                        output_text.insert(tk.END, "\n{}: {}\n".format(key.capitalize(), value))
                    output_text.insert(tk.END, "\n")

    if not spyware_detected:
        output_text.insert(tk.END, "No spyware detected in the analyzed PCAP file: {}\n".format(filepath))


# Match payload against the compiled YARA rules and return spyware details if found
def is_spyware(payload):
    matches = compiled_rule.match(data=payload)
    if matches:
        # Extract metadata from YARA rule
        spyware_details = {}
        for match in matches:
            spyware_details['Rule Name'] = match.rule
            spyware_details['Description'] = match.meta['description']
            spyware_details['Author'] = match.meta['author']
            spyware_details['Reference'] = match.meta['reference']
            spyware_details['Version'] = match.meta['version']
        return spyware_details
    return None


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


def browse_file(output_text):
    filename = filedialog.askopenfilename(initialdir="/", title="Select PCAP File", filetypes=(("PCAP files", "*.pcap"), ("all files", "*.*")))
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Selected PCAP File: {}\n".format(filename))
    analyze_pcap(filename, output_text)


def clear_output(output_text):
    output_text.delete(1.0, tk.END)


root = tk.Tk()
root.title("PCAP Analyzer")

input_label = tk.Label(root, text="PCAP File Path:")
input_label.grid(row=0, column=0, padx=5, pady=5)

input_text = tk.Entry(root, width=50)
input_text.grid(row=0, column=1, padx=5, pady=5)

analyze_button = tk.Button(root, text="Analyze", command=lambda: analyze_pcap(input_text.get(), output_text))
analyze_button.grid(row=0, column=2, padx=5, pady=5)

output_text = tk.Text(root, height=20, width=80)
output_text.grid(row=1, column=0, columnspan=3, padx=10, pady=10)

browse_button = tk.Button(root, text="Browse", command=partial(browse_file, output_text))
browse_button.grid(row=2, column=0, padx=5, pady=5)

clear_button = tk.Button(root, text="Clear Output", command=partial(clear_output, output_text))
clear_button.grid(row=2, column=1, padx=5, pady=5)

exit_button = tk.Button(root, text="Exit", command=root.quit)
exit_button.grid(row=2, column=2, padx=5, pady=5)

root.mainloop()
