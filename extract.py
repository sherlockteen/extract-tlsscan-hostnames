#!/usr/bin/env python3
# https://github.com/sherlockteen
# Use it to retrieve host name information from the JSON output of tls-scan

import json
import sys

def filter_hostnames(unfiltered):
    if unfiltered is None:
        return None
    # Упрощенный фильтр для вашего примера
    if "kubernetes" in unfiltered or "kube-api" in unfiltered or "ip-" in unfiltered:
        return None
    filtered = unfiltered.replace("DNS:", "").replace("IP Address:", "").replace("*.","")
    return filtered

if len(sys.argv) != 2:
    print("Extract host name information from TLS-Scan JSON certificate details.")
    print("This isn't perfect, and you will likely need to do some manual filtering of these results.\n")
    print(f"Usage: {sys.argv[0]} <tls-scan-output.json>")
    sys.exit(0)

with open(sys.argv[1], "r") as fc:
    certsubjects = []
    for line in fc:
        json_rec = json.loads(line)

        # Проверки для subjectCN
        if "cert" in json_rec and "subject" in json_rec["cert"] and "commonName" in json_rec["cert"]["subject"]:
            subject = json_rec["cert"]["subject"]["commonName"]
            subject = filter_hostnames(subject)
            if subject and " " not in subject and "." in subject:
                certsubjects.append(json_rec["ip"] + ":" + subject)

        # Проверки для subjectAltName
        if "cert" in json_rec and "subjectAltName" in json_rec["cert"]:
            for alt_subject in json_rec["cert"]["subjectAltName"]:
                alt_subject = filter_hostnames(alt_subject[1])
                if alt_subject:
                    certsubjects.append(json_rec["ip"] + ":" + alt_subject)

    for each_subject in sorted(set(certsubjects)):
        print(each_subject)
