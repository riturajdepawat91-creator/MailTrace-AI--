from services.ip_intelligence import analyze_ip


result = analyze_ip(
    "8.8.8.8"
)


print("\n==============================")
print("MAILTRACE IP INTELLIGENCE")
print("==============================")

print(
    "IP:",
    result["ip"]
)

print(
    "Valid:",
    result["valid"]
)

print(
    "Hostname:",
    result["hostname"]
)

print(
    "Country:",
    result["country"]
)

print(
    "Region:",
    result["region"]
)

print(
    "City:",
    result["city"]
)

print(
    "ISP:",
    result["isp"]
)

print(
    "Organization:",
    result["organization"]
)

print(
    "ASN:",
    result["asn"]
)

print(
    "Latitude:",
    result["latitude"]
)

print(
    "Longitude:",
    result["longitude"]
)

print(
    "Risk:",
    result["risk"]
)

print(
    "Risk Score:",
    result["risk_score"]
)

print("==============================")