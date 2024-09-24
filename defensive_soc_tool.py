import requests
import sys
from datetime import datetime

# Clés API
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
EMAILREP_API_KEY = 'YOUR_EMAILREP_API_KEY'
ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_API_KEY'

def check_hash_with_virustotal(file_hash):
    """Vérifie le hash avec VirusTotal."""
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error retrieving data: {response.status_code}"}

def get_email_info(email):
    """Obtenez des informations sur l'e-mail avec EmailRep."""
    url = f'https://emailrep.io/{email}'
    headers = {
        'Content-Type': 'application/json',
        'API-Key': EMAILREP_API_KEY
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error retrieving data: {response.status_code}"}

def check_ip_with_abuseipdb(ip):
    """Vérifie l'IP avec AbuseIPDB."""
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params = {'ipAddress': ip}
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Error retrieving data: {response.status_code}"}

def generate_report(hash_value, email, ip, vt_result, email_info, ip_info):
    """Générer un rapport à partir des résultats des vérifications."""
    report_file = f'defensive_report_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt'
    with open(report_file, 'w') as f:
        f.write(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Vérification du hash avec VirusTotal
        f.write(f"[HASH CHECK]\n")
        f.write(f"Hash: {hash_value}\n")
        if 'error' not in vt_result:
            f.write(f"VirusTotal Result: {vt_result}\n")
        else:
            f.write(vt_result['error'] + "\n")
        
        # Vérification de l'e-mail avec EmailRep
        f.write(f"\n[EMAIL CHECK]\n")
        f.write(f"Email: {email}\n")
        if 'error' not in email_info:
            f.write(f"EmailRep Result: {email_info}\n")
        else:
            f.write(email_info['error'] + "\n")
        
        # Vérification de l'IP avec AbuseIPDB
        f.write(f"\n[IP CHECK]\n")
        f.write(f"IP: {ip}\n")
        if 'error' not in ip_info:
            f.write(f"AbuseIPDB Result: {ip_info}\n")
        else:
            f.write(ip_info['error'] + "\n")
    
    print(f"Report saved to {report_file}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python defensive_tool.py <hash> <email> <ip>")
        sys.exit(1)

    hash_value = sys.argv[1]
    email = sys.argv[2]
    ip = sys.argv[3]

    # Vérification du hash avec VirusTotal
    vt_result = check_hash_with_virustotal(hash_value)

    # Vérification de l'email avec EmailRep
    email_info = get_email_info(email)

    # Vérification de l'IP avec AbuseIPDB
    ip_info = check_ip_with_abuseipdb(ip)

    # Génération du rapport
    generate_report(hash_value, email, ip, vt_result, email_info, ip_info)

if __name__ == "__main__":
    main()
