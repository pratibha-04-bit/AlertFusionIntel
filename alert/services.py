# services.py
import requests
from django.utils import timezone
from datetime import timedelta
from .models import Ticket, Project, Organization
from django.contrib.auth.models import User
from django.db import transaction

VIRUSTOTAL_API_KEY = ''
ABUSEIPDB_API_KEY = ''

def create_or_correlate_ticket(title, description, severity, hostname, project_key, organization_id, assignee_username=None):
    """
    Create or correlate a ticket based on severity and hostname.
    """
    try:
        project = Project.objects.get(project_key=project_key)
        organization = Organization.objects.get(id=organization_id)
    except (Project.DoesNotExist, Organization.DoesNotExist):
        raise ValueError("Invalid Project or Organization.")

    assignee = User.objects.filter(username=assignee_username).first() if assignee_username else None

    # For LOW/MEDIUM - Always create a new alert
    if severity in ['LOW', 'MEDIUM']:
        return create_ticket(title, description, severity, hostname, project, organization, assignee)

    # For HIGH/CRITICAL - Correlate within 1 hour
    time_threshold = timezone.now() - timedelta(hours=1)
    correlated_ticket = Ticket.objects.filter(
        hostname=hostname,
        priority=severity,
        project=project,
        organization=organization,
        created_at__gte=time_threshold
    ).first()

    if correlated_ticket:
        correlated_ticket.description += f"\n\n[New Alert]: {description}"
        correlated_ticket.updated_at = timezone.now()
        correlated_ticket.save()
        return correlated_ticket

    return create_ticket(title, description, severity, hostname, project, organization, assignee)

def create_ticket(title, description, severity, hostname, project, organization, assignee):
    """
    Create a new alert ticket.
    """
    with transaction.atomic():
        ticket = Ticket.objects.create(
            title=title,
            description=f"Host: {hostname}\n\n{description}",
            priority=severity,
            hostname=hostname,
            project=project,
            organization=organization,
            assignee=assignee
        )
        
        # Trigger enrichment in the background
        enrich_ticket(ticket)

        return ticket

def enrich_ticket(ticket):
    """
    Enrich ticket with external threat intelligence.
    """
    indicators = extract_indicators(ticket.description)
    enrichment_data = {
        'hash': get_hash_reputation(indicators.get('hash')),
        'ip': get_ip_reputation(indicators.get('ip')),
        'url': get_url_reputation(indicators.get('url'))
    }
    ticket.enrichment = enrichment_data
    ticket.save()

def extract_indicators(description):
    """
    Extract hash, IP, and URL from the alert description.
    """
    import re
    indicators = {
        'hash': re.findall(r'\b[a-f0-9]{64}\b', description),
        'ip': re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', description),
        'url': re.findall(r'https?://[^\s]+', description)
    }
    return {k: v[0] if v else None for k, v in indicators.items()}

def get_hash_reputation(hash_value):
    if not hash_value:
        return "No hash found"
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else "Hash not found"

def get_ip_reputation(ip):
    if not ip:
        return "No IP found"
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip}
    response = requests.get(url, headers=headers, params=params)
    return response.json() if response.status_code == 200 else "IP not found"

def get_url_reputation(url):
    if not url:
        return "No URL found"
    vt_url = f'https://www.virustotal.com/api/v3/urls'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.post(vt_url, headers=headers, data={'url': url})
    return response.json() if response.status_code == 200 else "URL not found"
