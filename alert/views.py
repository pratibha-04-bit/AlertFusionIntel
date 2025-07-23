import re
import requests
from django.utils import timezone
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from .models import Ticket
from .forms import TicketForm
from django.core.paginator import Paginator

# Helper Function: Extract alert details from description
def extract_alert_details(description):
    details = {
        'domain': re.search(r'Domain: ([\w\.-]+)', description),
        'sha256': re.search(r'SHA256: ([a-fA-F0-9]{64})', description),
        'severity': re.search(r'Severity: (\w+)', description),
        'hostname': re.search(r'Hostname: ([\w-]+)', description)
    }
    return {k: v.group(1) if v else None for k, v in details.items()}

# Enrichment Functions
def enrich_hash(hash_value):
    vt_url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": "YOUR_VT_API_KEY"}
    response = requests.get(vt_url, headers=headers)
    if response.status_code == 200:
        return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return "No data available from VirusTotal."

def enrich_domain(domain):
    urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    response = requests.get(urlscan_url)
    if response.status_code == 200:
        results = response.json().get("results", [])
        if results:
            return results[0]
    return "No data available from URLScan.io."

# Main Ticket Creation and Correlation Logic
def create_ticket(request):
    if request.method == 'POST':
        form = TicketForm(request.POST, user=request.user)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.created_by = request.user

            # Extract alert details from description
            alert_details = extract_alert_details(ticket.description)
            hostname = alert_details.get('hostname')
            severity = alert_details.get('severity')
            sha256 = alert_details.get('sha256')
            domain = alert_details.get('domain')

            # Correlation Logic: Check for High/Critical alerts within 1 hour
            if severity in ['High', 'Critical']:
                one_hour_ago = timezone.now() - timedelta(hours=1)
                correlated_ticket = Ticket.objects.filter(
                    project=ticket.project,
                    organization=ticket.organization,
                    priority__in=['High', 'Critical'],
                    description__icontains=hostname,
                    created_at__gte=one_hour_ago
                ).first()

                if correlated_ticket:
                    correlated_ticket.description += f"\n\n---\nNew Alert:\n{ticket.description}"
                    correlated_ticket.save()
                    return redirect('ticket_list')

            # Enrichment Data
            enrichment_data = ""
            if sha256:
                enrichment_data += f"\n\n**VirusTotal Enrichment:**\n{enrich_hash(sha256)}"
            if domain:
                enrichment_data += f"\n\n**URLScan.io Enrichment:**\n{enrich_domain(domain)}"

            # Append enrichment data to ticket description
            ticket.description += enrichment_data
            ticket.save()

            return redirect('ticket_list')

    else:
        form = TicketForm()

    return render(request, 'create_ticket.html', {'form': form})

def alert_list_view(request):
    alerts = Ticket.objects.all().order_by('-created_at')
    paginator = Paginator(alerts, 10)  # Paginate alerts
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'alert_list_.html', {'page_obj': page_obj})


# Master View: List of All Alerts
def alerts_list(request):
    alerts = Ticket.objects.all().order_by('-created_at')  # List all alerts
    return render(request, 'alerts_list.html', {'alerts': alerts})

# Helper function to extract hostname from description
def extract_hostname(description):
    pattern = re.compile(r'Hostname:\s*([\w.-]+)')
    match = pattern.search(description)
    return match.group(1) if match else None

# Detail View: Specific Alert + Correlated Alerts
def alert_detail(request, pk):
    print("*** test")
    alert = get_object_or_404(Ticket, pk=pk)

    # Extract hostname from the current alert's description
    alert_details = extract_alert_details(alert.description)
    hostname = alert_details.get('hostname')

    correlated_alerts = Ticket.objects.none()

    # Ensure hostname and priority are present
    if hostname and alert.priority in ['High', 'Critical']:
        print("===== Correlation Logic: Debugging =====")
        print(f"Extracted Hostname: {hostname}")
        print(f"Alert Priority: {alert.priority}")

        # Normalize the hostname for case-insensitive matching
        normalized_hostname = hostname.lower()

        # Correlation Logic: Find alerts with the same hostname (case-insensitive) and high/critical severity
        correlated_alerts = Ticket.objects.filter(
            description__icontains=normalized_hostname,
            priority__in=['High', 'Critical']
        ).exclude(id=alert.id)

        # Debugging: Print the generated SQL query and check the results
        print(f"Generated Query: {correlated_alerts.query}")
        print(f"Query Result Count: {correlated_alerts.count()}")

        # Force evaluation and display matched correlated alerts
        for correlated in correlated_alerts:
            print(f"Correlated Alert ID: {correlated.id}, Hostname: {hostname}, Priority: {correlated.priority}")

        # Optional: Time-based correlation (commented for now)
        # one_hour_ago = alert.created_at - timedelta(hours=1)
        # correlated_alerts = correlated_alerts.filter(created_at__gte=one_hour_ago)



    return render(request, 'alert_detail.html', {
        'alert': alert,
        'correlated_alerts': correlated_alerts
    })


# Detail View: Specific Alert + Correlated Alerts
# def alert_detail(request, pk):
#     alert = get_object_or_404(Ticket, pk=pk)
#     print("@@@@@@@@@@@",alert.description)
#     # Extract hostname from description
#     hostname = extract_hostname(alert.description)
#     print("***********************",hostname)

#     # Ensure hostname is present
#     if hostname:
#         # Get correlated alerts: Same hostname + within 1 hour + severity High/Critical
#         # one_hour_ago = alert.created_at - timedelta(hours=10)
#         correlated_alerts = Ticket.objects.filter(
#             description__icontains=hostname,
#             priority__in=['High', 'Critical'],
#             # created_at__gte=one_hour_ago,
#             # created_at__lte=alert.created_at + timedelta(hours=1)
#         ).exclude(id=alert.id)

#     else:
#         correlated_alerts = Ticket.objects.none()
#     print(f"Hostname: {hostname}")
#     print(f"Correlated Alerts: {correlated_alerts}")

#     return render(request, 'alert_detail.html', {
#         'alert': alert,
#         'correlated_alerts': correlated_alerts
#     })
