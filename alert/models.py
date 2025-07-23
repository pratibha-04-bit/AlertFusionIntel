# models.py
from django.db import models
from django.contrib.auth.models import User

class Project(models.Model):
    project_key = models.CharField(max_length=20, unique=True)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Organization(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Ticket(models.Model):
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
        ('CLOSED', 'Closed'),
    ]

    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    ticket_id = models.CharField(max_length=50, unique=True, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField()
    hostname = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='LOW')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='tickets')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tickets')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='tickets')

    def save(self, *args, **kwargs):
        if not self.ticket_id:
            last_ticket = Ticket.objects.filter(project=self.project).order_by('-created_at').first()
            new_number = int(last_ticket.ticket_id.split('-')[-1]) + 1 if last_ticket else 1
            self.ticket_id = f"{self.project.project_key}-{new_number}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ticket_id}: {self.title} ({self.get_status_display()})"

    class Meta:
        ordering = ['-created_at']
