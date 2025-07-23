from django.contrib import admin
from .models import Ticket, Project, Organization

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('ticket_id', 'title', 'status', 'priority', 'created_at', 'updated_at')
    list_filter = ('status', 'priority', 'project', 'organization')
    search_fields = ('ticket_id', 'title', 'description')
    readonly_fields = ('ticket_id', 'created_at', 'updated_at')
    ordering = ('-created_at',)

    fieldsets = (
        ('Ticket Details', {
            'fields': ('ticket_id', 'title', 'description', 'status', 'priority')
        }),
        ('Relations', {
            'fields': ('assignee', 'project', 'organization')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'project_key')
    search_fields = ('name', 'project_key')

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
