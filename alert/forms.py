# forms.py
from django import forms
from .models import Ticket, Project, Organization
from django.contrib.auth.models import User

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['title', 'description', 'status', 'priority', 'assignee', 'project', 'organization']

    def __init__(self, *args, **kwargs):
        user = kwargs.get('user', None)  # Retrieve the user from the form initialization
        super().__init__(*args, **kwargs)
        
        if user and user.is_authenticated:
            # Filter organizations based on the logged-in user (optional, if you have a user-organization relationship)
            self.fields['organization'].queryset = Organization.objects.filter(users=user)
            if self.instance and self.instance.organization:
                # Filter projects based on the selected organization
                self.fields['project'].queryset = Project.objects.filter(organization=self.instance.organization)
            else:
                self.fields['project'].queryset = Project.objects.none()

    def clean_project(self):
        # Ensure the selected project belongs to the selected organization
        project = self.cleaned_data.get('project')
        if project and project.organization != self.cleaned_data['organization']:
            raise forms.ValidationError('The selected project does not belong to the chosen organization.')
        return project
    
class UpdateTicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['title', 'description', 'status', 'assignee']  # Include the assignee field here

    # Optionally, you can add custom validation or widgets here
    assignee = forms.ModelChoiceField(
        queryset=User.objects.all(), 
        required=False, 
        empty_label="Unassigned"  # This will show "Unassigned" if no assignee is selected
    )
