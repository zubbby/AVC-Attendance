from django import forms
from django.utils import timezone
from .models import Permission, Session

class PermissionRequestForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['session', 'reason', 'explanation']
        widgets = {
            'explanation': forms.Textarea(attrs={
                'rows': 4,
                'placeholder': 'Please explain your reason for requesting permission...',
                'class': 'form-control'
            }),
            'session': forms.Select(attrs={'class': 'form-select'}),
            'reason': forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            # Only show sessions that haven't ended yet
            self.fields['session'].queryset = Session.objects.filter(
                end_time__gt=timezone.now()
            ).order_by('-start_time')  # Order by most recent first

    def clean_explanation(self):
        explanation = self.cleaned_data.get('explanation')
        if not explanation or len(explanation.strip()) < 10:
            raise forms.ValidationError('Please provide a detailed explanation (minimum 10 characters).')
        return explanation.strip()

    def clean(self):
        cleaned_data = super().clean()
        session = cleaned_data.get('session')
        reason = cleaned_data.get('reason')
        
        if session and reason:
            # Check if session has already ended
            if session.end_time < timezone.now():
                raise forms.ValidationError('Cannot request permission for a session that has already ended.')
            
            # Check if session hasn't started yet
            if session.start_time > timezone.now():
                raise forms.ValidationError('Cannot request permission for a session that hasn\'t started yet.')
        
        return cleaned_data

class PermissionApprovalForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['status', 'admin_comment']
        widgets = {
            'status': forms.Select(
        choices=[('approved', 'Approve'), ('rejected', 'Reject')],
                attrs={
                    'class': 'form-select',
                    'aria-label': 'Decision'
                }
            ),
            'admin_comment': forms.Textarea(
                attrs={
            'class': 'form-control',
            'rows': 3,
                    'placeholder': 'Please provide a reason for your decision...',
                    'required': True,
                    'aria-label': 'Admin Comment'
                }
            )
        }

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        admin_comment = cleaned_data.get('admin_comment')

        if not admin_comment or len(admin_comment.strip()) < 10:
            raise forms.ValidationError('Please provide a detailed reason for your decision (minimum 10 characters).')

        return cleaned_data

class SessionForm(forms.ModelForm):
    class Meta:
        model = Session
        fields = ['name', 'start_time', 'end_time', 'allowed_users']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Session Name'}),
            'start_time': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'end_time': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
            'allowed_users': forms.SelectMultiple(attrs={'class': 'form-select'})
        }

    def clean(self):
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        if start_time and end_time and end_time <= start_time:
            raise forms.ValidationError('End time must be after start time.')
        return cleaned_data 
