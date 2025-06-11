from django import forms
from django.utils import timezone
from .models import Permission, Session

class PermissionRequestForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['session', 'reason', 'explanation']
        widgets = {
            'explanation': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Please explain your reason for requesting permission...'}),
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
            )

class PermissionApprovalForm(forms.ModelForm):
    class Meta:
        model = Permission
        fields = ['status', 'admin_comment']
        widgets = {
            'status': forms.Select(
                choices=[('approved', 'Approve'), ('rejected', 'Reject')],
                attrs={'class': 'form-select'}
            ),
            'admin_comment': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 3,
                    'placeholder': 'Please provide a reason for your decision...',
                    'required': True
                }
            )
        }

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        admin_comment = cleaned_data.get('admin_comment')

        if not admin_comment:
            raise forms.ValidationError('Please provide a reason for your decision.')

        return cleaned_data 
