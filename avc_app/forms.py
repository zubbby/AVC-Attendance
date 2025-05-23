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

class PermissionApprovalForm(forms.Form):
    status = forms.ChoiceField(
        choices=[('approved', 'Approve'), ('rejected', 'Reject')],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    admin_comment = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Please provide a reason for your decision...'
        }),
        required=True,
        min_length=5,
        max_length=500,
        help_text='Please provide a clear explanation for your decision (5-500 characters).'
    )

    def clean_admin_comment(self):
        comment = self.cleaned_data['admin_comment']
        if len(comment.strip()) < 5:
            raise forms.ValidationError('Please provide a more detailed comment (minimum 5 characters).')
        return comment.strip() 
