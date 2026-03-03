from django import forms

from monitoring.models import PatientRecord


class PatientRecordForm(forms.ModelForm):
    class Meta:
        model = PatientRecord
        fields = [
            "hospital_id",
            "full_name",
            "date_of_birth",
            "diagnosis",
            "notes",
            "attending_doctor",
        ]
        widgets = {
            "date_of_birth": forms.DateInput(attrs={"type": "date"}),
        }
