from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import QuerySet
from django.http import QueryDict
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_POST
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from monitoring.forms import PatientRecordForm
from monitoring.models import AccessLog, EvaluationResult, PatientRecord, RoleChoices
from monitoring.real_data import DATASET_MARKER
from monitoring.permissions import RoleRequiredMixin, get_user_role, user_has_any_role
from monitoring.services import evaluate_detector, log_record_access, run_isolation_forest_detection


class PatientListView(RoleRequiredMixin, ListView):
    model = PatientRecord
    template_name = "monitoring/patient_list.html"
    context_object_name = "patients"
    paginate_by = 20
    allowed_roles = (RoleChoices.DOCTOR, RoleChoices.NURSE, RoleChoices.ADMIN)

    def get_queryset(self) -> QuerySet[PatientRecord]:
        return (
            PatientRecord.objects.select_related("attending_doctor")
            .all()
            .order_by("full_name")
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["role"] = get_user_role(self.request.user)
        context["total_access_logs"] = AccessLog.objects.count()
        context["flagged_logs"] = AccessLog.objects.filter(is_flagged=True).count()
        return context


class PatientDetailView(RoleRequiredMixin, DetailView):
    model = PatientRecord
    template_name = "monitoring/patient_detail.html"
    context_object_name = "patient"
    allowed_roles = (RoleChoices.DOCTOR, RoleChoices.NURSE, RoleChoices.ADMIN)

    def get_object(self, queryset=None):
        patient = super().get_object(queryset)
        log_record_access(
            user=self.request.user,
            patient_record=patient,
            action=AccessLog.AccessAction.VIEW,
            request=self.request,
        )
        return patient


class PatientCreateView(RoleRequiredMixin, CreateView):
    model = PatientRecord
    form_class = PatientRecordForm
    template_name = "monitoring/patient_form.html"
    success_url = reverse_lazy("patient-list")
    allowed_roles = (RoleChoices.DOCTOR, RoleChoices.ADMIN)

    def form_valid(self, form):
        response = super().form_valid(form)
        log_record_access(
            user=self.request.user,
            patient_record=self.object,
            action=AccessLog.AccessAction.CREATE,
            request=self.request,
        )
        messages.success(self.request, "Patient record created.")
        return response


class PatientUpdateView(RoleRequiredMixin, UpdateView):
    model = PatientRecord
    form_class = PatientRecordForm
    template_name = "monitoring/patient_form.html"
    allowed_roles = (RoleChoices.DOCTOR, RoleChoices.ADMIN)

    def get_success_url(self):
        return reverse_lazy("patient-detail", kwargs={"pk": self.object.pk})

    def get_object(self, queryset=None):
        patient = super().get_object(queryset)
        if self.request.method == "GET":
            log_record_access(
                user=self.request.user,
                patient_record=patient,
                action=AccessLog.AccessAction.VIEW,
                request=self.request,
                notes="Opened patient update form",
            )
        return patient

    def form_valid(self, form):
        response = super().form_valid(form)
        log_record_access(
            user=self.request.user,
            patient_record=self.object,
            action=AccessLog.AccessAction.UPDATE,
            request=self.request,
        )
        messages.success(self.request, "Patient record updated.")
        return response


class PatientDeleteView(RoleRequiredMixin, DeleteView):
    model = PatientRecord
    template_name = "monitoring/patient_confirm_delete.html"
    success_url = reverse_lazy("patient-list")
    allowed_roles = (RoleChoices.ADMIN,)

    def get_object(self, queryset=None):
        patient = super().get_object(queryset)
        if self.request.method == "GET":
            log_record_access(
                user=self.request.user,
                patient_record=patient,
                action=AccessLog.AccessAction.VIEW,
                request=self.request,
                notes="Opened patient delete confirmation",
            )
        return patient

    def post(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        patient = self.get_object()
        log_record_access(
            user=request.user,
            patient_record=patient,
            action=AccessLog.AccessAction.DELETE,
            request=request,
        )
        messages.warning(request, "Patient record deleted.")
        return super().post(request, *args, **kwargs)


class AccessLogListView(RoleRequiredMixin, ListView):
    model = AccessLog
    template_name = "monitoring/accesslog_list.html"
    context_object_name = "logs"
    paginate_by = 50
    allowed_roles = (RoleChoices.ADMIN,)

    def get_queryset(self):
        queryset = AccessLog.objects.select_related("user", "patient_record").all()

        user_query = self.request.GET.get("user", "").strip()
        patient_query = self.request.GET.get("patient", "").strip()
        action_query = self.request.GET.get("action", "").strip().lower()
        source_query = self.request.GET.get("source", "").strip().lower()
        flagged_query = self.request.GET.get("flagged", "").strip().lower()
        date_from_query = self.request.GET.get("date_from", "").strip()
        date_to_query = self.request.GET.get("date_to", "").strip()

        if user_query:
            queryset = queryset.filter(user__username__icontains=user_query)
        if patient_query:
            queryset = queryset.filter(patient_record__hospital_id__icontains=patient_query)
        if action_query:
            queryset = queryset.filter(action=action_query)
        if source_query == "live":
            queryset = queryset.filter(is_simulated=False)
        if flagged_query == "yes":
            queryset = queryset.filter(is_flagged=True)
        elif flagged_query == "no":
            queryset = queryset.filter(is_flagged=False)

        date_from = parse_date(date_from_query) if date_from_query else None
        date_to = parse_date(date_to_query) if date_to_query else None
        if date_from:
            queryset = queryset.filter(accessed_at__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(accessed_at__date__lte=date_to)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filters"] = {
            "user": self.request.GET.get("user", "").strip(),
            "patient": self.request.GET.get("patient", "").strip(),
            "action": self.request.GET.get("action", "").strip().lower(),
            "source": self.request.GET.get("source", "").strip().lower(),
            "flagged": self.request.GET.get("flagged", "").strip().lower(),
            "date_from": self.request.GET.get("date_from", "").strip(),
            "date_to": self.request.GET.get("date_to", "").strip(),
        }
        context["action_choices"] = AccessLog.AccessAction.choices
        query_copy = QueryDict(mutable=True)
        query_copy.update(self.request.GET)
        if "page" in query_copy:
            query_copy.pop("page")
        encoded = query_copy.urlencode()
        context["page_query"] = f"&{encoded}" if encoded else ""
        return context


class AnomalyListView(RoleRequiredMixin, ListView):
    model = AccessLog
    template_name = "monitoring/anomaly_list.html"
    context_object_name = "logs"
    paginate_by = 50
    allowed_roles = (RoleChoices.ADMIN,)

    def get_queryset(self):
        return (
            AccessLog.objects.select_related("user", "patient_record")
            .filter(is_flagged=True)
            .order_by("-anomaly_score", "-accessed_at")
        )


class EvaluationListView(RoleRequiredMixin, ListView):
    model = EvaluationResult
    template_name = "monitoring/evaluation_list.html"
    context_object_name = "evaluations"
    paginate_by = 25
    allowed_roles = (RoleChoices.ADMIN,)


def _admin_only(user) -> bool:
    return user_has_any_role(user, (RoleChoices.ADMIN,))


@login_required
@user_passes_test(_admin_only)
@require_POST
def run_detection_view(request: HttpRequest) -> HttpResponseRedirect:
    threshold_raw = request.POST.get("threshold_quantile", "").strip()
    threshold_quantile = None
    if threshold_raw:
        try:
            threshold_quantile = float(threshold_raw)
        except ValueError:
            messages.error(request, "Invalid threshold quantile value.")
            return redirect("anomaly-list")
        if not (0.0 < threshold_quantile < 1.0):
            messages.error(request, "Threshold quantile must be between 0 and 1.")
            return redirect("anomaly-list")
    summary = run_isolation_forest_detection(threshold_quantile=threshold_quantile)
    messages.success(
        request,
        (
            f"Detection complete: {summary.anomalies_flagged} anomalies flagged from "
            f"{summary.total_events} events in {summary.execution_time_ms:.2f} ms. "
            f"Automated alerts opened/reopened: {summary.automated_alerts_created}."
        ),
    )
    return redirect("anomaly-list")


@login_required
@user_passes_test(_admin_only)
@require_POST
def run_evaluation_view(request: HttpRequest) -> HttpResponseRedirect:
    logs = AccessLog.objects.filter(notes__contains=DATASET_MARKER).order_by("accessed_at")
    if not logs.exists():
        messages.error(
            request,
            "No imported dataset available. Run `python manage.py import_cybersecurity_csv` first.",
        )
        return redirect("evaluation-list")

    threshold_raw = request.POST.get("threshold_quantile", "").strip()
    threshold_quantile = None
    if threshold_raw:
        try:
            threshold_quantile = float(threshold_raw)
        except ValueError:
            messages.error(request, "Invalid threshold quantile value.")
            return redirect("evaluation-list")
        if not (0.0 < threshold_quantile < 1.0):
            messages.error(request, "Threshold quantile must be between 0 and 1.")
            return redirect("evaluation-list")

    result = evaluate_detector(logs, threshold_quantile=threshold_quantile)
    messages.success(
        request,
        (
            f"Evaluation complete. Precision={result.precision:.3f}, "
            f"Recall={result.recall:.3f}, FPR={result.false_positive_rate:.3f}."
        ),
    )
    return redirect("evaluation-list")
