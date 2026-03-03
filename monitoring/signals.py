from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

from monitoring.models import RoleChoices, UserProfile


User = get_user_model()


@receiver(post_save, sender=User)
def create_or_update_profile(sender, instance, created, **kwargs):
    if created:
        role = RoleChoices.ADMIN if instance.is_superuser else RoleChoices.NURSE
        UserProfile.objects.create(user=instance, role=role)
    else:
        UserProfile.objects.get_or_create(user=instance)
