import uuid

from enumfields import EnumField
from bucketreactor.enums import *

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

from django.utils.timezone import (
    utc, now
)
from django.db import models
from django.utils.translation import gettext_lazy as _

class DateModel(models.Model):
    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.created)


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class AbstractUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)
    email = models.EmailField(_('email address'), null=True, unique=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=now)

    objects = UserManager()
    all_objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def __str__(self):
        return self.email

    def get_full_name(self):
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        "Returns the short name for the user."
        return self.first_name


class User(AbstractUser, DateModel):
    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'


class Box(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    tag = models.CharField(max_length=64)
    name = models.CharField(max_length=50, db_index=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    model = models.CharField(max_length=50, db_index=True, blank=True)
    user = models.ForeignKey('bucketreactor.User', on_delete=models.CASCADE)

class Measurement(DateModel):
    identifier = models.UUIDField(unique=True, db_index=True,
        default=uuid.uuid4)
    box = models.ForeignKey('bucketreactor.Box', on_delete=models.CASCADE)
    temperature = models.DecimalField(decimal_places=5,max_digits=8)
    humidity = models.DecimalField(decimal_places=5,max_digits=8)
    soil_moisture = models.DecimalField(decimal_places=5,max_digits=8)
    grow_light_state = models.BooleanField(default=True)
    fans_state = models.BooleanField(default=True)
    irrigation_state = models.BooleanField(default=True)
    grow_schedule = EnumField(ScheduleType, max_length=50,
        default=ScheduleType.PHASE1)
